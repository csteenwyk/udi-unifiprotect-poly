#!/usr/bin/env python3
"""UniFi Protect nodeserver for ISY/PG3x.

Each camera becomes a node with binary driver states for real-time smart
detection (motion, person, vehicle, animal, package). Drivers stay True
while the event is open; cleared when Protect closes it.

Detection drivers are ephemeral: they are reset to 0 on startup, and a
configurable per-driver timeout (``detection_timeout``) auto-clears any
driver left stuck on by a missed WebSocket close event.

Uses aiohttp directly — no uiprotect dependency — for FreeBSD compatibility.
"""

import asyncio
import json
import logging
import os
import ssl
import struct
import threading
import time
import zlib

import aiohttp
import udi_interface

LOGGER = udi_interface.LOGGER

_PLUGIN_DIR  = os.path.dirname(os.path.abspath(__file__))
_PROFILE_DIR = os.path.join(_PLUGIN_DIR, 'profile')

# Self-healing: minutes of sustained connection failure before the plugin
# restarts itself, and how long before it may do so again (so a genuinely-down
# controller doesn't cause a reboot loop). Notices stay quiet for brief blips.
_WATCHDOG_DEFAULT_MIN = 5
_RESTART_COOLDOWN_SEC = 1800
_NOTICE_AFTER_SEC     = 60

# ---------------------------------------------------------------------------
# Dynamic profile writer
# ---------------------------------------------------------------------------

def _write_profile(ringtones: list):
    """Write NLS and editors with dynamic ringtone list, then return subset string."""
    names = [r.get('name', f'Ringtone {i}') for i, r in enumerate(ringtones)]

    # NLS
    nls = _STATIC_NLS
    nls += '\n# Dynamic — Ringtones\n'
    for i, name in enumerate(names):
        nls += f'RINGTONE-{i} = {name}\n'
    if not names:
        nls += 'RINGTONE-0 = (none)\n'
    with open(os.path.join(_PROFILE_DIR, 'nls', 'en_us.txt'), 'w') as f:
        f.write(nls)

    # Editors
    subset = ','.join(str(i) for i in range(len(names))) if names else '0'
    editors = f"""<editors>
  <editor id="E_STATUS">
    <range uom="2" subset="0,1"/>
  </editor>
  <editor id="E_VOL">
    <range uom="51" min="0" max="100" prec="0"/>
  </editor>
  <editor id="E_REPEAT">
    <range uom="56" min="1" max="5" step="1"/>
  </editor>
  <editor id="E_RINGTONE">
    <range uom="25" subset="{subset}" nls="RINGTONE"/>
  </editor>
</editors>
"""
    with open(os.path.join(_PROFILE_DIR, 'editor', 'editors.xml'), 'w') as f:
        f.write(editors)

    LOGGER.info(f'Profile updated: {len(names)} ringtone(s)')


_STATIC_NLS = """\
# Node Server Names
ND-unifi_controller-NAME = UniFi Protect Controller
ND-unifi_camera-NAME = UniFi Camera

# Controller Drivers
ST-unifi_controller-ST-NAME = Status

# Controller Commands
CMD-unifi_controller-DISCOVER-NAME = Re-Discover
CMD-unifi_controller-QUERY-NAME = Query All

# Camera Drivers
ST-unifi_camera-ST-NAME = Connected
ST-unifi_camera-GV1-NAME = Motion
ST-unifi_camera-GV2-NAME = Person
ST-unifi_camera-GV3-NAME = Vehicle
ST-unifi_camera-GV4-NAME = Animal
ST-unifi_camera-GV5-NAME = Package
ST-unifi_camera-GV6-NAME = Ring Volume
ST-unifi_camera-GV7-NAME = Repeat Times
ST-unifi_camera-GV8-NAME = Ringtone

# Camera Commands
CMD-unifi_camera-QUERY-NAME = Query
CMD-unifi_camera-SET_RINGTONE-NAME = Set Ringtone
CMD-unifi_camera-SET_RING_VOL-NAME = Set Ring Volume
CMD-unifi_camera-SET_REPEAT-NAME = Set Repeat Times

"""

# ---------------------------------------------------------------------------
# UniFi Protect binary WebSocket protocol parser
# ---------------------------------------------------------------------------
# Each WS message: [8-byte header][action payload][8-byte header][data payload]
# Header: uint16 packet_type, uint8 payload_format, uint8 deflate, uint32 size
# payload_format: 1=JSON, 2=UTF8, 3=binary

_HEADER_FMT  = '>BBBBI'   # packet_type(1), payload_format(1), deflate(1), unknown(1), size(4)
_HEADER_SIZE = struct.calcsize(_HEADER_FMT)   # 8

_FMT_JSON  = 1
_FMT_UTF8  = 2


def _decode(data: bytes, deflate: bool, fmt: int):
    if deflate:
        data = zlib.decompress(data)
    if fmt in (_FMT_JSON, _FMT_UTF8):
        return json.loads(data)
    return data


def _parse_ws_message(raw: bytes):
    """Return (action_dict, data_dict) or (None, None) on parse error."""
    try:
        if len(raw) < _HEADER_SIZE * 2:
            return None, None

        # Action frame
        _, a_fmt, a_deflate, _, a_size = struct.unpack_from(_HEADER_FMT, raw, 0)
        a_payload = _decode(raw[_HEADER_SIZE: _HEADER_SIZE + a_size], bool(a_deflate), a_fmt)

        # Data frame
        d_off = _HEADER_SIZE + a_size
        _, d_fmt, d_deflate, _, d_size = struct.unpack_from(_HEADER_FMT, raw, d_off)
        d_payload = _decode(raw[d_off + _HEADER_SIZE: d_off + _HEADER_SIZE + d_size],
                            bool(d_deflate), d_fmt)

        return a_payload, d_payload
    except Exception as e:
        LOGGER.debug(f'WS parse error: {e}')
        return None, None


# ---------------------------------------------------------------------------
# Minimal UniFi Protect API client
# ---------------------------------------------------------------------------

class ProtectClient:
    """Minimal aiohttp-based UniFi Protect client."""

    def __init__(self, host: str, port: int, username: str, password: str,
                 verify_ssl: bool = False):
        self.host       = host
        self.port       = port
        self.username   = username
        self.password   = password
        self._ssl            = ssl.create_default_context() if verify_ssl else False
        self._session        = None
        self._csrf_token     = None
        self._auth_cookie    = None
        self._last_update_id = None

    def _url(self, path: str) -> str:
        return f'https://{self.host}:{self.port}{path}'

    def _ws_url(self) -> str:
        base = f'wss://{self.host}:{self.port}/proxy/protect/ws/updates'
        if self._last_update_id:
            return f'{base}?lastUpdateId={self._last_update_id}'
        return base

    async def connect(self):
        # DummyCookieJar ignores all Set-Cookie headers — we handle TOKEN manually
        # in _headers(). This prevents the cookie jar from sending stale cookies
        # that conflict with our manually-extracted TOKEN on re-login.
        # Bound connection ESTABLISHMENT only. A blackholed route (no ICMP
        # unreachable — what a lost route actually looks like) hangs the TCP
        # connect, which is the case we care about.
        # Deliberately no `total`: this session is also used for ws_connect,
        # and a total timeout applies to the whole upgraded connection, which
        # would tear down a healthy WebSocket on a timer.
        self._session = aiohttp.ClientSession(
            cookie_jar=aiohttp.DummyCookieJar(),
            timeout=aiohttp.ClientTimeout(total=None, connect=10, sock_connect=10))
        await self._login()

    async def _login(self):
        resp = await self._session.post(
            self._url('/api/auth/login'),
            json={'username': self.username, 'password': self.password},
            ssl=self._ssl,
        )
        resp.raise_for_status()
        # Extract TOKEN cookie manually — aiohttp cookie jar may drop 'partitioned' cookies.
        # Use getall() because Set-Cookie appears as multiple headers; get() only returns first.
        self._auth_cookie = None
        for header_val in resp.headers.getall('set-cookie', []):
            for part in header_val.split(';'):
                part = part.strip()
                if part.startswith('TOKEN='):
                    self._auth_cookie = part  # e.g. "TOKEN=eyJ..."
                    break
            if self._auth_cookie:
                break
        self._csrf_token = (resp.headers.get('X-Csrf-Token')
                            or resp.headers.get('x-csrf-token')
                            or resp.headers.get('X-Updated-Csrf-Token'))
        LOGGER.info(f'Login: TOKEN={"found" if self._auth_cookie else "NOT FOUND"}, '
                    f'CSRF={"found" if self._csrf_token else "not found"}')

    def _headers(self) -> dict:
        h = {}
        if self._auth_cookie:
            h['Cookie'] = self._auth_cookie
        if self._csrf_token:
            h['X-Csrf-Token'] = self._csrf_token
        return h

    async def get_bootstrap(self) -> dict:
        resp = await self._session.get(
            self._url('/proxy/protect/api/bootstrap'),
            headers=self._headers(),
            ssl=self._ssl,
        )
        resp.raise_for_status()
        data = await resp.json()
        self._last_update_id = data.get('lastUpdateId')
        return data

    async def listen(self, on_message, on_connect=None):
        """Open WebSocket and call on_message(action, data) for each event."""
        async with self._session.ws_connect(self._ws_url(), headers=self._headers(), ssl=self._ssl) as ws:
            # Only trustworthy "we are online" signal — fires once the socket
            # is genuinely established, not merely attempted.
            if on_connect:
                on_connect()
            async for msg in ws:
                if msg.type == aiohttp.WSMsgType.BINARY:
                    action, data = _parse_ws_message(msg.data)
                    if action and data:
                        # Track lastUpdateId so reconnects don't miss events
                        uid = action.get('newUpdateId')
                        if uid:
                            self._last_update_id = uid
                        on_message(action, data)
                elif msg.type in (aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR):
                    LOGGER.warning(f'WebSocket closed/error: {msg.type}')
                    break

    async def get_ringtones(self) -> list:
        resp = await self._session.get(
            self._url('/proxy/protect/api/ringtones'),
            headers=self._headers(), ssl=self._ssl)
        resp.raise_for_status()
        return await resp.json()

    async def get_camera(self, camera_id: str) -> dict:
        resp = await self._session.get(
            self._url(f'/proxy/protect/api/cameras/{camera_id}'),
            headers=self._headers(), ssl=self._ssl)
        resp.raise_for_status()
        return await resp.json()

    async def patch_camera(self, camera_id: str, payload: dict):
        resp = await self._session.patch(
            self._url(f'/proxy/protect/api/cameras/{camera_id}'),
            headers=self._headers(), ssl=self._ssl, json=payload)
        if resp.status == 401:
            LOGGER.warning('patch_camera: 401 — reconnecting and retrying')
            await self.reconnect()
            resp = await self._session.patch(
                self._url(f'/proxy/protect/api/cameras/{camera_id}'),
                headers=self._headers(), ssl=self._ssl, json=payload)
        resp.raise_for_status()

    async def refresh_token(self):
        """Re-login on existing session to get a fresh TOKEN without touching the WebSocket."""
        await self._login()
        LOGGER.info('Auth token refreshed')

    async def reconnect(self):
        """Close existing session and re-authenticate with a fresh one."""
        await self.close()
        await self.connect()

    async def close(self):
        if self._session:
            await self._session.close()
            self._session = None


# ---------------------------------------------------------------------------
# Async bridge
# ---------------------------------------------------------------------------

class _AsyncBridge:
    def __init__(self):
        self._loop   = asyncio.new_event_loop()
        self._thread = threading.Thread(
            target=self._loop.run_forever, daemon=True, name='unifi-async')
        self._thread.start()

    def run(self, coro, timeout=30):
        future = asyncio.run_coroutine_threadsafe(coro, self._loop)
        try:
            return future.result(timeout=timeout)
        except asyncio.TimeoutError:
            LOGGER.error('Async call timed out')
            return None
        except Exception as e:
            LOGGER.error(f'Async error: {e}')
            return None

    def submit(self, coro):
        def _log_exception(fut):
            if not fut.cancelled() and fut.exception():
                LOGGER.error(f'Async task error: {fut.exception()}')
        future = asyncio.run_coroutine_threadsafe(coro, self._loop)
        future.add_done_callback(_log_exception)

    def shutdown(self):
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(timeout=5)


# ---------------------------------------------------------------------------
# Camera node
# ---------------------------------------------------------------------------

class CameraNode(udi_interface.Node):
    id = 'unifi_camera'

    drivers = [
        {'driver': 'ST',  'value': 0, 'uom': 2},   # connected
        {'driver': 'GV1', 'value': 0, 'uom': 2},   # motion
        {'driver': 'GV2', 'value': 0, 'uom': 2},   # person
        {'driver': 'GV3', 'value': 0, 'uom': 2},   # vehicle
        {'driver': 'GV4', 'value': 0, 'uom': 2},   # animal
        {'driver': 'GV5', 'value': 0, 'uom': 2},   # package
        {'driver': 'GV6', 'value': 50, 'uom': 51},  # ring volume
        {'driver': 'GV7', 'value': 1, 'uom': 56},  # repeat times
        {'driver': 'GV8', 'value': 0, 'uom': 25},  # current ringtone (index)
    ]

    # Ephemeral detection drivers — reset on startup, auto-cleared on timeout
    DETECTION_DRIVERS = ('GV1', 'GV2', 'GV3', 'GV4', 'GV5')

    def __init__(self, polyglot, primary, address, name, camera_id, controller):
        super().__init__(polyglot, primary, address, name)
        self.camera_id   = camera_id
        self._ctrl       = controller
        self._timers     = {}                 # driver -> threading.Timer (auto-clear)
        self._timer_lock = threading.Lock()

    def _set(self, driver, value):
        self.setDriver(driver, 1 if value else 0, report=True, force=False)

    def set_connected(self, connected: bool):
        self._set('ST', connected)

    def set_motion(self, active: bool):
        self._set_detection('GV1', active)

    def set_smart(self, obj_type: str, active: bool):
        mapping = {
            'person':  'GV2',
            'vehicle': 'GV3',
            'animal':  'GV4',
            'package': 'GV5',
        }
        driver = mapping.get(obj_type)
        if driver:
            self._set_detection(driver, active)

    def _set_detection(self, driver, active: bool):
        """Set a detection driver and (re)arm its auto-clear timeout.

        Protect signals a detection 'open' then later 'closed'. If the closing
        WebSocket message is missed (reconnect, dropped frame), the driver would
        otherwise stay stuck on. We (re)arm a configurable timer on every 'open'
        so a missed close self-heals after ``detection_timeout`` seconds."""
        self._set(driver, active)
        timeout = self._ctrl.detection_timeout if self._ctrl else 0
        with self._timer_lock:
            existing = self._timers.pop(driver, None)
            if existing:
                existing.cancel()
            if active and timeout > 0:
                timer = threading.Timer(timeout, self._timeout_clear, args=(driver,))
                timer.daemon = True
                self._timers[driver] = timer
                timer.start()

    def _timeout_clear(self, driver):
        with self._timer_lock:
            self._timers.pop(driver, None)
        LOGGER.warning(
            f'{self.name}: {driver} auto-cleared after '
            f'{self._ctrl.detection_timeout}s (no close event received)')
        self._set(driver, False)

    def clear_detections(self):
        """Force all detection drivers to 0 and cancel pending timers.

        Detections are ephemeral and must not survive a restart — PG3x persists
        driver values, so a stuck driver would otherwise ride through a plugin
        restart. Called on startup for each camera."""
        with self._timer_lock:
            for timer in self._timers.values():
                timer.cancel()
            self._timers.clear()
        for driver in self.DETECTION_DRIVERS:
            self.setDriver(driver, 0, report=True, force=True)

    def set_speaker(self, speaker: dict):
        self.setDriver('GV6', speaker.get('ringVolume', 0))
        self.setDriver('GV7', speaker.get('repeatTimes', 1))
        ringtone_id = speaker.get('ringtoneId', '')
        ringtones = self._ctrl.ringtones if self._ctrl else []
        idx = next((i for i, r in enumerate(ringtones) if r.get('id') == ringtone_id), 0)
        self.setDriver('GV8', idx)

    def _patch(self, payload: dict):
        if self._ctrl and self._ctrl._client:
            self._ctrl._async.submit(
                self._ctrl._client.patch_camera(self.camera_id, payload))

    def cmd_set_ringtone(self, command):
        idx = int(command.get('value', 0))
        ringtones = self._ctrl.ringtones
        if idx < len(ringtones):
            ringtone_id = ringtones[idx]['id']
            self._patch({'speakerSettings': {'ringtoneId': ringtone_id}})
            self.setDriver('GV8', idx)
            LOGGER.info(f'{self.name}: set ringtone → {ringtones[idx]["name"]}')
        else:
            LOGGER.warning(f'{self.name}: ringtone index {idx} out of range')

    def cmd_set_ring_vol(self, command):
        vol = int(command.get('value', 0))
        self._patch({'speakerSettings': {'ringVolume': vol}})
        self.setDriver('GV6', vol)
        LOGGER.info(f'{self.name}: set ring volume → {vol}')

    def cmd_set_repeat(self, command):
        times = int(command.get('value', 1))
        self._patch({'speakerSettings': {'repeatTimes': times}})
        self.setDriver('GV7', times)
        LOGGER.info(f'{self.name}: set repeat times → {times}')

    def query(self, command=None):
        if self._ctrl and self._ctrl._client:
            self._ctrl._async.submit(self._refresh())
        else:
            self.reportDrivers()

    async def _refresh(self):
        try:
            cam = await self._ctrl._client.get_camera(self.camera_id)
            if cam.get('speakerSettings'):
                self.set_speaker(cam['speakerSettings'])
            self.reportDrivers()
        except Exception as e:
            LOGGER.warning(f'{self.name}: query refresh failed: {e}')
            self.reportDrivers()

    commands = {
        'QUERY':         query,
        'SET_RINGTONE':  cmd_set_ringtone,
        'SET_RING_VOL':  cmd_set_ring_vol,
        'SET_REPEAT':    cmd_set_repeat,
    }


# ---------------------------------------------------------------------------
# Controller node
# ---------------------------------------------------------------------------

class Controller(udi_interface.Node):
    id = 'unifi_controller'

    drivers = [
        {'driver': 'ST', 'value': 0, 'uom': 2},
    ]

    def __init__(self, polyglot, primary, address, name):
        super().__init__(polyglot, primary, address, name)

        self._async            = _AsyncBridge()
        self._client           = None
        self._cameras          = {}     # address -> CameraNode
        self.ringtones         = []     # list of {id, name} dicts
        self.detection_timeout = 300    # seconds; auto-clear stuck detection drivers (0 = off)
        self._initialized      = False
        self._controller_added = False
        self._node_events      = {}     # node address -> threading.Event
        self._node_events_lock = threading.Lock()
        self._params           = udi_interface.Custom(polyglot, 'customparams')
        self._data             = udi_interface.Custom(polyglot, 'customdata')
        self._down_since       = None   # epoch of first failure in current outage
        self._watchdog_minutes = _WATCHDOG_DEFAULT_MIN
        self._running          = True
        self._connect_lock     = threading.Lock()
        self._profile_written  = False

        polyglot.subscribe(polyglot.CONFIGDONE,   self._on_config_done)
        polyglot.subscribe(polyglot.START,        self.start)
        polyglot.subscribe(polyglot.CUSTOMPARAMS, self.param_handler)
        polyglot.subscribe(polyglot.CUSTOMDATA,   self._customdata_handler)
        polyglot.subscribe(polyglot.POLL,         self.poll)
        polyglot.subscribe(polyglot.STOP,         self.stop)
        polyglot.subscribe(polyglot.ADDNODEDONE,  self._on_node_added)

        polyglot.ready()
        polyglot.addNode(self)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self):
        LOGGER.debug('start() called')

    def _customdata_handler(self, data):
        """Custom() does not self-load — without this the watchdog's restart
        cooldown would read None every start and could reboot-loop."""
        self._data.load(data or {})

    def stop(self):
        LOGGER.info('Stopping UniFi Protect nodeserver')
        self._running = False
        if self._client:
            self._async.run(self._client.close(), timeout=10)
        self._async.shutdown()

    def _on_config_done(self):
        if self._controller_added:
            return
        LOGGER.info('Config done — adding controller node')
        try:
            self._add_node_wait(self, timeout=3)
            self._controller_added = True
            # ST reflects the Protect connection, not node creation. Claiming 1
            # here made the controller look healthy through an entire outage.
            self.setDriver('ST', 0)
            if not self._initialized:
                self._try_connect()
        except Exception as e:
            LOGGER.error(f'Failed to add controller node: {e}', exc_info=True)

    def _on_node_added(self, data):
        addr = (data or {}).get('address')
        with self._node_events_lock:
            if addr is None:
                # Payload without an address: we can't tell who it was for,
                # so wake everyone rather than hang every waiter.
                waiters = list(self._node_events.values())
            else:
                # A known address with no waiter means a late or duplicate ack.
                # Waking someone else here is exactly the cross-wake this
                # per-address scheme exists to prevent.
                ev = self._node_events.get(addr)
                waiters = [ev] if ev else []
        for e in waiters:
            e.set()

    def _add_node_wait(self, node, timeout=15):
        # One Event per address: a single shared Event let concurrent callers
        # consume each other's completion and return before their node existed.
        ev = threading.Event()
        with self._node_events_lock:
            self._node_events[node.address] = ev
        try:
            self.poly.addNode(node)
            if not ev.wait(timeout=timeout):
                LOGGER.warning(f'Timed out waiting for ISY to add {node.address}')
        finally:
            with self._node_events_lock:
                self._node_events.pop(node.address, None)

    # ------------------------------------------------------------------
    # Params / connection
    # ------------------------------------------------------------------

    def param_handler(self, params):
        # PG3 always publishes CUSTOMPARAMS at startup, but with a None payload
        # when it has nothing stored. Loading that would wipe _rawdata, and
        # params.get() would raise inside a bare handler thread — silently
        # leaving the plugin configured-but-never-connected.
        if not params:
            LOGGER.warning('CUSTOMPARAMS with no data — keeping existing params')
            return
        self._params.load(params)
        # Targeted delete, not clear() — clear() would also wipe an active
        # outage notice every time params are saved.
        self.poly.Notices.delete('config')

        try:
            self.detection_timeout = max(0, int((params.get('detection_timeout') or '300').strip()))
        except (ValueError, TypeError):
            self.detection_timeout = 300

        host     = (params.get('host')     or '').strip()
        username = (params.get('username') or '').strip()
        password = (params.get('password') or '').strip()

        if not host or not username or not password:
            self.poly.Notices['config'] = (
                'Set host, username, and password in Custom Parameters')
            return

        if not self._initialized:
            self._try_connect()

    def _is_configured(self) -> bool:
        p = self._params
        if ((p.get('host') or '').strip() and (p.get('username') or '').strip()
                and (p.get('password') or '').strip()):
            return True
        # _params can be empty if CUSTOMPARAMS never reached us. PG3's config is
        # the authoritative copy, so fall back to it rather than staying dead.
        try:
            cfg = (self.poly.getConfig() or {}).get('customParams') or {}
        except Exception:
            return False
        if ((cfg.get('host') or '').strip() and (cfg.get('username') or '').strip()
                and (cfg.get('password') or '').strip()):
            LOGGER.warning('Recovered params from PG3 config')
            self._params.load(cfg)
            return True
        return False

    def _try_connect(self):
        # CONFIGDONE, CUSTOMPARAMS and POLL each run on their own thread, so a
        # bare check-then-set would let two supervisors start against two
        # clients, leaking a session and orphaning a loop.
        with self._connect_lock:
            if self._initialized:
                return
            self._initialized = True

        params  = self._params
        host    = (params.get('host')     or '').strip()
        user    = (params.get('username') or '').strip()
        passwd  = (params.get('password') or '').strip()
        port    = int((params.get('port') or '443').strip())
        verify  = (params.get('verify_ssl') or 'false').strip().lower() == 'true'
        try:
            self._watchdog_minutes = int(
                (params.get('watchdog_minutes') or _WATCHDOG_DEFAULT_MIN))
        except (ValueError, TypeError):
            self._watchdog_minutes = _WATCHDOG_DEFAULT_MIN

        if not host or not user or not passwd:
            LOGGER.warning('host/username/password not set — not connecting')
            self._initialized = False
            return

        self._async.submit(self._supervisor(host, port, user, passwd, verify))

    async def _supervisor(self, host, port, username, password, verify_ssl):
        """Owns the whole connection lifecycle.

        First connect and reconnect-after-an-outage are deliberately the same
        code path, so a plugin that starts before the network is up simply
        retries until the network arrives instead of sitting idle forever.
        """
        try:
            await self._supervise(host, port, username, password, verify_ssl)
        finally:
            # Every exit path — clean stop or an unexpected crash — must clear
            # this, or the shortPoll safety net won't restart us.
            LOGGER.info('Connection supervisor stopped')
            self._initialized = False

    async def _supervise(self, host, port, username, password, verify_ssl):
        backoff = 5
        first = True
        while self._running:
            try:
                LOGGER.info(f'Connecting to UniFi Protect at {host}:{port}')
                # A fresh client each attempt re-runs /api/auth/login, which is
                # what refreshes the expiring TOKEN cookie.
                self._client = ProtectClient(host, port, username, password, verify_ssl)
                await self._client.connect()

                bootstrap = await self._client.get_bootstrap()
                LOGGER.info('Bootstrap received')

                # Ringtones drive the profile, which only needs writing once.
                if not self._profile_written:
                    try:
                        self.ringtones = await self._client.get_ringtones()
                        LOGGER.info(f'Ringtones: {[r["name"] for r in self.ringtones]}')
                    except Exception as e:
                        LOGGER.warning(f'Could not fetch ringtones: {e}')
                        self.ringtones = []
                    _write_profile(self.ringtones)
                    self.poly.updateProfile()
                    self._profile_written = True

                if first:
                    await asyncio.sleep(2)   # let ISY digest the profile
                    first = False

                LOGGER.info('Discovering cameras')
                await asyncio.get_event_loop().run_in_executor(
                    None, self._discover_cameras, bootstrap)

                LOGGER.info('Listening for WebSocket events')
                backoff = 5
                # _mark_online fires from inside, once the socket is truly up.
                await self._client.listen(self._on_ws_message,
                                          on_connect=self._mark_online)
                LOGGER.warning('WebSocket closed by peer')
                self._mark_offline('WebSocket closed')
            except asyncio.CancelledError:
                raise
            except Exception as e:
                self._mark_offline(e)

            await self._teardown_client()
            if not self._running:
                break
            LOGGER.info(f'Retrying in {backoff}s')
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 60)

    async def _teardown_client(self):
        self.setDriver('ST', 0)
        client, self._client = self._client, None
        if client:
            try:
                await client.close()
            except Exception as e:
                LOGGER.debug(f'Error closing client: {e}')

    def _mark_online(self):
        """Called only when the WebSocket is genuinely established."""
        self.setDriver('ST', 1)
        if self._down_since is not None:
            down_min = (time.time() - self._down_since) / 60
            LOGGER.info(f'Connection restored after {down_min:.1f} min offline')
            self._down_since = None
        self.poly.Notices.delete('offline')

    def _mark_offline(self, err):
        """Track a sustained outage: surface it, then self-restart if it persists."""
        now = time.time()
        if self._down_since is None:
            self._down_since = now
        down_sec = now - self._down_since
        LOGGER.warning(f'Connection failed (down {down_sec / 60:.1f} min): {err}')

        if down_sec >= _NOTICE_AFTER_SEC:
            self.poly.Notices['offline'] = (
                f'No connection to UniFi Protect for {down_sec / 60:.0f} min: {err}')

        if not self._watchdog_minutes or down_sec < self._watchdog_minutes * 60:
            return

        # Sustained outage. The retry loop above is the real recovery path;
        # restart() is a blunt last resort and a no-op if MQTT never came up.
        # Cooldown is persisted so it survives the restart it just caused.
        last = float(self._data.get('last_restart') or 0)
        if now - last < _RESTART_COOLDOWN_SEC:
            return
        self._data['last_restart'] = now
        LOGGER.error(f'No connection for {down_sec / 60:.0f} min — restarting plugin')
        try:
            self.poly.restart()
        except Exception as e:
            LOGGER.error(f'Self-restart failed: {e}')

    # ------------------------------------------------------------------
    # Camera discovery
    # ------------------------------------------------------------------

    def _discover_cameras(self, bootstrap: dict):
        cameras = bootstrap.get('cameras') or []
        if isinstance(cameras, dict):
            cameras = cameras.values()
        for cam in cameras:
            self._ensure_camera(cam)

    def _ensure_camera(self, cam: dict):
        cam_id  = cam.get('id', '')
        mac     = cam.get('mac', '')
        # Use MAC address as node address — stable across re-adoption
        address = mac.lower().replace(':', '')[:14] if mac else cam_id[:14].lower().replace('-', '')
        if address in self._cameras:
            return self._cameras[address]

        name = cam.get('name') or cam_id
        node = CameraNode(self.poly, self.address, address, name, cam_id, self)
        self._add_node_wait(node, timeout=3)
        node.clear_detections()   # ephemeral state must not persist across restart
        node.set_connected(cam.get('state', '') == 'CONNECTED')
        if cam.get('speakerSettings'):
            node.set_speaker(cam['speakerSettings'])
        self._cameras[address] = node
        LOGGER.info(f'Added camera: {name} ({address})')
        return node

    def _node_for_camera(self, camera_id: str):
        for node in self._cameras.values():
            if node.camera_id == camera_id:
                return node
        return None

    # ------------------------------------------------------------------
    # WebSocket event handling
    # ------------------------------------------------------------------

    def _on_ws_message(self, action: dict, data: dict):
        try:
            model_key = action.get('modelKey', '')
            act       = action.get('action', '')

            if model_key == 'camera':
                cam_id = action.get('id', '')
                node   = self._node_for_camera(cam_id)
                if node and 'state' in data:
                    node.set_connected(data['state'] == 'CONNECTED')
                elif not node and act == 'add':
                    # Newly adopted camera — trigger resync to get full data
                    # (WebSocket add events lack the name field)
                    LOGGER.info(f'New camera detected ({cam_id}) — resyncing')
                    self._async.submit(self._resync())

            elif model_key == 'event':
                self._handle_event(action, data)

        except Exception as e:
            LOGGER.error(f'Error handling WS message: {e}', exc_info=True)

    def _handle_event(self, action: dict, data: dict):
        cam_id   = data.get('camera') or data.get('cameraId')
        if not cam_id:
            return

        node = self._node_for_camera(cam_id)
        if not node:
            return

        evt_type = data.get('type', '')
        is_open  = data.get('end') is None   # no end timestamp = still active

        if evt_type == 'motion':
            node.set_motion(is_open)

        elif evt_type == 'smartDetectZone':
            for obj in (data.get('smartDetectTypes') or []):
                node.set_smart(obj, is_open)

    # ------------------------------------------------------------------
    # Poll — long poll re-syncs camera state
    # ------------------------------------------------------------------

    def poll(self, flag):
        # Safety net for the case the supervisor never started at all: a
        # startup callback that didn't fire, a crashed handler thread, or
        # params that arrived late. shortPoll (60s) rather than longPoll so
        # recovery is a minute, not ten.
        if flag == 'shortPoll':
            if not self._initialized and self._is_configured():
                LOGGER.warning('No connection supervisor running — starting one')
                self._try_connect()
            return
        if flag == 'longPoll' and self._initialized and self._client:
            self._async.submit(self._resync())

    async def _resync(self):
        try:
            bootstrap = await self._client.get_bootstrap()
        except aiohttp.ClientResponseError as e:
            if e.status == 401:
                try:
                    LOGGER.info('Resync 401 — creating fresh session')
                    await self._client.reconnect()
                    bootstrap = await self._client.get_bootstrap()
                except Exception as e2:
                    LOGGER.warning(f'Resync failed after reconnect: {e2}')
                    return
            else:
                LOGGER.warning(f'Resync failed: {e}')
                return
        except Exception as e:
            LOGGER.warning(f'Resync failed: {e}')
            return
        cameras = bootstrap.get('cameras') or []
        if isinstance(cameras, dict):
            cameras = cameras.values()
        for cam in cameras:
            node = self._node_for_camera(cam.get('id', ''))
            if node:
                node.set_connected(cam.get('state', '') == 'CONNECTED')
                if cam.get('speakerSettings'):
                    node.set_speaker(cam['speakerSettings'])

    # ------------------------------------------------------------------
    # Commands
    # ------------------------------------------------------------------

    def query(self, command=None):
        self.reportDrivers()
        for node in self._cameras.values():
            node.query()

    def cmd_discover(self, command=None):
        if not self._initialized:
            self._try_connect()
        elif self._client:
            self._async.submit(self._resync())

    commands = {
        'QUERY':    query,
        'DISCOVER': cmd_discover,
    }


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    polyglot = udi_interface.Interface([Controller, CameraNode])
    polyglot.start('1.0.1')
    Controller(polyglot, 'controller', 'controller', 'UniFi Protect')
    polyglot.runForever()
