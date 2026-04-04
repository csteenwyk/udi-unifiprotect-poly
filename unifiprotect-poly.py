#!/usr/bin/env python3
"""UniFi Protect nodeserver for ISY/PG3x.

Each camera becomes a node with binary driver states for real-time smart
detection (motion, person, vehicle, animal, package). Drivers stay True
while the event is open; cleared when Protect closes it.

Uses aiohttp directly — no uiprotect dependency — for FreeBSD compatibility.
"""

import asyncio
import json
import logging
import ssl
import struct
import threading
import zlib

import aiohttp
import udi_interface

LOGGER = udi_interface.LOGGER

# ---------------------------------------------------------------------------
# UniFi Protect binary WebSocket protocol parser
# ---------------------------------------------------------------------------
# Each WS message: [8-byte header][action payload][8-byte header][data payload]
# Header: uint16 packet_type, uint8 payload_format, uint8 deflate, uint32 size
# payload_format: 1=JSON, 2=UTF8, 3=binary

_HEADER_FMT  = '>HBBI'
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
        _, a_fmt, a_deflate, a_size = struct.unpack_from(_HEADER_FMT, raw, 0)
        a_payload = _decode(raw[_HEADER_SIZE: _HEADER_SIZE + a_size], bool(a_deflate), a_fmt)

        # Data frame
        d_off = _HEADER_SIZE + a_size
        _, d_fmt, d_deflate, d_size = struct.unpack_from(_HEADER_FMT, raw, d_off)
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
        jar = aiohttp.CookieJar(unsafe=True)
        self._session = aiohttp.ClientSession(cookie_jar=jar)
        await self._login()

    async def _login(self):
        resp = await self._session.post(
            self._url('/api/auth/login'),
            json={'username': self.username, 'password': self.password},
            ssl=self._ssl,
        )
        resp.raise_for_status()
        # Extract TOKEN cookie manually — aiohttp cookie jar may drop 'partitioned' cookies
        set_cookie = resp.headers.get('set-cookie', '')
        for part in set_cookie.split(';'):
            part = part.strip()
            if part.startswith('TOKEN='):
                self._auth_cookie = part  # e.g. "TOKEN=eyJ..."
                break
        self._csrf_token = (resp.headers.get('X-Csrf-Token')
                            or resp.headers.get('x-csrf-token')
                            or resp.headers.get('X-Updated-Csrf-Token'))
        LOGGER.debug(f'Auth cookie: {"stored" if self._auth_cookie else "not found"}, '
                     f'CSRF: {"stored" if self._csrf_token else "not found"}')

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

    async def listen(self, on_message):
        """Open WebSocket and call on_message(action, data) for each event."""
        async with self._session.ws_connect(self._ws_url(), headers=self._headers(), ssl=self._ssl) as ws:
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
        asyncio.run_coroutine_threadsafe(coro, self._loop)

    def shutdown(self):
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(timeout=5)


# ---------------------------------------------------------------------------
# Camera node
# ---------------------------------------------------------------------------

class CameraNode(udi_interface.Node):
    id = 'unifi_camera'

    drivers = [
        {'driver': 'ST',  'value': 0, 'uom': 2},  # connected
        {'driver': 'GV1', 'value': 0, 'uom': 2},  # motion
        {'driver': 'GV2', 'value': 0, 'uom': 2},  # person
        {'driver': 'GV3', 'value': 0, 'uom': 2},  # vehicle
        {'driver': 'GV4', 'value': 0, 'uom': 2},  # animal
        {'driver': 'GV5', 'value': 0, 'uom': 2},  # package
    ]

    def __init__(self, polyglot, primary, address, name, camera_id):
        super().__init__(polyglot, primary, address, name)
        self.camera_id = camera_id

    def _set(self, driver, value):
        self.setDriver(driver, 1 if value else 0, report=True, force=False)

    def set_connected(self, connected: bool):
        self._set('ST', connected)

    def set_motion(self, active: bool):
        self._set('GV1', active)

    def set_smart(self, obj_type: str, active: bool):
        mapping = {
            'person':  'GV2',
            'vehicle': 'GV3',
            'animal':  'GV4',
            'package': 'GV5',
        }
        driver = mapping.get(obj_type)
        if driver:
            self._set(driver, active)

    def query(self, command=None):
        self.reportDrivers()

    commands = {'QUERY': query}


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
        self._initialized      = False
        self._controller_added = False
        self._node_added       = threading.Event()
        self._params           = udi_interface.Custom(polyglot, 'customparams')

        polyglot.subscribe(polyglot.CONFIGDONE,   self._on_config_done)
        polyglot.subscribe(polyglot.START,        self.start)
        polyglot.subscribe(polyglot.CUSTOMPARAMS, self.param_handler)
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

    def stop(self):
        LOGGER.info('Stopping UniFi Protect nodeserver')
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
            self.setDriver('ST', 1)
            if not self._initialized:
                self._try_connect()
        except Exception as e:
            LOGGER.error(f'Failed to add controller node: {e}', exc_info=True)

    def _on_node_added(self, data):
        self._node_added.set()

    def _add_node_wait(self, node, timeout=15):
        self._node_added.clear()
        self.poly.addNode(node)
        self._node_added.wait(timeout=timeout)

    # ------------------------------------------------------------------
    # Params / connection
    # ------------------------------------------------------------------

    def param_handler(self, params):
        self._params.load(params)
        self.poly.Notices.clear()

        host     = params.get('host',     '').strip()
        username = params.get('username', '').strip()
        password = params.get('password', '').strip()

        if not host or not username or not password:
            self.poly.Notices['config'] = (
                'Set host, username, and password in Custom Parameters')
            return

        if not self._initialized:
            self._try_connect()

    def _try_connect(self):
        params  = self._params
        host    = (params.get('host')     or '').strip()
        user    = (params.get('username') or '').strip()
        passwd  = (params.get('password') or '').strip()
        port    = int((params.get('port') or '443').strip())
        verify  = (params.get('verify_ssl') or 'false').strip().lower() == 'true'

        if not host or not user or not passwd:
            return

        self._initialized = True
        self._async.submit(self._connect(host, port, user, passwd, verify))

    async def _connect(self, host, port, username, password, verify_ssl):
        try:
            LOGGER.info(f'Connecting to UniFi Protect at {host}:{port}')
            self._client = ProtectClient(host, port, username, password, verify_ssl)
            await self._client.connect()

            bootstrap = await self._client.get_bootstrap()
            LOGGER.info('Bootstrap received — discovering cameras')
            self._discover_cameras(bootstrap)

            LOGGER.info('Listening for WebSocket events')
            await self._ws_loop()

        except Exception as e:
            LOGGER.error(f'Connection failed: {e}', exc_info=True)
            self.poly.Notices['error'] = f'Connection failed: {e}'
            self._initialized = False
            if self._client:
                await self._client.close()
                self._client = None

    async def _ws_loop(self):
        """Run WebSocket listener with automatic reconnection."""
        backoff = 5
        while self._initialized:
            try:
                self.setDriver('ST', 1)
                await self._client.listen(self._on_ws_message)
            except Exception as e:
                LOGGER.warning(f'WebSocket disconnected: {e} — reconnecting in {backoff}s')
            self.setDriver('ST', 0)
            if not self._initialized:
                break
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 60)
            try:
                # Re-login in case session expired
                await self._client._login()
                await self._client.get_bootstrap()
                backoff = 5
            except Exception as e:
                LOGGER.warning(f'Reconnect failed: {e}')

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
        address = cam_id[:14].lower().replace('-', '')
        if address in self._cameras:
            return self._cameras[address]

        name = cam.get('name') or cam_id
        node = CameraNode(self.poly, self.address, address, name, cam_id)
        self._add_node_wait(node, timeout=3)
        node.set_connected(cam.get('state', '') == 'CONNECTED')
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
                    # Newly adopted camera
                    cam_data = dict(data)
                    cam_data.setdefault('id', cam_id)
                    self._ensure_camera(cam_data)

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
        if not self._initialized or not self._client:
            return
        if flag == 'longPoll':
            self._async.submit(self._resync())

    async def _resync(self):
        try:
            bootstrap = await self._client.get_bootstrap()
            cameras   = bootstrap.get('cameras') or []
            if isinstance(cameras, dict):
                cameras = cameras.values()
            for cam in cameras:
                node = self._node_for_camera(cam.get('id', ''))
                if node:
                    node.set_connected(cam.get('state', '') == 'CONNECTED')
        except Exception as e:
            LOGGER.warning(f'Resync failed: {e}')

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
    polyglot = udi_interface.Interface([])
    polyglot.start('1.0.0')
    Controller(polyglot, 'controller', 'controller', 'UniFi Protect')
    polyglot.runForever()
