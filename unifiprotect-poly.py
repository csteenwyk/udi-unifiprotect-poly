#!/usr/bin/env python3
"""UniFi Protect nodeserver for ISY/PG3x.

Each camera becomes a node with binary drivers that reflect real-time
smart-detection state (motion, person, vehicle, animal, package).
Drivers stay True while the event is open; cleared when Protect closes it.
"""

import asyncio
import logging
import threading

import udi_interface
from uiprotect.api import ProtectApiClient
from uiprotect.data import Camera, Event, StateType
from uiprotect.data.types import EventType, SmartDetectObjectType
from uiprotect.websocket import WebsocketState

LOGGER = logging.getLogger('roborock-poly')   # reuses udi log name convention
LOGGER = udi_interface.LOGGER

# ---------------------------------------------------------------------------
# Async bridge (same pattern as Roborock plugin)
# ---------------------------------------------------------------------------

class _AsyncBridge:
    def __init__(self):
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(
            target=self._loop.run_forever, daemon=True, name='unifi-async')
        self._thread.start()

    def run(self, coro, timeout=30):
        """Submit a coroutine and block until done."""
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
        """Submit a coroutine without blocking."""
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

    def __init__(self, polyglot, primary, address, name):
        super().__init__(polyglot, primary, address, name)
        self._camera_id = None   # set by controller after addNode

    def _set(self, driver, value):
        self.setDriver(driver, 1 if value else 0, report=True, force=False)

    def set_connected(self, connected: bool):
        self._set('ST', connected)

    def set_motion(self, active: bool):
        self._set('GV1', active)

    def set_smart(self, obj_type: SmartDetectObjectType, active: bool):
        mapping = {
            SmartDetectObjectType.PERSON:  'GV2',
            SmartDetectObjectType.VEHICLE: 'GV3',
            SmartDetectObjectType.ANIMAL:  'GV4',
            SmartDetectObjectType.PACKAGE: 'GV5',
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

        self._async          = _AsyncBridge()
        self._client         = None       # ProtectApiClient
        self._cameras        = {}         # address -> CameraNode
        self._unsub_ws       = None       # websocket unsubscribe callable
        self._unsub_state    = None       # websocket state unsubscribe callable
        self._initialized    = False
        self._controller_added = False
        self._node_added     = threading.Event()
        self._params         = udi_interface.Custom(polyglot, 'customparams')

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
        self._disconnect()
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

        host     = params.get('host', '').strip()
        username = params.get('username', '').strip()
        password = params.get('password', '').strip()

        if not host or not username or not password:
            self.poly.Notices['config'] = (
                'Set host, username, and password in Custom Parameters')
            return

        if not self._initialized:
            self._try_connect()

    def _try_connect(self):
        params = self._params
        host     = (params.get('host')     or '').strip()
        username = (params.get('username') or '').strip()
        password = (params.get('password') or '').strip()
        port     = int((params.get('port') or '443').strip())
        verify   = (params.get('verify_ssl') or 'false').strip().lower() == 'true'

        if not host or not username or not password:
            return

        self._initialized = True
        self._async.submit(self._connect(host, port, username, password, verify))

    async def _connect(self, host, port, username, password, verify_ssl):
        try:
            LOGGER.info(f'Connecting to UniFi Protect at {host}:{port}')
            self._client = ProtectApiClient(
                host=host,
                port=port,
                username=username,
                password=password,
                verify_ssl=verify_ssl,
            )
            await self._client.update()
            LOGGER.info('Connected — discovering cameras')
            await self._discover_cameras()

            # Subscribe to real-time WebSocket events
            self._unsub_ws    = self._client.subscribe_websocket(self._on_ws_message)
            self._unsub_state = self._client.subscribe_websocket_state(self._on_ws_state)
            LOGGER.info('WebSocket subscribed — listening for events')

        except Exception as e:
            LOGGER.error(f'Failed to connect to UniFi Protect: {e}', exc_info=True)
            self.poly.Notices['error'] = f'Connection failed: {e}'
            self._initialized = False

    def _disconnect(self):
        if self._unsub_ws:
            self._unsub_ws()
            self._unsub_ws = None
        if self._unsub_state:
            self._unsub_state()
            self._unsub_state = None
        if self._client:
            self._async.run(self._client.close_session(), timeout=10)
            self._client = None

    # ------------------------------------------------------------------
    # Camera discovery
    # ------------------------------------------------------------------

    async def _discover_cameras(self):
        bootstrap = self._client.bootstrap
        if not bootstrap:
            LOGGER.warning('No bootstrap data available')
            return

        for camera in bootstrap.cameras.values():
            self._ensure_camera_node(camera)

    def _ensure_camera_node(self, camera: Camera):
        address = camera.id[:14].lower().replace('-', '')
        if address in self._cameras:
            return self._cameras[address]

        name = camera.name or camera.id
        node = CameraNode(self.poly, self.address, address, name)
        node._camera_id = camera.id
        self._add_node_wait(node, timeout=3)
        node.set_connected(camera.state == StateType.CONNECTED)
        self._cameras[address] = node
        LOGGER.info(f'Added camera node: {name} ({address})')
        return node

    def _node_for_camera_id(self, camera_id: str):
        for node in self._cameras.values():
            if node._camera_id == camera_id:
                return node
        return None

    # ------------------------------------------------------------------
    # WebSocket event handling
    # ------------------------------------------------------------------

    def _on_ws_state(self, state: WebsocketState):
        connected = state == WebsocketState.CONNECTED
        LOGGER.info(f'WebSocket state: {state.name}')
        self.setDriver('ST', 1 if connected else 0)
        if connected and self._client:
            # Re-sync connection state for all cameras
            bootstrap = self._client.bootstrap
            if bootstrap:
                for camera in bootstrap.cameras.values():
                    node = self._node_for_camera_id(camera.id)
                    if node:
                        node.set_connected(camera.state == StateType.CONNECTED)

    def _on_ws_message(self, msg):
        """Handle real-time WebSocket messages from Protect."""
        try:
            new_obj = msg.new_obj
            old_obj = msg.old_obj

            # Camera connection state changes
            if isinstance(new_obj, Camera):
                node = self._node_for_camera_id(new_obj.id)
                if node:
                    node.set_connected(new_obj.state == StateType.CONNECTED)
                else:
                    # Newly adopted camera
                    self._ensure_camera_node(new_obj)
                return

            # Motion / smart detection events
            if isinstance(new_obj, Event):
                self._handle_event(new_obj, old_obj)

        except Exception as e:
            LOGGER.error(f'Error handling WebSocket message: {e}', exc_info=True)

    def _handle_event(self, event: Event, old_event):
        camera_id = getattr(event, 'camera_id', None)
        if not camera_id:
            return

        node = self._node_for_camera_id(camera_id)
        if not node:
            return

        is_open = event.end is None   # event still active if no end timestamp

        if event.type == EventType.MOTION:
            node.set_motion(is_open)

        elif event.type == EventType.SMART_DETECT:
            for obj_type in (event.smart_detect_types or []):
                node.set_smart(obj_type, is_open)

    # ------------------------------------------------------------------
    # Poll
    # ------------------------------------------------------------------

    def poll(self, flag):
        if not self._initialized or not self._client:
            return
        if flag == 'longPoll':
            self._async.submit(self._refresh())

    async def _refresh(self):
        """Periodic full refresh to re-sync state in case WebSocket missed anything."""
        try:
            await self._client.update()
            bootstrap = self._client.bootstrap
            if not bootstrap:
                return
            for camera in bootstrap.cameras.values():
                node = self._node_for_camera_id(camera.id)
                if node:
                    node.set_connected(camera.state == StateType.CONNECTED)
        except Exception as e:
            LOGGER.warning(f'Refresh failed: {e}')

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
            self._async.submit(self._discover_cameras())

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
