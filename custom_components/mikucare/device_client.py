# Modified from https://github.com/fuatakgun/eufy_security/blob/master/custom_components/eufy_security/eufy_security_api/web_socket_client.py
import asyncio
import logging
import traceback

import aiohttp
from aiohttp import WSMessage

from .api import MikuCareApi
from .exceptions import WebSocketConnectionException

_LOGGER = logging.getLogger(__name__)


class MikuCareDeviceClient:
    """Websocket client for Miku Care device"""

    def __init__(
        self, api: MikuCareApi, device_id: str, message_callback, close_callback
    ):
        self._device_id = device_id
        self._message_callback = message_callback
        self._close_callback = close_callback
        self.api = api
        self.socket: aiohttp.ClientWebSocketResponse = None
        self.loop: asyncio.AbstractEventLoop = asyncio.get_event_loop()
        self.task = None

    async def connect(self):
        try:
            _LOGGER.debug("connect: device=%s", self._device_id)
            self.socket = await self.api.session.ws_connect(
                f"wss://api.mikucloud.com/devices/{self._device_id}/events",
                headers=self.api.get_headers(),
                heartbeat=60,
            )
        except Exception as exc:
            raise WebSocketConnectionException() from exc
        self.task = self.loop.create_task(self._process_messages())
        self.task.add_done_callback(self._on_close)
        await self._on_open()

    async def disconnect(self):
        _LOGGER.debug("disconnect: device=%s", self._device_id)
        if self.socket is not None:
            await self.socket.close()
            self.socket = None
        if self.task is not None:
            self.task.cancel()
            self.task = None

    async def _on_open(self) -> None:
        _LOGGER.debug("_on_open: device=%s", self._device_id)

    async def _process_messages(self):
        async for msg in self.socket:
            await self._on_message(msg)

    async def _on_message(self, message: WSMessage):
        try:
            _LOGGER.debug(
                "_on_message: device=%s, message=%s", self._device_id, message
            )
            await self._message_callback(message)
        except Exception as err:
            _LOGGER.error(
                "_on_message: %s Error processing message=%s error=%s",
                self._device_id,
                message,
                err,
            )
            traceback.print_exc()

    async def _on_error(self, error: str = "Unspecified") -> None:
        _LOGGER.debug("_on_error: device=%s, error=%s", self._device_id, error)

    async def _on_close(self, future="") -> None:
        _LOGGER.debug("_on_close: device=%s", self._device_id)
        self.socket = None
        await self._close_callback()

    async def send_message(self, message):
        if self.socket is None:
            raise WebSocketConnectionException("Socket is not open")
        await self.socket.send_str(message)
