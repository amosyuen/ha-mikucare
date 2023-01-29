"""Miku Care Coordinator"""
import asyncio
import logging
from collections.abc import Callable
from datetime import datetime
from datetime import timedelta
from typing import Any

from aiohttp import WSMessage
from aiohttp import WSMsgType
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from .api import MikuCareApi
from .const import DOMAIN
from .device_client import MikuCareDeviceClient
from .exceptions import AuthException


ALGO_STATE_MAP = {}
CRIB_STATE_MAP = {}
STATE_MAP = {"breathing": "sleeping"}
SPEAKER_STATE_MAP = {
    0: "none",
    1: "music",
    2: "streaming",
}

_LOGGER: logging.Logger = logging.getLogger(__package__)


async def async_call_with_retry(api, func, args=None):
    if args is None:
        args = []
    try:
        return await func(*args)
    except AuthException:
        await api.login()
        return await func(*args)
    except asyncio.TimeoutError:
        # Retry for timeouts
        return await func(*args)


class MikuCareDeviceData:
    def __init__(
        self,
    ) -> None:
        # Analytics
        self.analytics_update_time = datetime.fromtimestamp(0)
        self.breaths = None
        self.humidity = None
        self.state = None
        self.temperature = None
        self.illuminance_avg = None
        self.illuminance_max = None
        self.illuminance_min = None
        self.sound_avg = None
        self.sound_max = None
        self.sound_min = None
        self.speaker_state = None
        # device
        self.power = None
        # rnd_data
        self.algorithm_state = None
        self.crib_state = None

    def update_from_analytics_data(
        self,
        data: None | dict[str:Any] = None,
    ) -> None:
        if data is None:
            data = {}

        self.analytics_update_time = datetime.fromtimestamp(data.get("time", 0))
        self.breaths = data.get("bpm")
        self.humidity = data.get("humid")
        state = data.get("state")
        self.state = STATE_MAP.get(state, state)
        self.temperature = data.get("temp")
        self.illuminance_avg = data.get("lux")
        self.illuminance_max = data.get("maxLux")
        self.illuminance_min = data.get("minLux")
        self.sound_avg = data.get("avgSound")
        self.sound_max = data.get("maxSound")
        self.sound_min = data.get("minSound")
        sound_state = data.get("soundState")
        self.speaker_state = SPEAKER_STATE_MAP.get(sound_state, sound_state)

    def update_from_device(
        self,
        data: None | dict[str:Any] = None,
    ) -> None:
        if data is None:
            data = {}

        if data.get("connectionStatus") == "connected":
            self.power = data.get("state", {}).get("standbyMode") == "inactive"
            if not self.power:
                # Set analytics to None
                self.update_from_analytics_data({})
        else:
            self.power = None

    def update_from_rnd_data(
        self,
        data: None | dict[str:Any] = None,
    ) -> None:
        if data is None:
            data = {}

        algorithm_state = data.get("algo_state")
        self.algorithm_state = ALGO_STATE_MAP.get(algorithm_state, algorithm_state)
        crib_state = data.get("crib_state")
        self.crib_state = CRIB_STATE_MAP.get(crib_state, crib_state)


class MikuCareDeviceUpdateCoordinator(DataUpdateCoordinator):
    def __init__(
        self,
        hass: HomeAssistant,
        api: MikuCareApi,
        device,
    ) -> None:
        self.api = api
        self.device = device

        device_id = device["deviceId"]
        self.client = MikuCareDeviceClient(
            api,
            device_id,
            message_callback=self._message_callback,
            close_callback=self._async_update_data,
        )
        self._on_close: list[Callable] = []

        super().__init__(
            hass,
            _LOGGER,
            name=f"{DOMAIN}-device-{device_id}",
            update_interval=timedelta(minutes=1),
        )
        # Must come after __init__
        self.data = MikuCareDeviceData()

    async def connect(
        self,
    ):
        await self.client.connect()

    async def _async_update_data(self) -> MikuCareDeviceData:
        device = await async_call_with_retry(
            self.api, self.api.get_device, [self.device["deviceId"]]
        )
        if device is None:
            return None

        self.device = device
        self.data.update_from_device(device)

        if self.data.power:
            # We should get analytics data every minute, close and reopen client if no data for 2 minutes
            if (
                self.client.socket is not None
                and datetime.now() - self.data.analytics_update_time
                > timedelta(minutes=2)
            ):
                _LOGGER.debug(
                    "_async_update_data: Analytics data is more than 2 minutes old. Closing client."
                )
                await self.client.disconnect()
            if self.client.socket is None:
                # Rec-connect web-socket if not in standby
                await self.connect()
        return self.data

    async def _message_callback(self, message: WSMessage):
        if message.type == WSMsgType.TEXT:
            data = message.json()
            topic = data.get("topic")
            device_id = self.device["deviceId"]
            if topic == f"{device_id}/analytics":
                self.data.update_from_analytics_data(data.get("event"))
                self.async_set_updated_data(self.data)
            if topic == f"{device_id}/rnd_data":
                self.data.update_from_rnd_data(data.get("event"))
                self.async_set_updated_data(self.data)

    async def disconnect(self):
        await self.client.disconnect()
