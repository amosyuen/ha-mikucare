"""Miku Care Coordinator"""
import asyncio
import logging
from collections.abc import Callable
from datetime import datetime
from datetime import timedelta
from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from .api import MikuCareApi
from .const import DOMAIN

_LOGGER: logging.Logger = logging.getLogger(__package__)


async def async_call_with_retry(func, args=[]):
    try:
        return await func(*args)
    except (asyncio.TimeoutError):
        # Retry for timeouts
        return await func(*args)


class MikuCareDeviceData:
    """Data for a Miku device."""

    def __init__(
        self,
        data: None | dict[str:Any] = {},
    ) -> None:
        self.breaths = data.get("bpm")
        self.humidity = data.get("humid")
        self.state = data.get("state")
        self.temperature = data.get("temp")
        self.lux_avg = data.get("lux")
        self.lux_max = data.get("maxLux")
        self.lux_min = data.get("minLux")
        self.sound_avg = data.get("avgSound")
        self.sound_max = data.get("maxSound")
        self.sound_min = data.get("minSound")
        self.sound_state = data.get("soundState")


class MikuCareDeviceUpdateCoordinator(DataUpdateCoordinator):
    """Class to manage fetching data from the API for a device."""

    def __init__(
        self,
        hass: HomeAssistant,
        api: MikuCareApi,
        device,
    ) -> None:
        """Initialize."""
        self.api = api
        self.device = device
        self._on_close: list[Callable] = []

        super().__init__(
            hass,
            _LOGGER,
            name=f'{DOMAIN}-device-{device["deviceId"]}',
            update_interval=timedelta(minutes=1),
        )

    async def _async_update_data(self):
        """Update data via api."""
        device_id = self.device["deviceId"]
        now = datetime.now()
        start_datetime = now + timedelta(minutes=-2)
        analytics = await async_call_with_retry(
            self.api.get_analytics, [device_id, start_datetime]
        )
        if len(analytics) == 0:
            _LOGGER.warning(
                "_async_update_data: %s: No device data",
                device_id,
            )
            return MikuCareDeviceData()

        data = analytics[-1]
        _LOGGER.debug("_async_update_data: %s: data=%s", device_id, data)
        return MikuCareDeviceData(data)
