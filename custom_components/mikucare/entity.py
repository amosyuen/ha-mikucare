"""Miku Care base entity."""
import logging

from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import MikuCareDeviceUpdateCoordinator


_LOGGER: logging.Logger = logging.getLogger(__package__)


class MikuCareCoordinatorEntity(CoordinatorEntity[MikuCareDeviceUpdateCoordinator]):
    """Miku Care Device Coordinator Entity."""

    @property
    def device_info(self) -> DeviceInfo:
        device = self.coordinator.device
        if device is None:
            return None

        return DeviceInfo(
            identifiers={(DOMAIN, device["deviceId"])},
            name=f'{device["subjectName"]} Miku',
            manufacturer="Miku",
            model=device.get("partNumber"),
            sw_version=device.get("mikuVersion"),
        )
