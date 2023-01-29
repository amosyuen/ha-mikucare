"""Miku Care."""
import logging

from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import callback
from homeassistant.core import HomeAssistant

from .const import DATA_COORDINATORS
from .const import DOMAIN
from .coordinator import MikuCareDeviceUpdateCoordinator
from .entity import MikuCareCoordinatorEntity


_LOGGER: logging.Logger = logging.getLogger(__package__)


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities
):
    data = hass.data[DOMAIN][entry.entry_id]
    coordinators = data[DATA_COORDINATORS]

    entities = []
    for coordinator in coordinators:
        entities.append(MikuCareDeviceSwitch(coordinator=coordinator))

    async_add_entities(entities)


class MikuCareDeviceSwitch(MikuCareCoordinatorEntity, SwitchEntity):
    """Miku Care Device Switch."""

    def __init__(
        self,
        coordinator: MikuCareDeviceUpdateCoordinator,
    ) -> None:
        device_id = coordinator.device["deviceId"]
        device_name = coordinator.device["subjectName"]
        self._attr_name = f"{device_name} Power"
        self._attr_unique_id = f"{device_id}_power"

        super().__init__(coordinator)

    @property
    def available(self) -> bool:
        if self.coordinator.data is None:
            return False
        return True

    @property
    def is_on(self):
        data = self.coordinator.data
        if data is None:
            return None
        return data.power

    async def async_turn_on(self, **kwargs) -> None:
        _LOGGER.error("async_turn_on")
        # device = dict(self.coordinator.device)
        # state = dict(device["state"])
        # state["standbyMode"] = "inactive"
        # device["state"] = state
        # await self.coordinator.api.update_device(device["deviceId"], device)
        # self.async_write_ha_state()

    async def async_turn_off(self, **kwargs) -> None:
        _LOGGER.error("async_turn_off")
        # device = dict(self.coordinator.device)
        # state = dict(device["state"])
        # state["standbyMode"] = "active"
        # device["state"] = state
        # await self.coordinator.api.update_device(device["deviceId"], device)
        # self.async_write_ha_state()

    @callback
    async def async_on_demand_update(self):
        await self.coordinator.async_request_refresh()

    @callback
    def _handle_coordinator_update(self) -> None:
        self.async_write_ha_state()
