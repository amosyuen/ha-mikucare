"""Miku Care."""
import logging
from typing import Any

from homeassistant.components.sensor import ATTR_STATE_CLASS
from homeassistant.components.sensor import SensorDeviceClass
from homeassistant.components.sensor import SensorEntity
from homeassistant.components.sensor import SensorStateClass
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import ATTR_DEVICE_CLASS
from homeassistant.const import STATE_UNAVAILABLE
from homeassistant.core import callback
from homeassistant.core import HomeAssistant

from .const import DATA_COORDINATORS
from .const import DOMAIN
from .coordinator import MikuCareDeviceUpdateCoordinator
from .entity import MikuCareCoordinatorEntity
from .util import snake_case_to_title_space

SENSORS = [
    {
        "key": "algorithm_state",
    },
    {
        "key": "crib_state",
    },
    {
        "key": "breaths",
        ATTR_STATE_CLASS: SensorStateClass.MEASUREMENT,
        "native_unit_of_measurement": "bpm",
    },
    {
        "key": "humidity",
        ATTR_STATE_CLASS: SensorStateClass.MEASUREMENT,
        ATTR_DEVICE_CLASS: SensorDeviceClass.HUMIDITY,
        "native_unit_of_measurement": "%",
        "native_precision": 0,
    },
    {
        "key": "illuminance_avg",
        ATTR_STATE_CLASS: SensorStateClass.MEASUREMENT,
        ATTR_DEVICE_CLASS: SensorDeviceClass.ILLUMINANCE,
        "native_unit_of_measurement": "lx",
    },
    {
        "key": "illuminance_max",
        ATTR_STATE_CLASS: SensorStateClass.MEASUREMENT,
        ATTR_DEVICE_CLASS: SensorDeviceClass.ILLUMINANCE,
        "native_unit_of_measurement": "lx",
    },
    {
        "key": "illuminance_min",
        ATTR_STATE_CLASS: SensorStateClass.MEASUREMENT,
        ATTR_DEVICE_CLASS: SensorDeviceClass.ILLUMINANCE,
        "native_unit_of_measurement": "lx",
    },
    {
        "key": "sound_avg",
        ATTR_STATE_CLASS: SensorStateClass.MEASUREMENT,
        "native_precision": 0,
    },
    {
        "key": "sound_max",
        ATTR_STATE_CLASS: SensorStateClass.MEASUREMENT,
        "native_precision": 0,
    },
    {
        "key": "sound_min",
        ATTR_STATE_CLASS: SensorStateClass.MEASUREMENT,
        "native_precision": 0,
    },
    {"key": "speaker_state", "translation_key": "speaker_state"},
    {"key": "state", "translation_key": "state"},
    {
        "key": "temperature",
        ATTR_STATE_CLASS: SensorStateClass.MEASUREMENT,
        ATTR_DEVICE_CLASS: SensorDeviceClass.TEMPERATURE,
        "native_unit_of_measurement": "°C",
        "native_precision": 0,
    },
]


_LOGGER: logging.Logger = logging.getLogger(__package__)


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities
):
    data = hass.data[DOMAIN][entry.entry_id]
    coordinators = data[DATA_COORDINATORS]

    entities = []
    for coordinator in coordinators:
        for params in SENSORS:
            entities.append(MikuCareDeviceSensor(coordinator=coordinator, **params))

    async_add_entities(entities)


class MikuCareDeviceSensor(MikuCareCoordinatorEntity, SensorEntity):
    """Miku Care Device Entity Sensor."""

    def __init__(
        self,
        coordinator: MikuCareDeviceUpdateCoordinator,
        key: str,
        **params: dict[str:Any],
    ) -> None:
        self._key = key
        self._attr_state = STATE_UNAVAILABLE

        device_id = coordinator.device["deviceId"]
        device_name = coordinator.device["subjectName"]
        self._attr_name = f"{device_name} {snake_case_to_title_space(key)}"
        self._attr_unique_id = f"{device_id}_{key}"

        for key, value in params.items():
            setattr(self, f"_attr_{key}", value)

        super().__init__(coordinator)

    @property
    def available(self) -> bool:
        if self.coordinator.data is None:
            return False
        return True

    @property
    def native_value(self) -> Any:
        if self.coordinator.data is None:
            return None

        return getattr(self.coordinator.data, self._key)

    # @callback
    # async def async_on_demand_update(self):
    #     await self.coordinator.async_request_refresh()

    @callback
    def _handle_coordinator_update(self) -> None:
        self.async_write_ha_state()
