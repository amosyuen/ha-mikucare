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
from homeassistant.const import STATE_UNKNOWN
from homeassistant.core import callback
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DATA_COORDINATORS
from .const import DOMAIN
from .util import snake_case_to_title_space

SENSORS = [
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
    },
    {
        "key": "lux_avg",
        ATTR_STATE_CLASS: SensorStateClass.MEASUREMENT,
        ATTR_DEVICE_CLASS: SensorDeviceClass.ILLUMINANCE,
        "native_unit_of_measurement": "lx",
    },
    {
        "key": "lux_max",
        ATTR_STATE_CLASS: SensorStateClass.MEASUREMENT,
        ATTR_DEVICE_CLASS: SensorDeviceClass.ILLUMINANCE,
        "native_unit_of_measurement": "lx",
    },
    {
        "key": "lux_min",
        ATTR_STATE_CLASS: SensorStateClass.MEASUREMENT,
        ATTR_DEVICE_CLASS: SensorDeviceClass.ILLUMINANCE,
        "native_unit_of_measurement": "lx",
    },
    {
        "key": "sound_avg",
        ATTR_STATE_CLASS: SensorStateClass.MEASUREMENT,
        ATTR_DEVICE_CLASS: SensorDeviceClass.SOUND_PRESSURE,
        "native_unit_of_measurement": "dB",
        "native_precision": 2,
    },
    {
        "key": "sound_max",
        ATTR_STATE_CLASS: SensorStateClass.MEASUREMENT,
        ATTR_DEVICE_CLASS: SensorDeviceClass.SOUND_PRESSURE,
        "native_unit_of_measurement": "dB",
        "native_precision": 2,
    },
    {
        "key": "sound_min",
        ATTR_STATE_CLASS: SensorStateClass.MEASUREMENT,
        ATTR_DEVICE_CLASS: SensorDeviceClass.SOUND_PRESSURE,
        "native_unit_of_measurement": "dB",
        "native_precision": 2,
    },
    {
        "key": "sound_state",
    },
    {"key": "state", "translation_key": "state"},
    {
        "key": "temperature",
        ATTR_STATE_CLASS: SensorStateClass.MEASUREMENT,
        ATTR_DEVICE_CLASS: SensorDeviceClass.TEMPERATURE,
        "native_unit_of_measurement": "°F",
    },
]


_LOGGER: logging.Logger = logging.getLogger(__package__)


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities
):
    """Setup sensor platform."""
    data = hass.data[DOMAIN][entry.entry_id]
    coordinators = data[DATA_COORDINATORS]

    entities = []
    for coordinator in coordinators:
        _LOGGER.debug(
            "async_setup_entry: Creating entities for device %s",
            coordinator.device["deviceId"],
        )
        for params in SENSORS:
            entities.append(MikuCareDeviceSensor(coordinator=coordinator, **params))

    async_add_entities(entities)


def create_device_info(device) -> DeviceInfo:
    """Return device info."""
    _LOGGER.debug(
        "create_device_info: Creating device info for device %s",
        device,
    )
    if device is None:
        return None
    device_info = DeviceInfo(
        id=device["deviceId"],
        identifiers={(DOMAIN, device["deviceId"])},
        name=f'{device["subjectName"]} Miku',
        manufacturer="Miku",
        model=device.get("partNumber"),
        sw_version=device.get("mikuVersion"),
    )

    return device_info


class MikuCareDeviceSensor(CoordinatorEntity, SensorEntity):
    """Miku Care Device Entity Sensor."""

    def __init__(
        self,
        coordinator,
        key,
        **params: dict[str:Any],
    ) -> None:
        """Initialize a Miku Care entity."""
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

        state = getattr(self.coordinator.data, self._key)
        if state is None:
            return STATE_UNKNOWN

        return state

    @property
    def device_info(self) -> DeviceInfo:
        """Return device info."""
        return create_device_info(self.coordinator.device)

    @callback
    async def async_on_demand_update(self):
        """Request update from coordinator."""
        await self.coordinator.async_request_refresh()

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        self.async_write_ha_state()
