"""
Custom integration to integrate Miku Care with Home Assistant.

For more details about this integration, please refer to
https://github.com/amosyuen/ha-mikucare
"""
import asyncio
import logging
from typing import Any

import homeassistant.components as components
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_PASSWORD
from homeassistant.const import CONF_USERNAME
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import MikuCareApi
from .cognito import create_cognito
from .const import CONF_DEVICE_GROUP_KEY
from .const import CONF_DEVICE_KEY
from .const import CONF_DEVICE_PASSWORD
from .const import DATA_API
from .const import DATA_COGNITO
from .const import DATA_COORDINATORS
from .const import DOMAIN
from .coordinator import MikuCareDeviceUpdateCoordinator

PLATFORMS = [
    components.sensor.DOMAIN,
    components.switch.DOMAIN,
]

_LOGGER: logging.Logger = logging.getLogger(__package__)


async def async_create_data(
    hass: HomeAssistant,
    config_data: dict[str:Any],
):
    username = config_data.get(CONF_USERNAME)
    password = config_data.get(CONF_PASSWORD)
    device_group_key = config_data.get(CONF_DEVICE_GROUP_KEY)
    device_key = config_data.get(CONF_DEVICE_KEY)
    device_password = config_data.get(CONF_DEVICE_PASSWORD)
    _LOGGER.debug("async_create_data: config_data %s", config_data)
    session = async_get_clientsession(hass)

    cognito = create_cognito(
        username=username,
        device_group_key=device_group_key,
        device_key=device_key,
    )

    api = MikuCareApi(cognito, session, password, device_password)
    await api.login()

    devices = await api.list_devices()
    _LOGGER.debug("async_create_data: Miku found %d devices", len(devices))
    device_coordinators = []
    futures = []
    for device in devices:
        coordinator = MikuCareDeviceUpdateCoordinator(hass, api, device)
        device_coordinators.append(coordinator)
        futures.append(coordinator.connect())
    await asyncio.wait(futures)

    return {
        DATA_API: api,
        DATA_COGNITO: cognito,
        DATA_COORDINATORS: device_coordinators,
    }


async def async_setup_entry(hass: HomeAssistant, config_entry: ConfigEntry):
    if hass.data.get(DOMAIN) is None:
        hass.data.setdefault(DOMAIN, {})

    data = await async_create_data(hass, config_entry.data)
    hass.data[DOMAIN][config_entry.entry_id] = data

    for platform in PLATFORMS:
        hass.async_add_job(
            hass.config_entries.async_forward_entry_setup(config_entry, platform)
        )

    return True


async def async_unload_entry(hass: HomeAssistant, config_entry: ConfigEntry) -> bool:
    coordinators = hass.data[DOMAIN][config_entry.entry_id][DATA_COORDINATORS]
    unloaded = all(
        await asyncio.gather(
            *[
                hass.config_entries.async_forward_entry_unload(config_entry, platform)
                for platform in PLATFORMS
            ]
        )
    )
    if unloaded:
        for coordinator in coordinators:
            coordinator.disconnect()
        hass.data[DOMAIN].pop(config_entry.entry_id)

    return unloaded


async def async_reload_entry(hass: HomeAssistant, config_entry: ConfigEntry) -> None:
    await async_unload_entry(hass, config_entry)
    await async_setup_entry(hass, config_entry)
