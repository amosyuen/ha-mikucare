"""
Custom integration to integrate Miku Care with Home Assistant.

For more details about this integration, please refer to
https://github.com/amosyuen/ha-mikucare
"""
import asyncio
import logging
from typing import Any

from homeassistant.components.sensor import (
    DOMAIN as SENSOR_PLATFORM,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_PASSWORD
from homeassistant.const import CONF_USERNAME
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
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
from .pycognito.exceptions import DeviceSrpAuthChallengeException
from .pycognito.exceptions import SMSMFAChallengeException

PLATFORMS = [SENSOR_PLATFORM]

_LOGGER: logging.Logger = logging.getLogger(__package__)


async def async_create_data(
    hass: HomeAssistant,
    config_data: dict[str:Any],
):
    """Create integration data"""
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

    async def wrap_errors(func):
        try:
            return await hass.async_add_executor_job(func)
        except (
            cognito.client.exceptions.NotAuthorizedException,
            cognito.client.exceptions.UserNotFoundException,
        ) as err:
            _LOGGER.warning("async_create_data: Invalid credentials")
            raise ConfigEntryAuthFailed("Invalid credentials") from err

    try:
        _LOGGER.debug("async_create_data: Cognito log in")

        def login():
            cognito.authenticate(password=password)

        await wrap_errors(login)
    except DeviceSrpAuthChallengeException:
        _LOGGER.debug("async_create_data: Device SRP Auth")

        def authenticate_device():
            cognito.authenticate_device(password=device_password)

        await wrap_errors(authenticate_device)
    except SMSMFAChallengeException as err:
        _LOGGER.warning("async_create_data: SMS MFA code needed")
        raise ConfigEntryAuthFailed("SMS MFA code needed") from err

    _LOGGER.debug("async_create_data: Miku log in")
    api = MikuCareApi(session)
    await api.login(cognito.id_token)

    devices = await api.list_devices()
    _LOGGER.debug("async_create_data: Miku found %d devices", len(devices))
    device_coordinators = []
    futures = []
    for device in devices:
        coordinator = MikuCareDeviceUpdateCoordinator(hass, api, device)
        device_coordinators.append(coordinator)
        futures.append(coordinator.async_config_entry_first_refresh())
    await asyncio.wait(futures)

    return {
        DATA_API: api,
        DATA_COGNITO: cognito,
        DATA_COORDINATORS: device_coordinators,
    }


async def async_setup_entry(hass: HomeAssistant, config_entry: ConfigEntry):
    """Set up this integration using UI."""
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
    """Handle removal of an entry."""
    unloaded = all(
        await asyncio.gather(
            *[
                hass.config_entries.async_forward_entry_unload(config_entry, platform)
                for platform in PLATFORMS
            ]
        )
    )
    if unloaded:
        hass.data[DOMAIN].pop(config_entry.entry_id)

    return unloaded


async def async_reload_entry(hass: HomeAssistant, config_entry: ConfigEntry) -> None:
    """Reload config entry."""
    await async_unload_entry(hass, config_entry)
    await async_setup_entry(hass, config_entry)
