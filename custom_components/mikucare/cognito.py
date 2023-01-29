import asyncio
import logging

from homeassistant.exceptions import ConfigEntryAuthFailed

from .const import COGNITO_CLIENT_ID
from .const import COGNITO_CLIENT_SECRET
from .const import (
    COGNITO_USER_POOL_ID,
)
from .pycognito import Cognito
from .pycognito.exceptions import DeviceSrpAuthChallengeException
from .pycognito.exceptions import SMSMFAChallengeException

_LOGGER: logging.Logger = logging.getLogger(__package__)


def create_cognito(
    username,
    access_token=None,
    refresh_token=None,
    id_token=None,
    device_group_key=None,
    device_key=None,
):
    return Cognito(
        access_key="access_key",  # Not used but required for confirm_device
        secret_key="secret_key",  # Not used but required for confirm_device
        user_pool_id=COGNITO_USER_POOL_ID,
        client_id=COGNITO_CLIENT_ID,
        client_secret=COGNITO_CLIENT_SECRET,
        username=username,
        id_token=id_token,
        refresh_token=refresh_token,
        access_token=access_token,
        device_group_key=device_group_key,
        device_key=device_key,
    )


async def call_cognito(cognito, func, args=None):
    if args is None:
        args = []
    try:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, func, *args)
    except (
        cognito.client.exceptions.NotAuthorizedException,
        cognito.client.exceptions.UserNotFoundException,
    ) as err:
        _LOGGER.warning("call_cognito: Invalid credentials")
        raise ConfigEntryAuthFailed("Invalid credentials") from err


async def login(cognito: Cognito, password: str, device_password: str):
    if cognito.access_token is not None:
        try:
            _LOGGER.debug("login: Refresh token if expired")
            await call_cognito(cognito, cognito.check_token)
            return
        except Exception as err:
            _LOGGER.debug("login: Error refreshing tokens: %s", err)

    try:
        _LOGGER.debug("login: Log in")
        await call_cognito(cognito, cognito.authenticate, [password])
    except DeviceSrpAuthChallengeException:
        _LOGGER.debug("login: Device SRP Auth")
        await call_cognito(cognito, cognito.authenticate_device, [device_password])
    except SMSMFAChallengeException as err:
        _LOGGER.warning("async_create_data: SMS MFA code needed")
        raise ConfigEntryAuthFailed("SMS MFA code needed") from err
