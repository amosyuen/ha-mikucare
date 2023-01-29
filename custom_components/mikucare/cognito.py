import logging

from .const import COGNITO_CLIENT_ID
from .const import COGNITO_CLIENT_SECRET
from .const import (
    COGNITO_USER_POOL_ID,
)
from .pycognito import Cognito
from .pycognito.exceptions import (
    DeviceSrpAuthChallengeException,
)

_LOGGER = logging.getLogger(__name__)


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


# Will throw SMSMFAChallengeException if 2FA SMS needed
def login(cognito, password, device_password):
    _LOGGER.debug("cognito.login: username=%s", cognito.username)

    if cognito.access_token and cognito.refresh_token and cognito.id_token:
        try:
            _LOGGER.debug("cognito.login: Checking if tokens are expired")
            cognito.check_token(renew=True)
            return cognito
        except Exception as error:
            _LOGGER.error(
                "cognito.login: Error verifying and refreshing tokens: %s", error
            )

    try:
        _LOGGER.debug("cognito.login: Logging in")
        cognito.authenticate(password=password)
    except DeviceSrpAuthChallengeException:
        _LOGGER.debug("cognito.login: Device SRP Auth")
        cognito.authenticate_device(password=device_password)


def respond_to_2fa(cognito, code, hasDeviceKey, device_password):
    cognito.respond_to_sms_mfa_challenge(code)

    # Register 2FA device
    if not hasDeviceKey:
        _LOGGER.debug("cognito.login: device_key=%s", cognito.device_key)

        cognito.confirm_device(
            device_name="sdk_gphone64_x86_64",
            device_password=device_password,
        )
        _LOGGER.info(
            "cognito.login: MFA device %s has been confirmed", cognito.device_key
        )
