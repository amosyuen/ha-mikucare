"""Adds config flow for Miku Care."""
import logging
from typing import Any

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_PASSWORD
from homeassistant.const import CONF_USERNAME

from .cognito import create_cognito
from .const import CONF_DEVICE_GROUP_KEY
from .const import CONF_DEVICE_KEY
from .const import CONF_DEVICE_PASSWORD
from .const import DOMAIN
from .pycognito import Cognito
from .pycognito.aws_srp import AWSSRP
from .pycognito.exceptions import (
    SMSMFAChallengeException,
)

CONF_MFA_CODE = "mfa_code"

_LOGGER: logging.Logger = logging.getLogger(__package__)


def _get_auth_schema(data: dict[str:Any]):
    return {
        vol.Required(CONF_USERNAME, default=data.get(CONF_USERNAME, "")): str,
        vol.Required(CONF_PASSWORD, default=data.get(CONF_PASSWORD, "")): str,
    }


def _get_mfa_schema(data: dict[str:Any]):
    if data is None:
        data = {}
    return {
        vol.Required(CONF_MFA_CODE): str,
    }


class MikuCareFlowHandler(config_entries.ConfigFlow, domain=DOMAIN):
    """Config flow for Miku Care."""

    VERSION = 1
    CONNECTION_CLASS = config_entries.CONN_CLASS_CLOUD_POLL
    reauth_entry: ConfigEntry = None

    def __init__(self):
        """Initialize."""
        self._cognito: Cognito = None
        self._data = {CONF_DEVICE_PASSWORD: AWSSRP.generate_device_password()}
        self._init = False
        self._finish_fn = None

    async def async_step_user(self, user_input=None):
        """Handle a flow initialized by the user."""

        self._finish_fn = self._create_entry
        self._init = True
        return await self.async_step_auth(user_input)

    async def async_step_auth(self, user_input):
        """Config step for username and password"""
        errors = {}

        if user_input is not None:
            self._data.update(user_input)

            if self._init:
                unique_id = self._data[CONF_USERNAME]
                await self.async_set_unique_id(unique_id)
                self._abort_if_unique_id_configured()

            self._cognito = create_cognito(self._data.get(CONF_USERNAME))
            try:

                def login():
                    return self._cognito.authenticate(
                        password=self._data.get(CONF_PASSWORD)
                    )

                await self.hass.async_add_executor_job(login)
            except (
                self._cognito.client.exceptions.NotAuthorizedException,
                self._cognito.client.exceptions.UserNotFoundException,
            ):
                errors = {"base": "invalid_auth"}
            except SMSMFAChallengeException:
                _LOGGER.debug("async_step_auth: SMS MFA Challenge")
                return self.async_show_form(
                    step_id="mfa_auth",
                    data_schema=vol.Schema(_get_mfa_schema(user_input)),
                    errors=errors,
                )

            if len(errors) == 0:
                return await self._finish_fn()

        return self.async_show_form(
            step_id="auth",
            data_schema=vol.Schema(_get_auth_schema(user_input)),
            errors=errors,
        )

    async def async_step_mfa_auth(self, user_input):
        """Config step for MFA code"""
        errors = {}

        if user_input is not None:
            errors = await self.verify_mfa_code(user_input)

            if len(errors) == 0:
                return await self._finish_fn()

        return self.async_show_form(
            step_id="mfa_auth",
            data_schema=vol.Schema(_get_mfa_schema(user_input)),
            errors=errors,
        )

    async def verify_mfa_code(self, user_input):
        try:

            def response_to_mfa_challenge():
                self._cognito.respond_to_sms_mfa_challenge(
                    user_input.get(CONF_MFA_CODE)
                )

            await self.hass.async_add_executor_job(response_to_mfa_challenge)

            # Register 2FA device
            _LOGGER.debug(
                "async_step_mfa_auth: Confirming device device_key=%s",
                self._cognito.device_key,
            )

            def confirm_device():
                self._cognito.confirm_device(
                    device_name="sdk_gphone64_x86_64",
                    device_password=self._data.get(CONF_DEVICE_PASSWORD),
                )

            await self.hass.async_add_executor_job(confirm_device)

            return {}
        except self._cognito.client.exceptions.CodeMismatchException:
            return {"base": "invalid_mfa_code"}

    def _update_data(self):
        self._data[CONF_DEVICE_GROUP_KEY] = self._cognito.device_group_key
        self._data[CONF_DEVICE_KEY] = self._cognito.device_key

    async def _create_entry(self):
        self._update_data()
        return self.async_create_entry(title=self._data[CONF_USERNAME], data=self._data)

    async def async_step_reauth(self, user_input=None):
        """Perform reauth upon an API authentication error."""
        self.reauth_entry = self.hass.config_entries.async_get_entry(
            self.context["entry_id"]
        )
        self._data = dict(self.reauth_entry.data)
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(self, user_input=None):
        """Dialog that informs the user that reauth is required."""
        self._finish_fn = self._update_entry_and_reload
        return await self.async_step_auth(user_input)

    async def _update_entry_and_reload(self):
        self._update_data()
        self.hass.config_entries.async_update_entry(self.reauth_entry, data=self._data)
        await self.hass.config_entries.async_reload(self.reauth_entry.entry_id)
        return self.async_abort(reason="reauth_successful")
