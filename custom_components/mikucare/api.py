import asyncio
import logging
import math
from datetime import datetime
from datetime import timedelta

import async_timeout
from homeassistant.exceptions import ConfigEntryAuthFailed

from .cognito import login as cognito_login
from .exceptions import AuthException
from .pycognito import Cognito

_LOGGER = logging.getLogger(__name__)

BASE_URL = "https://api.mikucloud.com"
TIMEOUT = 60


class MikuCareApi:
    def __init__(self, cognito: Cognito, session, password: str, device_password: str):
        self.cognito = cognito
        self.session = session
        self.access_token = None

        self._device_password = device_password
        self._password = password

    async def login(self):
        await cognito_login(self.cognito, self._password, self._device_password)
        _LOGGER.debug("login: Miku log in")
        user = await self._http(
            context="login",
            path="users/login",
            method="post",
            payload={"cognitoToken": self.cognito.id_token},
        )
        _LOGGER.debug("login: Miku user=%s", user)

        self.access_token = user["token"]
        return user

    async def list_devices(self):
        response = await self._http(context="list_devices", path="users/me/devices")
        devices = response["devices"]
        _LOGGER.debug("list_devices: devices=%s", devices)
        return devices

    async def get_device(self, device_id: str):
        response = await self._http(context="get_device", path=f"devices/{device_id}")
        device = response["device"]
        _LOGGER.debug("get_device(%s): device=%s", device_id, device)
        return device

    async def list_analytics(
        self, device_id: str, start: datetime = None, end: datetime = None
    ):
        if end is None:
            end = datetime.now()
        if start is None:
            start = end - timedelta(minute=1)
        response = await self._http(
            context="list_analytics",
            path=f"devices/{device_id}/analytics",
            params={
                "from": math.floor(start.timestamp()),
                "until": math.ceil(end.timestamp()),
            },
        )
        data = response["data"]
        _LOGGER.debug("list_analytics(%s): data=%s", device_id, data)
        return data

    def get_headers(self):
        headers = {}
        if self.access_token:
            headers["authorization"] = f"Bearer {self.access_token}"
        return headers

    async def _call_cognito(self, func, args):
        try:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, func, *args)
        except (
            self.cognito.client.exceptions.NotAuthorizedException,
            self.cognito.client.exceptions.UserNotFoundException,
        ) as err:
            _LOGGER.warning("call_cognito: Invalid credentials")
            raise ConfigEntryAuthFailed("Invalid credentials") from err

    async def _http(self, context, path, method="get", params=None, payload=None):
        try:
            async with async_timeout.timeout(TIMEOUT):
                response = await getattr(self.session, method)(
                    f"{BASE_URL}/{path}",
                    headers=self.get_headers(),
                    params=params,
                    json=payload,
                )
        except Exception as err:
            _LOGGER.error(
                "_http: %s %s %s: error=%s",
                context,
                method,
                path,
                err,
            )
            raise err

        json = await response.json()

        status = json.get("statusCode")
        if status is not None:
            if (
                status == 401
                and json.get("attributes", {}).get("error") == "Expired token"
            ):
                raise AuthException(json)

            _LOGGER.error(
                "_http: %s %s %s: json=%s",
                context,
                method,
                path,
                json,
            )
            raise Exception(f"{context} {method} {path}:\n{json}")

        return json
