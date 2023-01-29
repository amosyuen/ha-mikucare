import logging
from datetime import datetime

import async_timeout

_LOGGER = logging.getLogger(__name__)

BASE_URL = "https://api.mikucloud.com"
TIMEOUT = 60


class MikuCareApi:
    """API for Miku Care"""

    def __init__(self, session):
        self._session = session
        self._access_token = None

    async def login(self, id_token):
        """Login using ID token from Amazon Cognito"""
        user = await self._http_post("login", "users/login", {"cognitoToken": id_token})
        _LOGGER.debug("login: user=%s", user)

        self._access_token = user["token"]
        return user

    async def list_devices(self):
        """List devices for logged in user"""
        response = await self._http_get("list_devices", "users/me/devices")
        devices = response["devices"]
        _LOGGER.debug("list_devices: devices=%s", devices)
        return devices

    async def get_analytics(self, device_id, start_datetime, end_datetime=None):
        """Get analytics for device"""
        if end_datetime is None:
            end_datetime = datetime.now()
        from_timestamp = round(datetime.timestamp(start_datetime))
        to_timestamp = round(datetime.timestamp(end_datetime))
        params = {
            "from": from_timestamp,
            "until": to_timestamp,
        }
        context = f"get_analytics({device_id},{from_timestamp}-{to_timestamp})"
        response = await self._http_get(
            context, f"devices/{device_id}/analytics", params
        )
        analytics = response["data"]
        _LOGGER.debug("%s: analytics=%s", context, analytics)
        return analytics

    def _headers(self):
        headers = {}
        if self._access_token:
            headers["authorization"] = f"Bearer {self._access_token}"
        return headers

    async def _http_get(self, context, path, params=None):

        try:
            async with async_timeout.timeout(TIMEOUT):
                response = await self._session.get(
                    f"{BASE_URL}/{path}",
                    headers=self._headers(),
                    params=params,
                )
        except Exception as err:  # pylint: disable=broad-except
            _LOGGER.error(
                "_http_get: context=%s, path=%s, error=%s",
                context,
                path,
                err,
            )
            raise err
        json = await response.json()

        if "error" in json:
            _LOGGER.error(
                "_http_get: context=%s, path=%s, json=%s",
                context,
                path,
                json,
            )
            raise Exception(f'{context}: {json["error"]}: {json["message"]}:\n{json}')

        return json

    async def _http_post(self, context, path, payload=None):
        try:
            async with async_timeout.timeout(TIMEOUT):
                response = await self._session.post(
                    f"{BASE_URL}/{path}",
                    headers=self._headers(),
                    json=payload,
                )
        except Exception as err:  # pylint: disable=broad-except
            _LOGGER.error(
                "_http_post: context=%s, path=%s, error=%s",
                context,
                path,
                err,
            )
            raise err
        json = await response.json()

        if "error" in json:
            _LOGGER.error(
                "_http_get: context=%s, path=%s, json=%s",
                context,
                path,
                json,
            )
            raise Exception(f'{context}: {json["error"]}: {json["message"]}:\n{json}')

        return json


# Device data
# {
#   "devices": [
#     {
#       "deviceId": "1414221B6658",
#       "subjectName": "Leo",
#       "subjectDob": "2022-10-01",
#       "subjectGender": "m",
#       "subjectIsPremature": false,
#       "subscriptionId": null,
#       "subscriptionState": null,
#       "isOwner": 1,
#       "subjectRelation": null,
#       "state": {
#         "factoryReset": false,
#         "deviceUpdating": false,
#         "criticalUpdateInProgress": false,
#         "2.4GHz": true,
#         "Audio": {
#           "mic": "10",
#           "mute": "off",
#           "volume": "10"
#         },
#         "ROI": {
#           "corner1": {
#             "x": 0.13,
#             "y": 0.16
#           },
#           "corner2": {
#             "x": 0.06,
#             "y": 0.78
#           },
#           "corner3": {
#             "x": 0.92,
#             "y": 0.89
#           },
#           "corner4": {
#             "x": 0.88,
#             "y": 0.19
#           },
#           "valid": true
#         },
#         "algoSensorData": false,
#         "connectivity": {
#           "iface": "wlan0",
#           "ssid": "Future Gadget Laboratory",
#           "mac": "f0:74:e4:1b:66:58",
#           "ipLocal": "192.168.0.164",
#           "hostname": "miku-1b6658",
#           "frequency": "5.18 GHz (Channel 36)",
#           "txBitrate": "433.3 MBit/s short GI",
#           "throttle_rate": 300000,
#           "signalQuality": "0",
#           "signalLevel": -49
#         },
#         "enableAdmin": true,
#         "enableAlarmDisarm": true,
#         "enableQuickView": false,
#         "hw_alarm": false,
#         "irMode": "auto",
#         "irThresh": "1000",
#         "led": "on",
#         "led_brightness": "0.150000",
#         "maxRange": "3.500000",
#         "minRange": "0.500000",
#         "otaExclusion": false,
#         "partNumber": "VBM02L16S01",
#         "sensitivity": {
#           "sleepTime": 10,
#           "sound": 0,
#           "wakeTime": 5
#         },
#         "standbyMode": "inactive",
#         "version": {
#           "shortVersion": "130462",
#           "mikuVersion": "Miku_13.04.62",
#           "xethruVersion": "XEP 3.4.7 (modified)"
#         },
#         "videoQuality": 2,
#         "videoRecording": "on",
#         "xethruStatus": "Running",
#         "crashcount": {
#           "mikucamerasensor": 0,
#           "mikuaudiorelay": 0,
#           "miku-v2-ota": 0,
#           "miku-qmmf-client": 0,
#           "diagnostics": 1,
#           "heartbeat": 1,
#           "nodebmtxserver": 1,
#           "rendezvous": 1
#         },
#         "lastHealthCheck": 1667081354,
#         "pipe": {
#           "me": "86443A35D6D6D426A27F4ED3BC39B50707AB31259590C6D8744671872F0EE6C9"
#         },
#         "uptime": "114 hours, 51 min, 1 sec"
#       },
#       "connectionStatus": "connected",
#       "lastConnStatus": "1667069604111"
#     }
#   ]
# }

# POST https://api.mikucloud.com/devices/1414221B6658/pipe/friend
# {
#   "certificate": "-----BEGIN CERTIFICATE-----\nMIICnTCCAYUCCAJXzG/pOoBQMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBldl\nYlJUQzAeFw0yMjEwMjgyMTM1MDhaFw0zMjEwMjYyMTM1MDhaMBExDzANBgNVBAMM\nBldlYlJUQzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK6MFQJaGdVf\nFjA6F/QHtz9uicMEsxu1ojrMpZliDj0PlQ6FwpLoj+uWHaPTI2eacIWkAWzInLSP\n/nTYeIvJra4gnuuxMBy7/UnzW1jUV3hIsrh3OOxpUcU20Iu6pNKU7NxK88VLHv5z\n+s7Enrtip1W0hPSoBNIU2L4nnyYIaV2ZoosZhEg+6EFmogCqFnP7EplnSkq44tmw\n2EkLClaMk9stU98Baqtq3yRmIfbLi7yKeUmts9xvLZBkzhJHVgq/CdgIzNeKU2xX\nkpQ6EBYqsyQGld4DEjLEmwyasRD5JPktp2xxKEWXO8S1JGHtDFqd1p1U1kY58Arh\ncbr4TauDFusCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAUH4kx3Vd9tY+koWKC0uM\nLzbusWXxqGxfcrs+5d8e1KLOCKcgHjFoV1qSA4uRdO8r2unWFKuy2XGmo1bXpkyu\nEGm8tBVaJQ+aUmjFOyx9Y3WIIHB/6XzXf2hQyLEg2TjWW6EA4KwS2tvh1nM4vR4e\nGZ4HtEtGLNXWuwQYdnZcOg0gZ7wG8Q2XKpDXr8RxMAx30k71hfAH/NqTYWaJME5a\nreCKA/haIq1IwSe5EzGwp4yCKyKrHUNDMY0mGcwBLKvBrYETszmzmbhhgz6LoR56\nhia7oqk9moz5P5tNlD5YtBnMX1UTeZShWkg971bwP5TotTZ9kODwcZphV8v6nIf/\nYQ==\n-----END CERTIFICATE-----\n    ",
#   "fingerprint": "230E4245E23771D0717B322F3B6D53A997DEF126586E698A1503BA4CEE31B230",
#   "requestID": "f4533147-5ada-4044-b158-a2762d229c2e"
# }
# Response
# {
#   "success": true,
#   "certExpiration": "2032-10-26T21:35:08Z",
#   "deviceAccess": "full"
# }

#
# {
#   "Results": {
#     "ef140058-e039-4a43-a969-b7f27d5ba6e9": {
#       "EndpointItemResponse": {
#         "StatusCode": 202,
#         "Message": "Accepted"
#       },
#       "EventsItemResponse": {
#         "88e0023f-e36a-4e53-960b-5376ee85c20c": {
#           "StatusCode": 202,
#           "Message": "Accepted"
#         },
#         "aa430960-1b38-44b1-b157-e00232afb4df": {
#           "StatusCode": 202,
#           "Message": "Accepted"
#         },
#         "a4cb1014-ad0e-479e-a636-0b246331f8ea": {
#           "StatusCode": 202,
#           "Message": "Accepted"
#         },
#         "b952fa87-633b-48f7-922b-0c2bd6d0c844": {
#           "StatusCode": 202,
#           "Message": "Accepted"
#         }
#       }
#     }
#   }
# }


# Add access code
# https://api.mikucloud.com/devices/1414221B6658/pipe/friend
# {
#   "certificate": "-----BEGIN CERTIFICATE-----\nMIICnTCCAYUCCAJXzG/pOoBQMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBldl\nYlJUQzAeFw0yMjEwMjgyMTM1MDhaFw0zMjEwMjYyMTM1MDhaMBExDzANBgNVBAMM\nBldlYlJUQzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK6MFQJaGdVf\nFjA6F/QHtz9uicMEsxu1ojrMpZliDj0PlQ6FwpLoj+uWHaPTI2eacIWkAWzInLSP\n/nTYeIvJra4gnuuxMBy7/UnzW1jUV3hIsrh3OOxpUcU20Iu6pNKU7NxK88VLHv5z\n+s7Enrtip1W0hPSoBNIU2L4nnyYIaV2ZoosZhEg+6EFmogCqFnP7EplnSkq44tmw\n2EkLClaMk9stU98Baqtq3yRmIfbLi7yKeUmts9xvLZBkzhJHVgq/CdgIzNeKU2xX\nkpQ6EBYqsyQGld4DEjLEmwyasRD5JPktp2xxKEWXO8S1JGHtDFqd1p1U1kY58Arh\ncbr4TauDFusCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAUH4kx3Vd9tY+koWKC0uM\nLzbusWXxqGxfcrs+5d8e1KLOCKcgHjFoV1qSA4uRdO8r2unWFKuy2XGmo1bXpkyu\nEGm8tBVaJQ+aUmjFOyx9Y3WIIHB/6XzXf2hQyLEg2TjWW6EA4KwS2tvh1nM4vR4e\nGZ4HtEtGLNXWuwQYdnZcOg0gZ7wG8Q2XKpDXr8RxMAx30k71hfAH/NqTYWaJME5a\nreCKA/haIq1IwSe5EzGwp4yCKyKrHUNDMY0mGcwBLKvBrYETszmzmbhhgz6LoR56\nhia7oqk9moz5P5tNlD5YtBnMX1UTeZShWkg971bwP5TotTZ9kODwcZphV8v6nIf/\nYQ==\n-----END CERTIFICATE-----\n    ",
#   "fingerprint": "230E4245E23771D0717B322F3B6D53A997DEF126586E698A1503BA4CEE31B230",
#   "otp": "100852",
#   "requestID": "a22e8b3f-0d87-4683-ae69-fa07cef438d8"
# }
# Response
# {
#   "success": true,
#   "certExpiration": "2032-10-26T21:35:08Z",
#   "deviceAccess": "full"
# }


# Set Standby
# POST https://pinpoint.us-east-1.amazonaws.com/v1/apps/1927dab206c044ffbcb2406a97fe7564/events
# authorization: AWS4-HMAC-SHA256 Credential=ASIAWJY5L2ESTWK6SJCW/20221029/us-east-1/mobiletargeting/aws4_request, SignedHeaders=host;x-amz-date;x-amz-security-token;x-amzn-clientsdkversion, Signature=a0ad10241cd365a4ff5d1819c94336548383d71bfb7af1769776dd8449c40ca0
# x-amz-security-token: IQoJb3JpZ2luX2VjEGYaCXVzLWVhc3QtMiJIMEYCIQCc2DnjcMCZQ3T0G8510hykwmhMsJKTFYkuWhmRnacThQIhAMf6m0PlFWj4AyOzCOGZ1yUtzZMDYLv/LQQJh8YGIL0KKsQECE8QAxoMNDMzMzE2NDE3ODI5Igx3lqNK1dg4Wy4HqOsqoQTZrqFRqQIKMxI40c+DqOgGHxoydLsDribF5bJ9vReNQ64+ewG+CM/SJqGq23MJ6mvanEovYSI2im+M1/Gb2aMLKacwRdJBXYKBkRWeli7U684TBDqIDR5qLpAJ1qQLRq2QpgOeEHGbWY7JERdQ6N2aLqw7tGqsOli1LkCN6HdPlJZDJFQ9vecOcPqF5C9mMZ//HNRz5MvJrOC3qK+7y7rMEkUsPdah6wGxJ1Ha0Sr9DEEFyO7jhT6TEse/x+cnHIxxNNz0vu6r+Tdy7X+WXjQ/dvVlqYX/iRH2ky1BudfxyC4WKEWPAapMJstK7CXsgVxrYK45fhY00d+OazLKlmkx0awlHLH5FpEHpvB5UTHCLco9ufHkowQoUUFgepr3Gia34c+50arVz/w1kbb6/sIPwGq6kZQUCWKdJLIpIBhlCvRdRX9DP+tnwu3pw8syCquwteRL5IEdANFfCLdGv50GJoDarurh4UV9M0qyr6j7dfEAojFvzshCb19dYNgux6IqIYBG7bHM8smuUyWQORqm9YhVwQSY8nx0dhhafiUUfo1FD/z+4A8dVNpDxtFakTrhkMi/EiicTOBNCbowqzBCve0OJGTiM/kmLtDSM7gFyyyAb7wynLuPqfVOSDBp9CqhQRp/57ozGUwArltIK/3uSvcN5kyKsX9RoB7su9aYwDezAft0DZOVCgY+TAM+B9ZUZOTVqXUoE+xSYxJI8p9uuTCBu/aaBjqEAl+3YaFOXhqZ5HwqvptSOMZcpJjBh7CIqYuxCCVibAnEqvIIZmXtzdcQZvwYgI6JzaMl925WHHMCdBlOainkEivcSDHG3MLe/GM7LoMrTvGqlVXH7jVXa7qzu8/te38xObenEsRT2iug76ZecZVl3aVE/qFeycR12AD+w5OLXT28hec02U2pw40e6si7FdPkQge1JYSH8UB8niaJxvGUvT4x/ocpdkqmjMmqTlAS9KxFyi8ZQKlOijfgWVVKrmBYJPW2HHe6MgUwdHbIIaankqhu5XgN6HiDdmfoYi2/YBtusn/PHjZyB+4+AKuXYVc+bKwxKRJrOKTJGMpeqrD45mXVKQ/7
# {
#   "BatchItem": {
#     "ef140058-e039-4a43-a969-b7f27d5ba6e9": {
#       "Endpoint": {
#         "Attributes": {},
#         "ChannelType": "GCM",
#         "Demographic": {
#           "AppVersion": "1.3.14",
#           "Locale": "en_US",
#           "Make": "Google",
#           "Model": "sdk_gphone_x86_64_arm64",
#           "Platform": "ANDROID",
#           "PlatformVersion": "11",
#           "Timezone": "America/Los_Angeles"
#         },
#         "EffectiveDate": "2022-10-29T21:39:12.142Z",
#         "Location": {
#           "City": "",
#           "Country": "USA",
#           "PostalCode": "",
#           "Region": ""
#         },
#         "Metrics": {},
#         "OptOut": "ALL"
#       },
#       "Events": {
#         "002f42a0-5421-4182-a532-d0ee01be78d2": {
#           "AppPackageName": "com.miku.mikucare",
#           "AppTitle": "Miku",
#           "AppVersionCode": "373",
#           "Attributes": {
#             "On": "true"
#           },
#           "ClientSdkVersion": "2.15.2",
#           "EventType": "Monitor_Button_Standby",
#           "Metrics": {},
#           "SdkName": "aws-sdk-android",
#           "Session": {
#             "Id": "7d5ba6e9-20221029-213912268",
#             "StartTimestamp": "2022-10-29T21:39:12.268Z"
#           },
#           "Timestamp": "2022-10-29T21:44:49.307Z"
#         }
#       }
#     }
#   }
# }
