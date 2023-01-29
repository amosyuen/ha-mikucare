"""Exceptions for Miku Care."""


class BaseMikuCareException(Exception):
    """Base exception."""


class AuthException(BaseMikuCareException):
    """Miku auth exception."""


class WebSocketConnectionException(BaseMikuCareException):
    """Web socket connection exception."""
