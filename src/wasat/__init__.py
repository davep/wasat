"""Wasat: An asynchronous, type-hinted client library for the Gemini Protocol."""

from .client import Client
from .exceptions import (
    ConnectionError,
    ProtocolError,
    RedirectError,
    SecurityError,
    URIError,
    WasatError,
)
from .response import Response
from .status import StatusCode
from .trust import FileTrustStore, TrustStore
from .uri import GeminiURI

__all__ = [
    "Client",
    "Response",
    "StatusCode",
    "GeminiURI",
    "TrustStore",
    "FileTrustStore",
    "WasatError",
    "URIError",
    "ProtocolError",
    "ConnectionError",
    "SecurityError",
    "RedirectError",
]

### __init__.py ends here
