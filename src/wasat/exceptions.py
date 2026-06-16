"""Exceptions for the Wasat Gemini client library."""


class WasatError(Exception):
    """Base exception for all errors raised by the Wasat library."""


class URIError(WasatError):
    """Raised when a Gemini URI is invalid or malformed."""


class ProtocolError(WasatError):
    """Raised when the Gemini server violates the protocol."""


class ConnectionError(WasatError):
    """Raised when a connection to the Gemini server fails."""


class SecurityError(WasatError):
    """Raised when TLS or certificate validation (TOFU) fails."""


class RedirectError(WasatError):
    """Raised when redirect limits are exceeded or redirects are invalid."""


### exceptions.py ends here
