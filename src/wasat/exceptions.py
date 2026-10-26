"""Exceptions for the Wasat Gemini client library."""


##############################################################################
class WasatError(Exception):
    """Base exception for all errors raised by the Wasat library."""


##############################################################################
class URIError(WasatError):
    """Raised when a Gemini URI is invalid or malformed."""


##############################################################################
class ProtocolError(WasatError):
    """Raised when the Gemini server violates the protocol."""


##############################################################################
class ConnectionError(WasatError):
    """Raised when a connection to the Gemini server fails."""


##############################################################################
class SecurityError(WasatError):
    """Raised when TLS or certificate validation (TOFU) fails."""


##############################################################################
class IgnorableSecurityError(SecurityError):
    """Base class for TLS or certificate security errors that can be ignored for a session."""


##############################################################################
class CertificateExpiredError(IgnorableSecurityError):
    """Raised when a server TLS certificate has expired."""


##############################################################################
class CertificateNotYetValidError(IgnorableSecurityError):
    """Raised when a server TLS certificate is not yet valid."""


##############################################################################
class HostnameMismatchError(IgnorableSecurityError):
    """Raised when a server TLS certificate does not match the requested hostname or IP address."""


##############################################################################
class CertificateUntrustedError(IgnorableSecurityError):
    """Raised when CA verification fails due to a self-signed or untrusted certificate."""


##############################################################################
class CertificateRevokedError(SecurityError):
    """Raised when a server TLS certificate has been revoked."""


##############################################################################
class FingerprintMismatchError(SecurityError):
    """Raised when a server TLS certificate fingerprint does not match the stored TOFU fingerprint."""


##############################################################################
class CertificateRejectedError(SecurityError):
    """Raised when a new server TLS certificate is rejected by the verification callback."""


##############################################################################
class RedirectError(WasatError):
    """Raised when redirect limits are exceeded or redirects are invalid."""


### exceptions.py ends here
