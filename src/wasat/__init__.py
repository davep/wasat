"""An async client library for the Gemini Protocol."""

##############################################################################
# Python imports.
from importlib.metadata import version

######################################################################
# Main library information.
__author__ = "Dave Pearson"
__copyright__ = "Copyright 2026, Dave Pearson"
__credits__ = ["Dave Pearson"]
__maintainer__ = "Dave Pearson"
__email__ = "davep@davep.org"
__version__: str = version("wasat")
__licence__ = "MIT"

##############################################################################
# Local imports.
from .certs import (
    ClientCertCallback,
    ClientCertificate,
    ClientCertificateStore,
    FileClientCertificateStore,
    ServerCertificate,
    generate_self_signed_cert,
    normalize_scope,
)
from .client import Client, VerifyMode
from .exceptions import (
    ConnectionError,
    ProtocolError,
    RedirectError,
    SecurityError,
    URIError,
    WasatError,
)
from .response import Response, VerificationMethod
from .status import StatusCode
from .trust import FileTrustStore, TrustStore
from .uri import GEMINI_DEFAULT_PORT, GeminiURI

##############################################################################
# Exports.
__all__ = [
    "Client",
    "Response",
    "ServerCertificate",
    "ClientCertificate",
    "StatusCode",
    "GeminiURI",
    "GEMINI_DEFAULT_PORT",
    "TrustStore",
    "FileTrustStore",
    "ClientCertificateStore",
    "FileClientCertificateStore",
    "ClientCertCallback",
    "generate_self_signed_cert",
    "normalize_scope",
    "WasatError",
    "URIError",
    "ProtocolError",
    "ConnectionError",
    "SecurityError",
    "RedirectError",
    "VerifyMode",
    "VerificationMethod",
]

### __init__.py ends here
