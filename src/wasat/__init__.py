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
    ClientCertificateStore,
    FileClientCertificateStore,
    generate_self_signed_cert,
)
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
from .uri import GEMINI_DEFAULT_PORT, GeminiURI

##############################################################################
# Exports.
__all__ = [
    "Client",
    "Response",
    "StatusCode",
    "GeminiURI",
    "GEMINI_DEFAULT_PORT",
    "TrustStore",
    "FileTrustStore",
    "ClientCertificateStore",
    "FileClientCertificateStore",
    "ClientCertCallback",
    "generate_self_signed_cert",
    "WasatError",
    "URIError",
    "ProtocolError",
    "ConnectionError",
    "SecurityError",
    "RedirectError",
]

### __init__.py ends here
