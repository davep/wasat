"""Gemini and Titan URI representation and parsing."""

##############################################################################
# Future imports.
from __future__ import annotations

##############################################################################
# Python imports.
import mimetypes
from functools import cached_property
from pathlib import Path
from typing import Final, Self
from urllib.parse import (
    quote,
    unquote,
    urljoin,
    urlsplit,
    uses_fragment,
    uses_netloc,
    uses_params,
    uses_query,
    uses_relative,
)

##############################################################################
# Local imports.
from .exceptions import URIError

##############################################################################
GEMINI_SCHEME: Final[str] = "gemini"
"""The URL scheme for the Gemini protocol."""
GEMINI_PREFIX: Final[str] = f"{GEMINI_SCHEME}://"
"""The standard prefix for Gemini URIs."""
GEMINI_DEFAULT_PORT: Final[int] = 1965
"""The default network port for the Gemini protocol."""

TITAN_SCHEME: Final[str] = "titan"
"""The URL scheme for the Titan protocol."""
TITAN_PREFIX: Final[str] = f"{TITAN_SCHEME}://"
"""The standard prefix for Titan URIs."""
TITAN_DEFAULT_PORT: Final[int] = 1965
"""The default network port for the Titan protocol."""

type AnyURI = GeminiURI | TitanURI
"""Type alias for any supported protocol URI."""

_EXTENSION_MIME_TYPES: Final[dict[str, str]] = {
    ".gmi": "text/gemini",
    ".gemini": "text/gemini",
    ".txt": "text/plain",
    ".text": "text/plain",
    ".md": "text/markdown",
    ".markdown": "text/markdown",
    ".htm": "text/html",
    ".html": "text/html",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".svg": "image/svg+xml",
    ".pdf": "application/pdf",
    ".mp3": "audio/mpeg",
}
"""Well-known file extension to MIME type mappings for Gemini and Titan."""


##############################################################################
def guess_mime_type(path: str | Path, default: str = "application/octet-stream") -> str:
    """Guess the MIME type for a given file path.

    Args:
        path: The file path or filename to inspect.
        default: The fallback MIME type if detection fails.

    Returns:
        The detected MIME type string.
    """
    suffix = Path(path).suffix.lower()
    if suffix in _EXTENSION_MIME_TYPES:
        return _EXTENSION_MIME_TYPES[suffix]
    guessed, _ = mimetypes.guess_type(str(path))
    return guessed if guessed is not None else default


##############################################################################
def _normalise_scheme(uri: str) -> str:
    """Normalise the scheme portion of a URI to lowercase."""
    scheme, separator, rest = uri.partition("://")
    return f"{scheme.lower()}{separator}{rest}" if separator else uri


##############################################################################
class _UnsetType:
    """Sentinel class to distinguish between omitted arguments and None."""


_UNSET: Final[_UnsetType] = _UnsetType()
"""Sentinel value to indicate that an argument has not been provided."""


##############################################################################
class _BaseURI:
    """Abstract base class for Gemini-family URIs."""

    MAXIMUM_LENGTH: Final[int] = 1024
    """The maximum length of a URI string."""

    _EXPECTED_SCHEME: str = ""
    """The expected URI scheme for this class."""

    _DEFAULT_PORT: int = 1965
    """The default port for this URI scheme."""

    def __init__(self) -> None:
        """Initialise base URI attributes."""
        self._scheme: str
        """The scheme portion of the URI."""
        self._host: str
        """The hostname portion of the URI."""
        self._port: int
        """The port number of the URI."""
        self._path: str
        """The path portion of the URI."""
        self._query: str | None
        """The query string portion of the URI, or None."""

    _KNOWN_SCHEMES: Final[set[str]] = set(
        scheme
        for scheme in (
            GEMINI_SCHEME,
            TITAN_SCHEME,
            *uses_netloc,
            *uses_params,
            *uses_relative,
            *uses_query,
            *uses_fragment,
        )
        if scheme
    )
    """Set of known URI schemes for validation."""

    @property
    def scheme(self) -> str:
        """The URI scheme."""
        return self._scheme

    @property
    def host(self) -> str:
        """The target hostname."""
        return self._host

    @property
    def port(self) -> int:
        """The target port."""
        return self._port

    @property
    def path(self) -> str:
        """The resource path (defaults to '/')."""
        return self._path

    @property
    def query(self) -> str | None:
        """The query string or None."""
        return self._query

    @cached_property
    def bytes_left(self) -> int:
        """The number of bytes left before reaching the maximum URI length."""
        return max(0, self.MAXIMUM_LENGTH - len(self))

    @cached_property
    def is_too_long(self) -> bool:
        """Is the URI too long to be valid?"""
        return len(self) > self.MAXIMUM_LENGTH

    def __len__(self) -> int:
        """Return the length of the string representation of the URI."""
        return len(str(self))

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}('{self}')"


##############################################################################
class GeminiURI(_BaseURI):
    """Represents a validated Gemini protocol URI."""

    _EXPECTED_SCHEME = GEMINI_SCHEME
    _DEFAULT_PORT = GEMINI_DEFAULT_PORT

    def __init__(self, uri: str | GeminiURI) -> None:
        """Initialise and validate a Gemini URI.

        Args:
            uri: The raw URI string or an existing GeminiURI to clone.

        Raises:
            URIError: If the URI is empty, the scheme is missing or is not 'gemini',
                the host is missing or invalid, or if parsing of the URI fails.
        """
        super().__init__()

        if isinstance(uri, GeminiURI):
            self._scheme = uri.scheme
            self._host = uri.host
            self._port = uri.port
            self._path = uri.path
            self._query = uri.query
            return

        if not (cleaned := _normalise_scheme(uri.strip())):
            raise URIError("URI cannot be empty")

        to_parse = cleaned
        if cleaned.startswith(GEMINI_PREFIX):
            to_parse = "https://" + cleaned.removeprefix(GEMINI_PREFIX)

        try:
            parsed = urlsplit(to_parse)
            if (scheme := parsed.scheme.lower()) == "https" and cleaned.startswith(
                GEMINI_PREFIX
            ):
                scheme = GEMINI_SCHEME

            if not scheme:
                raise URIError("URI scheme is missing")
            if scheme != GEMINI_SCHEME:
                raise URIError(
                    f"Invalid URI scheme: '{scheme}'. Expected '{GEMINI_SCHEME}'"
                )

            if not parsed.hostname:
                raise URIError("URI host is missing or invalid")

            self._scheme = scheme
            self._host = parsed.hostname
            self._port = parsed.port if parsed.port is not None else GEMINI_DEFAULT_PORT
            self._path = parsed.path or "/"
            self._query = parsed.query if parsed.query else None
        except URIError:
            raise
        except Exception as error:
            raise URIError(f"Failed to parse URI: {error}") from error

    @classmethod
    def with_default_scheme(cls, uri: str) -> Self:
        """Add the Gemini scheme to a URI if it is missing.

        Args:
            uri: The URI string to check and potentially modify.

        Returns:
            A new GeminiURI instance with the scheme added if it was missing.

        Raises:
            URIError: If the URI is empty, the scheme is not 'gemini',
                the host is missing or invalid, or if parsing of the URI fails.
        """
        if (uri := _normalise_scheme(uri.strip())) and (
            not (scheme := urlsplit(uri).scheme) or scheme not in cls._KNOWN_SCHEMES
        ):
            uri = f"{GEMINI_PREFIX}{uri}"
        return cls(uri)

    def replace(
        self,
        *,
        host: str | _UnsetType = _UNSET,
        port: int | _UnsetType = _UNSET,
        path: str | None | _UnsetType = _UNSET,
        query: str | None | _UnsetType = _UNSET,
    ) -> Self:
        """Create a new GeminiURI by replacing specific parts of this URI.

        Args:
            host: The new hostname, or _UNSET to keep the current host.
            port: The new port number, or _UNSET to keep the current port.
            path: The new path, None to clear the path, or _UNSET to keep current.
            query: The new query string, None to clear the query, or _UNSET to keep current.

        Returns:
            A new GeminiURI instance with the replaced components.

        Raises:
            URIError: If the resulting URI is invalid.
        """
        new_host = self._host if isinstance(host, _UnsetType) else host
        new_port = self._port if isinstance(port, _UnsetType) else port

        if isinstance(path, _UnsetType):
            new_path = self._path
        else:
            if not path:
                new_path = "/"
            elif not path.startswith("/"):
                new_path = "/" + path
            else:
                new_path = path

        if isinstance(query, _UnsetType):
            new_query = self._query
        else:
            new_query = quote(query, safe="~()*!.'") if query is not None else None

        port_str = f":{new_port}" if new_port != GEMINI_DEFAULT_PORT else ""
        query_str = f"?{new_query}" if new_query else ""
        new_uri_str = f"{GEMINI_PREFIX}{new_host}{port_str}{new_path}{query_str}"
        return self.__class__(new_uri_str)

    def with_host(self, host: str) -> Self:
        """Return a new GeminiURI with the host replaced.

        Args:
            host: The new hostname.

        Returns:
            A new GeminiURI instance with the updated host.

        Raises:
            URIError: If the resulting URI has an invalid or empty host.
        """
        return self.replace(host=host)

    def with_port(self, port: int) -> Self:
        """Return a new GeminiURI with the port replaced.

        Args:
            port: The new port number.

        Returns:
            A new GeminiURI instance with the updated port.

        Raises:
            URIError: If the resulting URI has an invalid or empty port.
        """
        return self.replace(port=port)

    def with_path(self, path: str | None) -> Self:
        """Return a new GeminiURI with the path replaced or cleared.

        Args:
            path: The new path, or None to clear/reset the path.

        Returns:
            A new GeminiURI instance with the updated path.

        Raises:
            URIError: If the resulting URI path is invalid.
        """
        return self.replace(path=path)

    def with_query(self, query: str | None) -> Self:
        """Return a new GeminiURI with the query parameter replaced, set or cleared.

        Args:
            query: The new query string (will be URL-encoded), or None to clear.

        Returns:
            A new GeminiURI instance with the updated query.

        Raises:
            URIError: If the resulting URI query is invalid.
        """
        return self.replace(query=query)

    @property
    def without_query(self) -> Self:
        """Return a new GeminiURI with the query parameter removed.

        Returns:
            A new GeminiURI instance without the query string.

        Raises:
            URIError: If the resulting URI is invalid.
        """
        return self.with_query(None)

    @property
    def parent(self) -> Self:
        """The URI representing the parent directory of this URI's path.

        Note:
            Any query will be removed.
        """
        return self.without_query.with_path(str(Path(self._path).parent))

    @property
    def root(self) -> Self:
        """The URI representing the root directory of this URI's host.

        Note:
            Any query will be removed.
        """
        return self.without_query.with_path(None)

    def resolve(self, relative_uri: str) -> GeminiURI | TitanURI:
        """Resolve a relative URI string against this URI as a base.

        Args:
            relative_uri: The relative or absolute target URI string.

        Returns:
            A new GeminiURI or TitanURI representing the resolved target.

        Raises:
            URIError: If the resolved target URI is invalid, or if the relative URI
                cannot be parsed or resolved against the base URI.
        """
        relative_cleaned = _normalise_scheme(relative_uri)
        if relative_cleaned.startswith(TITAN_PREFIX):
            return TitanURI(relative_cleaned)

        base_str = str(self)
        base_http = base_str.replace(GEMINI_PREFIX, "https://", 1)

        relative_http = relative_cleaned
        if relative_cleaned.startswith(GEMINI_PREFIX):
            relative_http = "https://" + relative_cleaned.removeprefix(GEMINI_PREFIX)

        try:
            resolved_http = urljoin(base_http, relative_http)
            resolved_gemini = resolved_http.replace("https://", GEMINI_PREFIX, 1)
            return self.__class__(resolved_gemini)
        except Exception as error:
            raise URIError(
                f"Failed to resolve relative URI '{relative_uri}' against base '{base_str}': {error}"
            ) from error

    def to_titan(
        self,
        *,
        size: int | None = None,
        mime: str | None = None,
        token: str | None = None,
    ) -> TitanURI:
        """Convert this GeminiURI into a TitanURI with optional parameters.

        Args:
            size: Optional upload payload size in bytes.
            mime: Optional MIME type of the payload.
            token: Optional authorization token.

        Returns:
            A new TitanURI instance.
        """
        port_str = f":{self._port}" if self._port != TITAN_DEFAULT_PORT else ""
        query_str = f"?{self._query}" if self._query else ""
        uri_str = f"{TITAN_PREFIX}{self._host}{port_str}{self._path}{query_str}"
        titan_uri = TitanURI(uri_str)
        return titan_uri.replace(
            size=size if size is not None else _UNSET,
            mime=mime if mime is not None else _UNSET,
            token=token if token is not None else _UNSET,
        )

    def __str__(self) -> str:
        """Return the string representation of the URI."""
        port_str = f":{self._port}" if self._port != GEMINI_DEFAULT_PORT else ""
        query_str = f"?{self._query}" if self._query else ""
        return f"{GEMINI_PREFIX}{self._host}{port_str}{self._path}{query_str}"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, str):
            try:
                other = GeminiURI(other)
            except URIError:
                return False
        if not isinstance(other, GeminiURI):
            return NotImplemented
        return (
            self.scheme == other.scheme
            and self.host == other.host
            and self.port == other.port
            and self.path == other.path
            and self.query == other.query
        )

    def __hash__(self) -> int:
        """Return the hash value of the URI."""
        return hash((self._scheme, self._host, self._port, self._path, self._query))


##############################################################################
class TitanURI(_BaseURI):
    """Represents a validated Titan protocol URI with support for path parameters."""

    _EXPECTED_SCHEME = TITAN_SCHEME
    _DEFAULT_PORT = TITAN_DEFAULT_PORT

    def __init__(self, uri: str | TitanURI) -> None:
        """Initialise and validate a Titan URI.

        Args:
            uri: The raw URI string or an existing TitanURI to clone.

        Raises:
            URIError: If the URI is empty, the scheme is missing or is not 'titan',
                the host is missing or invalid, or if parsing of the URI fails.
        """
        super().__init__()
        self._parameters: dict[str, str | None]
        """Dictionary of semicolon-separated path parameters."""

        if isinstance(uri, TitanURI):
            self._scheme = uri.scheme
            self._host = uri.host
            self._port = uri.port
            self._path = uri.path
            self._query = uri.query
            self._parameters = uri.parameters
            return

        if not (cleaned := _normalise_scheme(uri.strip())):
            raise URIError("URI cannot be empty")

        to_parse = cleaned
        if cleaned.startswith(TITAN_PREFIX):
            to_parse = "https://" + cleaned.removeprefix(TITAN_PREFIX)

        try:
            parsed = urlsplit(to_parse)
            if (scheme := parsed.scheme.lower()) == "https" and cleaned.startswith(
                TITAN_PREFIX
            ):
                scheme = TITAN_SCHEME

            if not scheme:
                raise URIError("URI scheme is missing")
            if scheme != TITAN_SCHEME:
                raise URIError(
                    f"Invalid URI scheme: '{scheme}'. Expected '{TITAN_SCHEME}'"
                )

            if not parsed.hostname:
                raise URIError("URI host is missing or invalid")

            # Parse path and semicolon parameters
            raw_path = parsed.path or "/"
            path, parameters = self._parse_path_and_parameters(raw_path)

            self._scheme = scheme
            self._host = parsed.hostname
            self._port = parsed.port if parsed.port is not None else TITAN_DEFAULT_PORT
            self._path = path
            self._parameters = parameters
            self._query = parsed.query if parsed.query else None
        except URIError:
            raise
        except Exception as error:
            raise URIError(f"Failed to parse URI: {error}") from error

    @staticmethod
    def _parse_path_and_parameters(
        raw_path: str,
    ) -> tuple[str, dict[str, str | None]]:
        """Extract the canonical path and path parameters from a raw path string.

        Args:
            raw_path: The raw path string containing possible semicolon parameters.

        Returns:
            A tuple of (clean_path, parameters_dict).

        Raises:
            URIError: If parameter syntax or size value is invalid.
        """
        if ";" not in raw_path:
            clean_path = raw_path if raw_path.startswith("/") else f"/{raw_path}"
            return clean_path, {}

        clean_path_part, _, param_string = raw_path.partition(";")
        clean_path = (
            clean_path_part
            if clean_path_part.startswith("/")
            else f"/{clean_path_part}"
        )
        if not clean_path:
            clean_path = "/"

        parameters: dict[str, str | None] = {}
        for param in param_string.split(";"):
            param = param.strip()
            if not param:
                continue
            if "=" in param:
                key, value = param.split("=", 1)
                key = key.strip().lower()
                val = unquote(value.strip())
                if key == "size":
                    try:
                        size_int = int(val)
                        if size_int < 0:
                            raise ValueError
                    except ValueError as error:
                        raise URIError(
                            f"Invalid Titan size parameter: '{val}'. Expected a non-negative integer."
                        ) from error
                parameters[key] = val
            else:
                parameters[param.lower()] = None

        return clean_path, parameters

    @classmethod
    def with_default_scheme(cls, uri: str) -> Self:
        """Add the Titan scheme to a URI if it is missing.

        Args:
            uri: The URI string to check and potentially modify.

        Returns:
            A new TitanURI instance with the scheme added if it was missing.

        Raises:
            URIError: If the URI is empty, the scheme is not 'titan',
                the host is missing or invalid, or if parsing of the URI fails.
        """
        if (uri := _normalise_scheme(uri.strip())) and (
            not (scheme := urlsplit(uri).scheme) or scheme not in cls._KNOWN_SCHEMES
        ):
            uri = f"{TITAN_PREFIX}{uri}"
        return cls(uri)

    @property
    def parameters(self) -> dict[str, str | None]:
        """The dictionary of path parameters."""
        return dict(self._parameters)

    @property
    def size(self) -> int | None:
        """The upload size parameter in bytes, or None if omitted."""
        val = self._parameters.get("size")
        if val is not None:
            return int(val)
        return None

    @property
    def mime(self) -> str | None:
        """The MIME type parameter, or None if omitted."""
        return self._parameters.get("mime")

    @property
    def token(self) -> str | None:
        """The authorization token parameter, or None if omitted."""
        return self._parameters.get("token")

    def replace(
        self,
        *,
        host: str | _UnsetType = _UNSET,
        port: int | _UnsetType = _UNSET,
        path: str | None | _UnsetType = _UNSET,
        query: str | None | _UnsetType = _UNSET,
        size: int | None | _UnsetType = _UNSET,
        mime: str | None | _UnsetType = _UNSET,
        token: str | None | _UnsetType = _UNSET,
        parameters: dict[str, str | None] | _UnsetType = _UNSET,
    ) -> Self:
        """Create a new TitanURI by replacing specific parts of this URI.

        Args:
            host: The new hostname, or _UNSET to keep current.
            port: The new port number, or _UNSET to keep current.
            path: The new path, or _UNSET to keep current.
            query: The new query string, or _UNSET to keep current.
            size: The new size parameter, None to remove, or _UNSET to keep current.
            mime: The new mime parameter, None to remove, or _UNSET to keep current.
            token: The new token parameter, None to remove, or _UNSET to keep current.
            parameters: Complete dictionary replacement of parameters, or _UNSET.

        Returns:
            A new TitanURI instance with the replaced components.

        Raises:
            URIError: If the resulting URI is invalid.
        """
        new_host = self._host if isinstance(host, _UnsetType) else host
        new_port = self._port if isinstance(port, _UnsetType) else port

        if isinstance(path, _UnsetType):
            new_path = self._path
        else:
            if not path:
                new_path = "/"
            elif not path.startswith("/"):
                new_path = "/" + path
            else:
                new_path = path

        if isinstance(query, _UnsetType):
            new_query = self._query
        else:
            new_query = quote(query, safe="~()*!.'") if query is not None else None

        new_params = (
            dict(self._parameters)
            if isinstance(parameters, _UnsetType)
            else dict(parameters)
        )

        if not isinstance(size, _UnsetType):
            if size is None:
                new_params.pop("size", None)
            else:
                if size < 0:
                    raise URIError(
                        f"Invalid Titan size parameter: '{size}'. Expected a non-negative integer."
                    )
                new_params["size"] = str(size)

        if not isinstance(mime, _UnsetType):
            if mime is None:
                new_params.pop("mime", None)
            else:
                new_params["mime"] = mime

        if not isinstance(token, _UnsetType):
            if token is None:
                new_params.pop("token", None)
            else:
                new_params["token"] = token

        param_parts: list[str] = []
        for k, v in new_params.items():
            if v is None:
                param_parts.append(k)
            else:
                param_parts.append(f"{k}={v}")

        params_str = f";{';'.join(param_parts)}" if param_parts else ""
        port_str = f":{new_port}" if new_port != TITAN_DEFAULT_PORT else ""
        query_str = f"?{new_query}" if new_query else ""
        new_uri_str = (
            f"{TITAN_PREFIX}{new_host}{port_str}{new_path}{params_str}{query_str}"
        )
        return self.__class__(new_uri_str)

    def with_host(self, host: str) -> Self:
        """Return a new TitanURI with the host replaced.

        Args:
            host: The new hostname.

        Returns:
            A new TitanURI instance with the updated host.

        Raises:
            URIError: If the resulting URI has an invalid or empty host.
        """
        return self.replace(host=host)

    def with_port(self, port: int) -> Self:
        """Return a new TitanURI with the port replaced.

        Args:
            port: The new port number.

        Returns:
            A new TitanURI instance with the updated port.

        Raises:
            URIError: If the resulting URI has an invalid or empty port.
        """
        return self.replace(port=port)

    def with_path(self, path: str | None) -> Self:
        """Return a new TitanURI with the path replaced or cleared.

        Args:
            path: The new path, or None to clear/reset the path.

        Returns:
            A new TitanURI instance with the updated path.

        Raises:
            URIError: If the resulting URI path is invalid.
        """
        return self.replace(path=path)

    def with_query(self, query: str | None) -> Self:
        """Return a new TitanURI with the query parameter replaced, set or cleared.

        Args:
            query: The new query string (will be URL-encoded), or None to clear.

        Returns:
            A new TitanURI instance with the updated query.

        Raises:
            URIError: If the resulting URI query is invalid.
        """
        return self.replace(query=query)

    def with_size(self, size: int | None) -> Self:
        """Return a new TitanURI with the size parameter set or removed.

        Args:
            size: The payload size in bytes, or None to remove.

        Returns:
            A new TitanURI instance.

        Raises:
            URIError: If size is negative.
        """
        return self.replace(size=size)

    def with_mime(self, mime: str | None) -> Self:
        """Return a new TitanURI with the MIME type parameter set or removed.

        Args:
            mime: The MIME type string, or None to remove.

        Returns:
            A new TitanURI instance.
        """
        return self.replace(mime=mime)

    def with_token(self, token: str | None) -> Self:
        """Return a new TitanURI with the authorization token parameter set or removed.

        Args:
            token: The authorization token string, or None to remove.

        Returns:
            A new TitanURI instance.
        """
        return self.replace(token=token)

    def with_parameters(self, parameters: dict[str, str | None]) -> Self:
        """Return a new TitanURI with the parameters dictionary replaced.

        Args:
            parameters: The new dictionary of parameters.

        Returns:
            A new TitanURI instance.
        """
        return self.replace(parameters=parameters)

    @property
    def without_parameters(self) -> Self:
        """Return a new TitanURI with all path parameters removed.

        Returns:
            A new TitanURI instance without parameters.
        """
        return self.replace(parameters={})

    @property
    def without_query(self) -> Self:
        """Return a new TitanURI with the query parameter removed.

        Returns:
            A new TitanURI instance without the query string.

        Raises:
            URIError: If the resulting URI is invalid.
        """
        return self.with_query(None)

    @property
    def parent(self) -> Self:
        """The URI representing the parent directory of this URI's path.

        Note:
            Any query and parameters will be removed.
        """
        return self.without_query.without_parameters.with_path(
            str(Path(self._path).parent)
        )

    @property
    def root(self) -> Self:
        """The URI representing the root directory of this URI's host.

        Note:
            Any query and parameters will be removed.
        """
        return self.without_query.without_parameters.with_path(None)

    def resolve(self, relative_uri: str) -> GeminiURI | TitanURI:
        """Resolve a relative URI string against this URI as a base.

        Args:
            relative_uri: The relative or absolute target URI string.

        Returns:
            A new GeminiURI or TitanURI representing the resolved target.

        Raises:
            URIError: If the resolved target URI is invalid, or if the relative URI
                cannot be parsed or resolved against the base URI.
        """
        relative_cleaned = _normalise_scheme(relative_uri)
        if relative_cleaned.startswith(GEMINI_PREFIX):
            return GeminiURI(relative_cleaned)

        base_str = str(self.without_parameters)
        base_http = base_str.replace(TITAN_PREFIX, "https://", 1)

        relative_http = relative_cleaned
        if relative_cleaned.startswith(TITAN_PREFIX):
            relative_http = "https://" + relative_cleaned.removeprefix(TITAN_PREFIX)

        try:
            resolved_http = urljoin(base_http, relative_http)
            resolved_titan = resolved_http.replace("https://", TITAN_PREFIX, 1)
            return self.__class__(resolved_titan)
        except Exception as error:
            raise URIError(
                f"Failed to resolve relative URI '{relative_uri}' against base '{base_str}': {error}"
            ) from error

    def to_gemini(self) -> GeminiURI:
        """Convert this TitanURI into a GeminiURI, stripping Titan parameters.

        Returns:
            A new GeminiURI instance.
        """
        port_str = f":{self._port}" if self._port != GEMINI_DEFAULT_PORT else ""
        query_str = f"?{self._query}" if self._query else ""
        uri_str = f"{GEMINI_PREFIX}{self._host}{port_str}{self._path}{query_str}"
        return GeminiURI(uri_str)

    def __str__(self) -> str:
        """Return the string representation of the URI."""
        param_parts: list[str] = []
        for k, v in self._parameters.items():
            if v is None:
                param_parts.append(k)
            else:
                param_parts.append(f"{k}={v}")

        params_str = f";{';'.join(param_parts)}" if param_parts else ""
        port_str = f":{self._port}" if self._port != TITAN_DEFAULT_PORT else ""
        query_str = f"?{self._query}" if self._query else ""
        return (
            f"{TITAN_PREFIX}{self._host}{port_str}{self._path}{params_str}{query_str}"
        )

    def __eq__(self, other: object) -> bool:
        if isinstance(other, str):
            try:
                other = TitanURI(other)
            except URIError:
                return False
        if not isinstance(other, TitanURI):
            return NotImplemented
        return (
            self.scheme == other.scheme
            and self.host == other.host
            and self.port == other.port
            and self.path == other.path
            and self.parameters == other.parameters
            and self.query == other.query
        )

    def __hash__(self) -> int:
        """Return the hash value of the URI."""
        params_tuple = tuple(sorted(self._parameters.items()))
        return hash(
            (
                self._scheme,
                self._host,
                self._port,
                self._path,
                params_tuple,
                self._query,
            )
        )


### uri.py ends here
