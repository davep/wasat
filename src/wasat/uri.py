"""Gemini URI representation and parsing."""

##############################################################################
# Future imports.
from __future__ import annotations

##############################################################################
# Python imports.
from typing import Final, Self
from urllib.parse import (
    quote,
    urljoin,
    urlparse,
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
"""The default URL scheme for the Gemini protocol."""
GEMINI_PREFIX: Final[str] = f"{GEMINI_SCHEME}://"
"""The standard prefix for Gemini URIs."""
GEMINI_DEFAULT_PORT: Final[int] = 1965
"""The default network port for the Gemini protocol."""


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
class GeminiURI:
    """Represents a validated Gemini protocol URI."""

    MAXIMUM_LENGTH: Final[int] = 1024
    """The maximum length of a Gemini URI string."""

    def __init__(self, uri: str | GeminiURI) -> None:
        """Initialise and validate a Gemini URI.

        Args:
            uri: The raw URI string or an existing GeminiURI to clone.

        Raises:
            URIError: If the URI is empty, the scheme is missing or is not 'gemini',
                the host is missing or invalid, or if parsing of the URI fails.
        """

        self._scheme: str
        """The scheme portion of the URI (always 'gemini')."""
        self._host: str
        """The hostname portion of the URI."""
        self._port: int
        """The port number of the URI, defaulting to 1965."""
        self._path: str
        """The path portion of the URI."""
        self._query: str | None
        """The query string portion of the URI, or None."""

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
            parsed = urlparse(to_parse)
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
        except Exception as e:
            raise URIError(f"Failed to parse URI: {e}") from e

    _KNOWN_SCHEMES: Final[set[str]] = set(
        scheme
        for scheme in (
            GEMINI_SCHEME,
            *uses_netloc,
            *uses_params,
            *uses_relative,
            *uses_query,
            *uses_fragment,
        )
        if scheme
    )
    """Set of known URI schemes for validation."""

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
            not (scheme := urlparse(uri).scheme) or scheme not in cls._KNOWN_SCHEMES
        ):
            uri = f"{GEMINI_PREFIX}{uri}"
        return cls(uri)

    @property
    def scheme(self) -> str:
        """The URI scheme (always 'gemini')."""
        return self._scheme

    @property
    def host(self) -> str:
        """The target hostname."""
        return self._host

    @property
    def port(self) -> int:
        """The target port (defaults to `GEMINI_DEFAULT_PORT`)."""
        return self._port

    @property
    def path(self) -> str:
        """The resource path (defaults to '/')."""
        return self._path

    @property
    def query(self) -> str | None:
        """The query string or None."""
        return self._query

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
            URIError: If the resulting URI is invalid (e.g., if the replaced host or
                port is invalid).
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

    def resolve(self, relative_uri: str) -> Self:
        """Resolve a relative URI string against this URI as a base.

        Args:
            relative_uri: The relative or absolute target URI string.

        Returns:
            A new GeminiURI representing the resolved target.

        Raises:
            URIError: If the resolved target URI is invalid, or if the relative URI
                cannot be parsed or resolved against the base URI.
        """
        base_str = str(self)
        base_http = base_str.replace(GEMINI_PREFIX, "https://", 1)

        relative_cleaned = _normalise_scheme(relative_uri)
        relative_http = relative_cleaned
        if relative_cleaned.startswith(GEMINI_PREFIX):
            relative_http = "https://" + relative_cleaned.removeprefix(GEMINI_PREFIX)

        try:
            resolved_http = urljoin(base_http, relative_http)
            resolved_gemini = resolved_http.replace("https://", GEMINI_PREFIX, 1)
            return self.__class__(resolved_gemini)
        except Exception as e:
            raise URIError(
                f"Failed to resolve relative URI '{relative_uri}' against base '{base_str}': {e}"
            ) from e

    @property
    def bytes_left(self) -> int:
        """The number of left left before reaching the maximum URI length."""
        return max(0, self.MAXIMUM_LENGTH - len(self))

    def __str__(self) -> str:
        """Return the string representation of the URI."""
        port_str = f":{self._port}" if self._port != GEMINI_DEFAULT_PORT else ""
        query_str = f"?{self._query}" if self._query else ""
        return f"{GEMINI_PREFIX}{self._host}{port_str}{self._path}{query_str}"

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}('{self}')"

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

    def __len__(self) -> int:
        """Return the length of the string representation of the URI."""
        return len(str(self))


### uri.py ends here
