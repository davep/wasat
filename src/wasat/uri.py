"""Gemini URI representation and parsing."""

import urllib.parse
from typing import Final, Self

from .exceptions import URIError

GEMINI_SCHEME: Final[str] = "gemini"
GEMINI_PREFIX: Final[str] = f"{GEMINI_SCHEME}://"
GEMINI_DEFAULT_PORT: Final[int] = 1965


def _normalise_scheme(uri: str) -> str:
    """Normalise the scheme portion of a URI to lowercase."""
    scheme, separator, rest = uri.partition("://")
    return f"{scheme.lower()}{separator}{rest}" if separator else uri


class GeminiURI:
    """Represents a validated Gemini protocol URI."""

    def __init__(self, uri: str | Self) -> None:
        """Initialise and validate a Gemini URI.

        Args:
            uri: The raw URI string or an existing GeminiURI to clone.

        Raises:
            URIError: If the URI is invalid or has an incorrect scheme.
        """
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
            parsed = urllib.parse.urlparse(to_parse)
        except Exception as e:
            raise URIError(f"Failed to parse URI: {e}") from e

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

    def with_query(self, query: str) -> Self:
        """Return a new GeminiURI with the query parameter replaced or set.

        Args:
            query: The new query string (will be URL-encoded).

        Returns:
            A new GeminiURI instance with the updated query.
        """
        encoded_query = urllib.parse.quote(query, safe="~()*!.'")
        port_str = f":{self._port}" if self._port != GEMINI_DEFAULT_PORT else ""
        new_uri_str = (
            f"{GEMINI_PREFIX}{self._host}{port_str}{self._path}?{encoded_query}"
        )
        return self.__class__(new_uri_str)

    def resolve(self, relative_uri: str) -> Self:
        """Resolve a relative URI string against this URI as a base.

        Args:
            relative_uri: The relative or absolute target URI string.

        Returns:
            A new GeminiURI representing the resolved target.

        Raises:
            URIError: If the resolved URI is invalid.
        """
        base_str = str(self)
        base_http = base_str.replace(GEMINI_PREFIX, "https://", 1)

        relative_cleaned = _normalise_scheme(relative_uri)
        relative_http = relative_cleaned
        if relative_cleaned.startswith(GEMINI_PREFIX):
            relative_http = "https://" + relative_cleaned.removeprefix(GEMINI_PREFIX)

        try:
            resolved_http = urllib.parse.urljoin(base_http, relative_http)
            resolved_gemini = resolved_http.replace("https://", GEMINI_PREFIX, 1)
            return self.__class__(resolved_gemini)
        except Exception as e:
            raise URIError(
                f"Failed to resolve relative URI '{relative_uri}' against base '{base_str}': {e}"
            ) from e

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


### uri.py ends here
