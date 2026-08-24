"""Response class for Gemini protocol requests."""

from __future__ import annotations

##############################################################################
# Python imports.
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Literal, Protocol, Self

##############################################################################
# Local imports.
from .certs import ServerCertificate
from .exceptions import ConnectionError, ProtocolError
from .status import StatusCode
from .trust import get_cert_fingerprint
from .uri import GeminiURI

##############################################################################
type VerificationMethod = Literal["ca", "tofu", "off"]
"""Type alias for server certificate verification method."""


##############################################################################
class ReaderProtocol(Protocol):
    """Protocol for async reader streams."""

    async def read(self, size: int = -1) -> bytes: ...


##############################################################################
class Response:
    """Represents a response from a Gemini server."""

    def __init__(
        self,
        status: StatusCode,
        meta: str,
        reader: ReaderProtocol | None = None,
        uri: GeminiURI | None = None,
        history: list[Response] | None = None,
        requested_uri: GeminiURI | None = None,
        client_cert_path: Path | None = None,
        server_cert_der: bytes | None = None,
        verification_method: VerificationMethod | None = None,
    ) -> None:
        """Initialise the Response object.

        Args:
            status: The Gemini status code.
            meta: The extra metadata line.
            reader: The stream reader for reading the response body.
            uri: The Gemini URI of the response.
            history: A history of response objects from any redirections.
            requested_uri: The originally requested Gemini URI.
            client_cert_path: The path to the client certificate used for the connection.
            server_cert_der: The raw DER-encoded server TLS certificate, or None.
            verification_method: The method used to verify the server TLS certificate, or None.
        """
        self._status = status
        """The Gemini status code of the response."""
        self._meta = meta
        """The meta/header line of the response."""
        self._reader = reader
        """The stream reader for the response body."""
        self._uri = uri
        """The Gemini URI of the response, or None if not set."""
        self._history = list(history) if history is not None else []
        """The history of response objects from any redirections."""
        self._requested_uri = requested_uri
        """The originally requested Gemini URI, or None if not set."""
        self._client_cert_path = client_cert_path
        """The path to the client certificate used for the connection, or None."""
        self._server_cert_der = server_cert_der
        """The raw DER-encoded server TLS certificate, or None if unavailable."""
        self._server_cert: ServerCertificate | None = None
        """The parsed server TLS certificate information, or None if unavailable."""
        self._verification_method = verification_method
        """The method used to verify the server TLS certificate, or None."""
        self._body: bytes | None = None
        """The cached response body bytes, or None if not read yet."""

    @property
    def status(self) -> StatusCode:
        """The response status code."""
        return self._status

    @property
    def uri(self) -> GeminiURI | None:
        """The Gemini URI associated with the response, or None if not set."""
        return self._uri

    @property
    def history(self) -> list[Response]:
        """The history of response objects from any redirections, ordered from oldest to newest."""
        return self._history

    @property
    def requested_uri(self) -> GeminiURI | None:
        """The originally requested Gemini URI, or None if not set."""
        return self._requested_uri

    @property
    def client_cert_path(self) -> Path | None:
        """The path to the client certificate used for the connection, or None."""
        return self._client_cert_path

    @property
    def client_cert_used(self) -> bool:
        """Whether a client certificate was used for the connection."""
        return self._client_cert_path is not None

    @property
    def server_cert_der(self) -> bytes | None:
        """The raw DER-encoded server TLS certificate, or None if unavailable."""
        return self._server_cert_der

    @property
    def server_cert(self) -> ServerCertificate | None:
        """The parsed server TLS certificate information, or None if unavailable."""
        if self._server_cert is None and self._server_cert_der is not None:
            self._server_cert = ServerCertificate.from_der(self._server_cert_der)
        return self._server_cert

    @property
    def server_cert_fingerprint(self) -> str | None:
        """The SHA-256 fingerprint of the server certificate, or None if unavailable."""
        if self._server_cert_der is None:
            return None
        return get_cert_fingerprint(self._server_cert_der)

    @property
    def verification_method(self) -> VerificationMethod | None:
        """The method used to verify the server TLS certificate, or None."""
        return self._verification_method

    @property
    def meta(self) -> str:
        """The extra info/meta string from the response line.

        For status 20, this is the MIME type.
        For other status codes, it contains error messages, instructions, or redirect URIs.
        """
        return self._meta

    @property
    def mime_type(self) -> str:
        """The raw MIME type of the response.

        Only relevant for 2x SUCCESS status codes. Defaults to 'text/gemini; charset=utf-8'.
        """
        if not self._status.is_success:
            return ""
        return (
            self._meta.strip() if self._meta.strip() else "text/gemini; charset=utf-8"
        )

    @property
    def content_type(self) -> str:
        """The base content type (e.g., 'text/gemini' or 'text/plain')."""
        return self.mime_type.split(";")[0].strip().lower()

    @property
    def charset(self) -> str:
        """The charset parameter from the MIME type, defaulting to 'utf-8'."""
        mime = self.mime_type
        for part in mime.split(";")[1:]:
            part = part.strip()
            if part.lower().startswith("charset="):
                return part.split("=", 1)[1].strip().lower()
        return "utf-8"

    async def read(self) -> bytes:
        """Read and return the entire response body.

        Returns:
            The raw response body bytes.

        Raises:
            ConnectionError: If the server connection drops during reading.
        """
        if self._body is not None:
            return self._body

        if self._reader is None:
            self._body = b""
            return self._body

        try:
            self._body = await self._reader.read()
            return self._body
        except Exception as error:
            raise ConnectionError(f"Error reading response body: {error}") from error

    async def text(self, encoding: str | None = None) -> str:
        """Read and return the entire response body as a decoded string.

        Args:
            encoding: The text encoding to use. If None, uses the charset from the response MIME type.

        Returns:
            The decoded response body text.

        Raises:
            ProtocolError: If the response body cannot be decoded using the specified encoding.
        """
        body_bytes = await self.read()
        resolved_encoding = encoding if encoding is not None else self.charset
        try:
            return body_bytes.decode(resolved_encoding)
        except UnicodeDecodeError as error:
            raise ProtocolError(
                f"Failed to decode response body with encoding '{resolved_encoding}': {error}"
            ) from error

    async def iter_chunks(self, chunk_size: int = 4096) -> AsyncIterator[bytes]:
        """Iterate over the response body in chunks as they arrive.

        Args:
            chunk_size: The maximum size of each chunk.

        Yields:
            Bytes chunks from the response body.

        Raises:
            ConnectionError: If the server connection drops during reading.
        """
        if self._body is not None:
            for offset in range(0, len(self._body), chunk_size):
                yield self._body[offset : offset + chunk_size]
            return

        if self._reader is None:
            return

        try:
            while True:
                chunk = await self._reader.read(chunk_size)
                if not chunk:
                    break
                yield chunk
        except Exception as error:
            raise ConnectionError(
                f"Error reading response body chunk: {error}"
            ) from error

    async def close(self) -> None:
        """Close the underlying connection if it is still open."""
        if self._reader is not None:
            close_method = getattr(self._reader, "close", None)
            if close_method is not None:
                await close_method()

    async def __aenter__(self) -> Self:
        """Enter the async context manager."""
        return self

    async def __aexit__(
        self,
        exception_type: type[BaseException] | None,
        exception_value: BaseException | None,
        exception_traceback: object,
    ) -> None:
        """Exit the async context manager and close the connection."""
        await self.close()


### response.py ends here
