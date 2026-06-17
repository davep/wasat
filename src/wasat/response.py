"""Response class for Gemini protocol requests."""

from collections.abc import AsyncIterator
from typing import Protocol, Self

from .exceptions import ConnectionError, ProtocolError
from .status import StatusCode


class ReaderProtocol(Protocol):
    """Protocol for async reader streams."""

    async def read(self, n: int = -1) -> bytes: ...


class Response:
    """Represents a response from a Gemini server."""

    def __init__(
        self,
        status: StatusCode,
        meta: str,
        reader: ReaderProtocol | None = None,
    ) -> None:
        """Initialise the Response object.

        Args:
            status: The Gemini status code.
            meta: The extra metadata line.
            reader: The stream reader for reading the response body.
        """
        self._status = status
        self._meta = meta
        self._reader = reader
        self._body: bytes | None = None

    @property
    def status(self) -> StatusCode:
        """The response status code."""
        return self._status

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
        except Exception as e:
            raise ConnectionError(f"Error reading response body: {e}") from e

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
        enc = encoding if encoding is not None else self.charset
        try:
            return body_bytes.decode(enc)
        except UnicodeDecodeError as e:
            raise ProtocolError(
                f"Failed to decode response body with encoding '{enc}': {e}"
            ) from e

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
            for i in range(0, len(self._body), chunk_size):
                yield self._body[i : i + chunk_size]
            return

        if self._reader is None:
            return

        try:
            while True:
                chunk = await self._reader.read(chunk_size)
                if not chunk:
                    break
                yield chunk
        except Exception as e:
            raise ConnectionError(f"Error reading response body chunk: {e}") from e

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
