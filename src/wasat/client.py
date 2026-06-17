"""Gemini Protocol async client implementation."""

import asyncio
import contextlib
import os
import pathlib
import ssl
import sys
from collections.abc import Callable, Coroutine
from typing import Final, Literal

from .exceptions import (
    ConnectionError,
    ProtocolError,
    RedirectError,
    SecurityError,
    URIError,
)
from .response import Response
from .status import StatusCode
from .trust import FileTrustStore, TrustStore, get_cert_fingerprint
from .uri import GeminiURI

type NewCertCallback = Callable[[str, int, str], Coroutine[None, None, bool]]


_DEFAULT_STORE_DIR: Final[str] = "wasat"
_DEFAULT_STORE_FILE: Final[str] = "known_hosts"


def _get_default_trust_store_path() -> pathlib.Path:
    """Get the default trust store filepath based on the operating system's behaviour.

    Returns:
        The default pathlib.Path to the known hosts store.
    """
    if sys.platform == "win32":
        appdata = os.environ.get("APPDATA")
        base_dir = (
            pathlib.Path(appdata)
            if appdata
            else pathlib.Path.home() / "AppData" / "Roaming"
        )
    else:
        base_dir = pathlib.Path.home() / ".config"

    return base_dir / _DEFAULT_STORE_DIR / _DEFAULT_STORE_FILE


class WrappedStreamReader:
    """Wraps StreamReader to ensure the StreamWriter is closed upon reaching EOF or on error."""

    def __init__(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Initialise the wrapper.

        Args:
            reader: The stream reader to wrap.
            writer: The stream writer to close on EOF or error.
        """
        self._reader = reader
        self._writer = writer
        self._closed = False

    async def read(self, n: int = -1) -> bytes:
        """Read data from the stream, closing the connection at EOF.

        Args:
            n: Number of bytes to read, or -1 to read until EOF.

        Returns:
            The read bytes.

        Raises:
            Exception: Any exception raised by the underlying reader.
        """
        try:
            chunk = await self._reader.read(n)
            if not chunk or n == -1:
                await self.close()
            return chunk
        except Exception:
            await self.close()
            raise

    async def close(self) -> None:
        """Close the writer transport."""
        if not self._closed:
            self._closed = True
            self._writer.close()
            with contextlib.suppress(Exception):
                await self._writer.wait_closed()


class Client:
    """Asynchronous Gemini Protocol Client."""

    def __init__(
        self,
        *,
        verify_mode: Literal["ca", "tofu", "off"] = "ca",
        trust_store: TrustStore | None = None,
        trust_store_path: str | pathlib.Path | None = None,
        client_cert: str | pathlib.Path | None = None,
        client_key: str | pathlib.Path | None = None,
        on_new_certificate: NewCertCallback | None = None,
        follow_redirects: bool = True,
        max_redirects: int = 5,
        connect_timeout: float = 10.0,
        read_timeout: float = 30.0,
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        """Initialise the Gemini Client.

        Args:
            verify_mode: The certificate verification mode:
                - 'ca': Trust certificates signed by system CAs.
                - 'tofu': Trust-On-First-Use validation.
                - 'off': Disable certificate verification (insecure).
            trust_store: Custom TrustStore instance for TOFU mode.
            trust_store_path: Filepath for the default FileTrustStore in TOFU mode.
            client_cert: Path to client TLS certificate (for client auth).
            client_key: Path to client TLS private key (optional if in cert file).
            on_new_certificate: Async callback called when a new certificate is
                encountered in TOFU mode. Must return True to accept, False to reject.
            follow_redirects: If True, automatically follow redirects.
            max_redirects: Maximum number of redirects to follow.
            connect_timeout: Timeout in seconds for establishing a connection.
            read_timeout: Timeout in seconds for reading the response line.
            ssl_context: Pre-configured ssl.SSLContext. Overrides verify_mode/cert config.
        """
        self._verify_mode = verify_mode
        self._trust_store = trust_store
        self._client_cert = (
            pathlib.Path(client_cert) if client_cert is not None else None
        )
        self._client_key = pathlib.Path(client_key) if client_key is not None else None
        self._on_new_certificate = on_new_certificate
        self._follow_redirects = follow_redirects
        self._max_redirects = max_redirects
        self._connect_timeout = connect_timeout
        self._read_timeout = read_timeout
        self._ssl_context = ssl_context

        # Set up default trust store for TOFU if none is specified
        if self._verify_mode == "tofu" and self._trust_store is None:
            self._trust_store = FileTrustStore(
                trust_store_path or _get_default_trust_store_path()
            )

        # Cache for permanent redirects (status 31)
        self._permanent_redirects: dict[GeminiURI, GeminiURI] = {}

    def _create_ssl_context(self) -> ssl.SSLContext:
        """Create and configure the SSLContext based on verification settings.

        Returns:
            A configured ssl.SSLContext instance.
        """
        # TLS 1.3/1.2 recommended by Gemini Protocol
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2

        if self._verify_mode == "ca":
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            context.load_default_certs()
        elif self._verify_mode in ("tofu", "off"):
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

        if self._client_cert:
            context.load_cert_chain(
                certfile=self._client_cert,
                keyfile=self._client_key,
            )

        return context

    async def request(self, uri: str | GeminiURI) -> Response:
        """Perform a Gemini request and return the response.

        Automatically handles redirection if configured.

        Args:
            uri: The target URI as a string or GeminiURI object.

        Returns:
            The final Gemini Response object.

        Raises:
            URIError: If the URI is invalid.
            ConnectionError: If network connection fails or times out.
            SecurityError: If TLS/certificate check fails.
            ProtocolError: If the server response violates the Gemini protocol.
            RedirectError: If redirect limits are exceeded or loops are detected.
        """
        if isinstance(uri, str):
            uri = GeminiURI(uri)

        # Resolve permanent redirects cache first
        seen_redirects = {uri}
        while uri in self._permanent_redirects:
            uri = self._permanent_redirects[uri]
            if uri in seen_redirects:
                raise RedirectError(
                    f"Circular permanent redirect cache loop detected for {uri}"
                )
            seen_redirects.add(uri)

        visited = {uri}
        response = await self._do_request(uri)

        while response.status.is_redirect and self._follow_redirects:
            if len(visited) > self._max_redirects:
                # Ensure we close the current response's connection
                await response.close()
                raise RedirectError(
                    f"Maximum redirect limit of {self._max_redirects} exceeded"
                )

            redirect_str = response.meta.strip()
            if not redirect_str:
                await response.close()
                raise ProtocolError(
                    "Redirect status received, but redirect URI is empty"
                )

            try:
                new_uri = uri.resolve(redirect_str)
            except URIError as e:
                await response.close()
                raise RedirectError(
                    f"Failed to resolve redirect URI '{redirect_str}': {e}"
                ) from e

            if new_uri in visited:
                await response.close()
                raise RedirectError(f"Circular redirect detected: {new_uri}")

            # If it's a permanent redirect, cache it
            if response.status == StatusCode.PERMANENT_REDIRECT:
                self._permanent_redirects[uri] = new_uri

            visited.add(new_uri)
            uri = new_uri

            # Close previous response before making the next request
            await response.close()
            response = await self._do_request(uri)

        return response

    async def _do_request(self, uri: GeminiURI) -> Response:
        """Execute a single Gemini request.

        Args:
            uri: The target GeminiURI.

        Returns:
            The Gemini Response object.

        Raises:
            ConnectionError: On connection/network failure.
            SecurityError: On certificate validation failure.
            ProtocolError: On protocol format violations.
        """
        ssl_context = (
            self._ssl_context
            if self._ssl_context is not None
            else self._create_ssl_context()
        )

        try:
            async with asyncio.timeout(self._connect_timeout):
                reader, writer = await asyncio.open_connection(
                    host=uri.host,
                    port=uri.port,
                    ssl=ssl_context,
                    server_hostname=uri.host if ssl_context.check_hostname else None,
                )
        except TimeoutError as e:
            raise ConnectionError(
                f"Connection to {uri.host}:{uri.port} timed out"
            ) from e
        except ssl.SSLError as e:
            raise SecurityError(f"TLS handshake failed: {e}") from e
        except Exception as e:
            raise ConnectionError(
                f"Failed to connect to {uri.host}:{uri.port}: {e}"
            ) from e

        try:
            # Custom validation for TOFU
            if self._verify_mode == "tofu":
                transport = writer.transport
                ssl_object = transport.get_extra_info("ssl_object")
                if ssl_object is None:
                    raise ConnectionError("TLS handshake not completed")

                cert_der = ssl_object.getpeercert(binary_form=True)
                if not cert_der:
                    raise SecurityError("Server did not present a TLS certificate")

                assert self._trust_store is not None
                is_trusted = await self._trust_store.verify(
                    uri.host, uri.port, cert_der
                )
                if not is_trusted:
                    stored_fingerprint = await self._trust_store.get_fingerprint(
                        uri.host, uri.port
                    )
                    current_fingerprint = get_cert_fingerprint(cert_der)
                    if stored_fingerprint is not None:
                        raise SecurityError(
                            f"Verification failed: certificate fingerprint mismatch for {uri.host}:{uri.port}. "
                            f"Expected: sha256:{stored_fingerprint}, Received: sha256:{current_fingerprint}."
                        )
                    else:
                        accept = True
                        if self._on_new_certificate:
                            accept = await self._on_new_certificate(
                                uri.host, uri.port, current_fingerprint
                            )
                        if accept:
                            await self._trust_store.save(uri.host, uri.port, cert_der)
                        else:
                            raise SecurityError(
                                f"Certificate rejected for {uri.host}:{uri.port} by callback."
                            )

            # Send request line
            request_line = f"{uri}\r\n".encode()
            writer.write(request_line)
            await writer.drain()

            # Read response line
            async with asyncio.timeout(self._read_timeout):
                try:
                    response_line_bytes = await reader.readuntil(b"\r\n")
                except asyncio.LimitOverrunError as e:
                    raise ProtocolError(
                        "Response line exceeds maximum allowed limit"
                    ) from e
                except (asyncio.IncompleteReadError, ConnectionResetError) as e:
                    raise ConnectionError(
                        "Connection closed by server before sending response"
                    ) from e

            response_line = response_line_bytes.decode("utf-8").rstrip("\r\n")
            if not response_line:
                raise ProtocolError("Received empty response line")

            parts = response_line.split(" ", 1)
            status_str = parts[0]
            if len(status_str) != 2 or not status_str.isdigit():
                raise ProtocolError(f"Invalid status code format: '{status_str}'")

            status_value = int(status_str)
            try:
                status_code = StatusCode.from_int(status_value)
            except ValueError as e:
                raise ProtocolError(f"Invalid status code: '{status_str}': {e}") from e
            meta = parts[1] if len(parts) > 1 else ""

            if status_code.is_success:
                wrapped_reader = WrappedStreamReader(reader, writer)
                return Response(status_code, meta, wrapped_reader)
            else:
                writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()
                return Response(status_code, meta, None)

        except Exception:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
            raise


### client.py ends here
