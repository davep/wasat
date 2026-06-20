"""Gemini Protocol async client implementation."""

##############################################################################
# Python imports.
import asyncio
import os
import ssl
import sys
from collections.abc import Callable, Coroutine
from contextlib import suppress
from pathlib import Path
from typing import Final, Literal

##############################################################################
# Local imports.
from .certs import (
    ClientCertCallback,
    ClientCertificateStore,
    FileClientCertificateStore,
)
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

##############################################################################
type NewCertCallback = Callable[[str, int, str], Coroutine[None, None, bool]]
"""Async callback function signature for verifying a new certificate."""

##############################################################################
_DEFAULT_STORE_DIR: Final[str] = "wasat"
"""The default directory name for storing known hosts."""
_DEFAULT_STORE_FILE: Final[str] = "known_hosts"
"""The default filename for storing known hosts."""
_DEFAULT_CERTS_DIR: Final[str] = "certs"
"""The default subdirectory name for storing client certificates."""


##############################################################################
def _get_default_base_dir() -> Path:
    """Get the default configuration base directory based on the operating system's behaviour.

    Returns:
        The default config base Path.
    """
    if sys.platform == "win32":
        appdata = os.environ.get("APPDATA")
        base = Path(appdata) if appdata else Path.home() / "AppData" / "Roaming"
    else:
        base = Path.home() / ".config"
    return base / _DEFAULT_STORE_DIR


##############################################################################
def _get_default_trust_store_path() -> Path:
    """Get the default trust store filepath based on the operating system's behaviour.

    Returns:
        The default Path to the known hosts store.
    """
    return _get_default_base_dir() / _DEFAULT_STORE_FILE


##############################################################################
def _get_default_certs_store_path() -> Path:
    """Get the default client certificates store directory filepath.

    Returns:
        The default Path to the client certificates store.
    """
    return _get_default_base_dir() / _DEFAULT_CERTS_DIR


##############################################################################
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
        """The wrapped async stream reader."""
        self._writer = writer
        """The wrapped async stream writer."""
        self._closed = False
        """Flag indicating whether the stream connection has been closed."""

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
            with suppress(Exception):
                await self._writer.wait_closed()


##############################################################################
class Client:
    """Asynchronous Gemini Protocol Client."""

    def __init__(
        self,
        *,
        verify_mode: Literal["ca", "tofu", "off"] = "ca",
        trust_store: TrustStore | None = None,
        trust_store_path: str | Path | None = None,
        client_cert: str | Path | None = None,
        client_key: str | Path | None = None,
        client_cert_store: ClientCertificateStore | None = None,
        client_cert_store_path: str | Path | None = None,
        on_client_certificate_required: ClientCertCallback | None = None,
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
            client_cert_store: Custom ClientCertificateStore instance.
            client_cert_store_path: Directory path for the default FileClientCertificateStore.
            on_client_certificate_required: Async callback invoked when client certificate
                is required (status code 60). Returns 'transient', 'persistent' or 'ignore'.
            on_new_certificate: Async callback called when a new certificate is
                encountered in TOFU mode. Must return True to accept, False to reject.
            follow_redirects: If True, automatically follow redirects.
            max_redirects: Maximum number of redirects to follow.
            connect_timeout: Timeout in seconds for establishing a connection.
            read_timeout: Timeout in seconds for reading the response line.
            ssl_context: Pre-configured ssl.SSLContext. Overrides verify_mode/cert config.
        """
        self._verify_mode = verify_mode
        """The verification mode: 'ca', 'tofu', or 'off'."""
        self._trust_store = trust_store
        """The trust store instance for TOFU verification."""
        self._client_cert = Path(client_cert) if client_cert is not None else None
        """The path to the client TLS certificate."""
        self._client_key = Path(client_key) if client_key is not None else None
        """The path to the client TLS private key."""
        self._client_cert_store: ClientCertificateStore = (
            client_cert_store
            if client_cert_store is not None
            else FileClientCertificateStore(
                client_cert_store_path or _get_default_certs_store_path()
            )
        )
        """The client certificate store instance."""
        self._on_client_certificate_required = on_client_certificate_required
        """Callback invoked when a client certificate is required by the server."""
        self._on_new_certificate = on_new_certificate
        """The async callback invoked when a new certificate is encountered."""
        self._follow_redirects = follow_redirects
        """Flag indicating whether to automatically follow redirects."""
        self._max_redirects = max_redirects
        """The maximum number of redirects to follow."""
        self._connect_timeout = connect_timeout
        """The connection establishment timeout in seconds."""
        self._read_timeout = read_timeout
        """The response line read timeout in seconds."""
        self._ssl_context = ssl_context
        """A pre-configured SSL context to override default TLS configuration."""

        # Set up default trust store for TOFU if none is specified
        if self._verify_mode == "tofu" and self._trust_store is None:
            self._trust_store = FileTrustStore(
                trust_store_path or _get_default_trust_store_path()
            )

        # Cache for permanent redirects (status 31)
        self._permanent_redirects: dict[GeminiURI, GeminiURI] = {}
        """Cache mapping requested URIs to their permanent redirect targets."""

    def _create_ssl_context(
        self,
        client_cert: Path | None = None,
        client_key: Path | None = None,
    ) -> ssl.SSLContext:
        """Create and configure the SSLContext based on verification settings.

        Args:
            client_cert: Optional path to the client certificate PEM file.
            client_key: Optional path to the client private key PEM file.

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

        cert_to_load = client_cert or self._client_cert
        key_to_load = client_key or self._client_key

        if cert_to_load:
            context.load_cert_chain(
                certfile=cert_to_load,
                keyfile=key_to_load,
            )

        return context

    async def _send_request_line(
        self, uri: GeminiURI, writer: asyncio.StreamWriter
    ) -> None:
        """Send the Gemini request line to the server.

        Args:
            uri: The target GeminiURI.
            writer: The StreamWriter representing the established connection.
        """
        writer.write(f"{uri}\r\n".encode())
        await writer.drain()

    async def _read_response_line(
        self, reader: asyncio.StreamReader
    ) -> tuple[StatusCode, str]:
        """Read and parse the response line from the server.

        Args:
            reader: The StreamReader representing the established connection.

        Returns:
            A tuple of (StatusCode, meta string).

        Raises:
            ConnectionError: If the connection is closed before reading the response.
            ProtocolError: If the response line format is invalid.
        """
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

        return status_code, meta

    async def _connect(
        self, uri: GeminiURI, ssl_context: ssl.SSLContext
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Establish connection to the Gemini server.

        Args:
            uri: The target GeminiURI.
            ssl_context: The SSLContext to use for the TLS handshake.

        Returns:
            A tuple of (StreamReader, StreamWriter).

        Raises:
            ConnectionError: If the connection attempt times out or fails.
            SecurityError: If the TLS handshake fails.
        """
        try:
            async with asyncio.timeout(self._connect_timeout):
                return await asyncio.open_connection(
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

    async def _verify_tofu(self, uri: GeminiURI, writer: asyncio.StreamWriter) -> None:
        """Verify the peer certificate using Trust-On-First-Use (TOFU).

        Args:
            uri: The target GeminiURI.
            writer: The StreamWriter representing the established connection.

        Raises:
            ConnectionError: If the TLS handshake was not completed.
            SecurityError: If the certificate is missing, mismatched, or rejected.
        """
        transport = writer.transport
        ssl_object = transport.get_extra_info("ssl_object")
        if ssl_object is None:
            raise ConnectionError("TLS handshake not completed")

        cert_der = ssl_object.getpeercert(binary_form=True)
        if not cert_der:
            raise SecurityError("Server did not present a TLS certificate")

        assert self._trust_store is not None
        is_trusted = await self._trust_store.verify(uri.host, uri.port, cert_der)
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

    @property
    def client_cert_store(self) -> ClientCertificateStore:
        """The client certificate store used by this client.

        Returns:
            The client certificate store instance.
        """
        return self._client_cert_store

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
        ssl_context = self._ssl_context
        if ssl_context is None:
            cert_path = self._client_cert
            key_path = self._client_key

            if not cert_path and self._client_cert_store is not None:
                creds = await self._client_cert_store.get_credentials(uri)
                if creds is not None:
                    cert_path, key_path = creds

            ssl_context = self._create_ssl_context(
                client_cert=cert_path,
                client_key=key_path,
            )

        reader, writer = await self._connect(uri, ssl_context)

        try:
            if self._verify_mode == "tofu":
                await self._verify_tofu(uri, writer)

            await self._send_request_line(uri, writer)
            status_code, meta = await self._read_response_line(reader)

            if status_code.is_success:
                wrapped_reader = WrappedStreamReader(reader, writer)
                return Response(status_code, meta, wrapped_reader)
            else:
                writer.close()
                with suppress(Exception):
                    await writer.wait_closed()

                response = Response(status_code, meta, None)

                # Handle client certificate required status
                if (
                    response.status == StatusCode.CLIENT_CERTIFICATE_REQUIRED
                    and self._on_client_certificate_required is not None
                    and self._client_cert_store is not None
                ):
                    # Check if a certificate was already presented
                    has_store_cert = (
                        await self._client_cert_store.get_credentials(uri) is not None
                    )
                    if not has_store_cert and not self._client_cert:
                        action = await self._on_client_certificate_required(
                            uri, self._client_cert_store
                        )
                        if action in ("transient", "persistent"):
                            await self._client_cert_store.create_credentials(
                                uri,
                                transient=(action == "transient"),
                            )
                            # Retry the request
                            return await self._do_request(uri)

                return response

        except Exception:
            writer.close()
            with suppress(Exception):
                await writer.wait_closed()
            raise

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

    async def close(self) -> None:
        """Close the client and clean up resources, including the client certificate store."""
        if self._client_cert_store is not None:
            await self._client_cert_store.close()

    async def __aenter__(self) -> "Client":
        """Enter the async context manager.

        Returns:
            The Client instance.
        """
        return self

    async def __aexit__(
        self, exc_type: object, exc_val: object, exc_tb: object
    ) -> None:
        """Exit the async context manager, closing resources."""
        await self.close()


### client.py ends here
