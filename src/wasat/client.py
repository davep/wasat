"""Gemini and Titan Protocol async client implementation."""

##############################################################################
# Python imports.
import asyncio
import os
import ssl
import sys
from collections.abc import AsyncIterator, Callable, Coroutine
from contextlib import suppress
from pathlib import Path
from typing import BinaryIO, Final, Literal, Self

from cryptography.hazmat.bindings.openssl.binding import Binding

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
    WasatError,
)
from .response import Response, VerificationMethod
from .status import StatusCode
from .trust import FileTrustStore, TrustStore, get_cert_fingerprint
from .uri import (
    AnyURI,
    GeminiURI,
    TitanURI,
    guess_mime_type,
)

##############################################################################
type NewCertCallback = Callable[[str, int, str], Coroutine[None, None, bool]]
"""Async callback function signature for verifying a new certificate."""

##############################################################################
type VerifyMode = Literal["ca", "tofu", "off", "hybrid"]
"""Type alias for the certificate verification mode."""

##############################################################################
_DEFAULT_STORE_DIR: Final[str] = "wasat"
"""The default directory name for storing known hosts."""
_DEFAULT_STORE_FILE: Final[str] = "known_hosts"
"""The default filename for storing known hosts."""
_DEFAULT_CERTS_DIR: Final[str] = "certs"
"""The default subdirectory name for storing client certificates."""

_openssl_lib = Binding().lib

_UNTRUSTED_CA_VERIFY_CODES: Final[set[int]] = {
    _openssl_lib.X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT,
    _openssl_lib.X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT,
    _openssl_lib.X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN,
    _openssl_lib.X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY,
    _openssl_lib.X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE,
    _openssl_lib.X509_V_ERR_CERT_UNTRUSTED,
}
"""OpenSSL X509 verification codes indicating untrusted root or self-signed certificates."""


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

    async def read(self, size: int = -1) -> bytes:
        """Read data from the stream, closing the connection at EOF.

        Args:
            size: Number of bytes to read, or -1 to read until EOF.

        Returns:
            The read bytes.

        Raises:
            Exception: Any exception raised by the underlying reader.
        """
        try:
            chunk = await self._reader.read(size)
            if not chunk or size == -1:
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
        verify_mode: VerifyMode = "ca",
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
                - 'hybrid': Combine CA validation with TOFU fallback (falls back to TOFU
                    only for untrusted root or self-signed certificates; raises SecurityError
                    for expired certs or hostname mismatches).
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
        """The verification mode: 'ca', 'tofu', 'off', or 'hybrid'."""
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

        # Set up default trust store for TOFU or hybrid if none is specified
        if self._verify_mode in ("tofu", "hybrid") and self._trust_store is None:
            self._trust_store = FileTrustStore(
                trust_store_path or _get_default_trust_store_path()
            )

        # Cache for permanent redirects (status 31)
        self._permanent_redirects: dict[AnyURI, AnyURI] = {}
        """Cache mapping requested URIs to their permanent redirect targets."""

    def _create_ssl_context(
        self,
        client_cert: Path | None = None,
        client_key: Path | None = None,
        verify_mode_override: VerifyMode | None = None,
    ) -> ssl.SSLContext:
        """Create and configure the SSLContext based on verification settings.

        Args:
            client_cert: Optional path to the client certificate PEM file.
            client_key: Optional path to the client private key PEM file.
            verify_mode_override: Optional mode override for SSLContext creation.

        Returns:
            A configured ssl.SSLContext instance.
        """
        # TLS 1.3/1.2 recommended by Gemini Protocol
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2

        mode = verify_mode_override or self._verify_mode

        if mode == "ca":
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            context.load_default_certs()
        elif mode in ("tofu", "off", "hybrid"):
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

    @staticmethod
    def _is_untrusted_root_error(error: SecurityError) -> bool:
        """Check if a SecurityError during CA verification was caused by an untrusted root or self-signed certificate.

        In hybrid verification mode, fallback to TOFU is only performed if CA validation fails
        due to an untrusted root or self-signed certificate. If CA validation fails due to
        certificate expiration, hostname mismatch, or revocation, fallback is denied and the error is raised.

        Args:
            error: The SecurityError raised during CA connection verification.

        Returns:
            True if the error is due to an untrusted root or self-signed certificate, False otherwise.
        """
        cause = error.__cause__
        target: BaseException = cause if cause is not None else error

        if isinstance(cause, ssl.SSLError):
            verify_code = getattr(cause, "verify_code", None)
            if verify_code is not None and isinstance(verify_code, int):
                return verify_code in _UNTRUSTED_CA_VERIFY_CODES

        error_message = str(target).lower()
        invalid_keywords = (
            "expired",
            "hostname",
            "mismatch",
            "not yet valid",
            "revoked",
        )
        if any(keyword in error_message for keyword in invalid_keywords):
            return False

        untrusted_keywords = (
            "self-signed",
            "self signed",
            "unable to get local issuer",
            "unable to get issuer",
            "unable to verify the first certificate",
            "certificate untrusted",
            "untrusted",
        )
        return any(keyword in error_message for keyword in untrusted_keywords)

    async def _send_request_line(
        self, uri: AnyURI, writer: asyncio.StreamWriter
    ) -> None:
        """Send the request line to the server.

        Args:
            uri: The target URI (GeminiURI or TitanURI).
            writer: The StreamWriter representing the established connection.

        Raises:
            ConnectionError: If sending the request line fails due to connection loss.
        """
        try:
            writer.write(f"{uri}\r\n".encode())
            await writer.drain()
        except (OSError, ssl.SSLError) as error:
            raise ConnectionError(f"Failed to send request line: {error}") from error

    async def _send_payload(self, payload: bytes, writer: asyncio.StreamWriter) -> None:
        """Send the payload bytes to the server.

        Args:
            payload: The raw bytes payload to send.
            writer: The StreamWriter representing the established connection.
        """
        if not payload:
            return
        try:
            writer.write(payload)
            await writer.drain()
        except (BrokenPipeError, ConnectionResetError, ssl.SSLEOFError, OSError):
            # The server may have rejected early (e.g. sent 5x or 60 status) and closed
            # the connection. We ignore socket write failures here so that the response
            # line can be read and handled gracefully.
            pass

    async def _send_payload_chunked(
        self,
        payload: bytes,
        writer: asyncio.StreamWriter,
        read_task: asyncio.Task[tuple[StatusCode, str]],
    ) -> None:
        """Stream payload chunks to the server while monitoring the read task.

        Args:
            payload: The raw bytes payload to send.
            writer: The StreamWriter representing the established connection.
            read_task: The background task reading the server response line.
        """
        chunk_size = 64 * 1024
        total_bytes = len(payload)
        for offset in range(0, total_bytes, chunk_size):
            if read_task.done():
                try:
                    status_code, _ = read_task.result()
                    if not status_code.is_success:
                        break
                except Exception:
                    break
            chunk = payload[offset : offset + chunk_size]
            try:
                writer.write(chunk)
                await writer.drain()
            except (BrokenPipeError, ConnectionResetError, ssl.SSLEOFError, OSError):
                break

    async def _send_payload_and_read_response(
        self,
        payload: bytes,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> tuple[StatusCode, str]:
        """Send the payload to the server while concurrently reading the response.

        Titan servers may reject an upload intent early (e.g. if the requested file size
        exceeds internal limits, a token is required, or MIME type is rejected) and close
        or stop reading from the connection. By concurrently reading the response line
        while streaming the payload in chunks, we ensure that an early response is caught
        immediately without stalling on TCP socket write buffers.

        Args:
            payload: The raw bytes payload to upload.
            reader: The StreamReader representing the established connection.
            writer: The StreamWriter representing the established connection.

        Returns:
            A tuple of (StatusCode, meta string).

        Raises:
            ConnectionError: If the connection is closed before reading the response.
            ProtocolError: If the response line format is invalid.
        """
        read_task: asyncio.Task[tuple[StatusCode, str]] = asyncio.create_task(
            self._read_response_line(reader)
        )
        send_task = asyncio.create_task(
            self._send_payload_chunked(payload, writer, read_task)
        )
        try:
            done, pending = await asyncio.wait(
                [read_task, send_task],
                return_when=asyncio.FIRST_COMPLETED,
            )

            if read_task in done:
                try:
                    status_code, meta = read_task.result()
                    if not status_code.is_success:
                        for task in pending:
                            task.cancel()
                            with suppress(asyncio.CancelledError):
                                await task
                        return status_code, meta
                except Exception:
                    for task in pending:
                        task.cancel()
                        with suppress(asyncio.CancelledError):
                            await task
                    return read_task.result()

            if send_task not in done:
                await send_task
            return await read_task
        finally:
            for task in (read_task, send_task):
                if not task.done():
                    task.cancel()
                    with suppress(asyncio.CancelledError, Exception):
                        await task

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
        try:
            async with asyncio.timeout(self._read_timeout):
                try:
                    response_line_bytes = await reader.readuntil(b"\r\n")
                except asyncio.LimitOverrunError as error:
                    raise ProtocolError(
                        "Response line exceeds maximum allowed limit"
                    ) from error
                except (
                    asyncio.IncompleteReadError,
                    OSError,
                    ssl.SSLError,
                ) as error:
                    raise ConnectionError(
                        "Connection closed by server before sending response"
                    ) from error
        except TimeoutError as error:
            raise ConnectionError(
                f"Timed out waiting for response line after {self._read_timeout}s"
            ) from error

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
        except ValueError as error:
            raise ProtocolError(
                f"Invalid status code: '{status_str}': {error}"
            ) from error
        meta = parts[1] if len(parts) > 1 else ""

        return status_code, meta

    async def _connect(
        self, uri: AnyURI, ssl_context: ssl.SSLContext
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Establish connection to the server.

        Args:
            uri: The target URI (GeminiURI or TitanURI).
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
        except TimeoutError as error:
            raise ConnectionError(
                f"Connection to {uri.host}:{uri.port} timed out"
            ) from error
        except ssl.SSLError as error:
            raise SecurityError(f"TLS handshake failed: {error}") from error
        except Exception as error:
            raise ConnectionError(
                f"Failed to connect to {uri.host}:{uri.port}: {error}"
            ) from error

    async def _verify_tofu(self, uri: AnyURI, writer: asyncio.StreamWriter) -> None:
        """Verify the peer certificate using Trust-On-First-Use (TOFU).

        Args:
            uri: The target URI (GeminiURI or TitanURI).
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
    def trust_store(self) -> TrustStore | None:
        """The trust store used by this client for TOFU verification.

        This will be `None` if not in TOFU mode.
        """
        return self._trust_store

    @property
    def client_cert_store(self) -> ClientCertificateStore:
        """The client certificate store used by this client.

        Returns:
            The client certificate store instance.
        """
        return self._client_cert_store

    async def _do_request(
        self,
        uri: AnyURI,
        history: list[Response] | None = None,
        requested_uri: AnyURI | None = None,
        payload: bytes | None = None,
    ) -> Response:
        """Execute a single Gemini or Titan request.

        Args:
            uri: The target URI (GeminiURI or TitanURI).
            history: Optional redirection history list.
            requested_uri: Optional originally requested URI.
            payload: Optional payload bytes to send for Titan upload requests.

        Returns:
            The Response object.

        Raises:
            ConnectionError: On connection/network failure.
            SecurityError: On certificate validation failure.
            ProtocolError: On protocol format violations.
            ValueError: If client certificate generation parameters are invalid.
            OSError: If creating directories or writing client certificate files fails.
            RuntimeError: If saving the updated client certificate store index fails.
        """
        ssl_context = self._ssl_context
        cert_path: Path | None = None
        key_path: Path | None = None
        cert_inherited = False
        if ssl_context is None:
            cert_path = self._client_cert
            key_path = self._client_key

            if not cert_path and self._client_cert_store is not None:
                credentials = await self._client_cert_store.get_credentials(uri)
                if credentials is not None:
                    cert_path, key_path = credentials
                elif history:
                    # Look back in the redirect history for a request on the same host and port
                    # that successfully used a client certificate.
                    for previous_response in reversed(history):
                        if (
                            previous_response.client_cert_used
                            and previous_response.uri is not None
                            and previous_response.uri.host.lower() == uri.host.lower()
                            and previous_response.uri.port == uri.port
                        ):
                            previous_credentials = (
                                await self._client_cert_store.get_credentials(
                                    previous_response.uri
                                )
                            )
                            if previous_credentials is not None:
                                cert_path, key_path = previous_credentials
                                cert_inherited = True
                                break

        verification_method: VerificationMethod | None = None

        if ssl_context is None and self._verify_mode == "hybrid":
            ca_ssl_context = self._create_ssl_context(
                client_cert=cert_path,
                client_key=key_path,
                verify_mode_override="ca",
            )
            try:
                reader, writer = await self._connect(uri, ca_ssl_context)
                verification_method = "ca"
                if self._trust_store is not None:
                    transport = writer.transport
                    ssl_object = transport.get_extra_info("ssl_object")
                    if ssl_object is not None:
                        cert_der = ssl_object.getpeercert(binary_form=True)
                        if cert_der:
                            await self._trust_store.save(uri.host, uri.port, cert_der)
            except SecurityError as error:
                if not self._is_untrusted_root_error(error):
                    raise
                tofu_ssl_context = self._create_ssl_context(
                    client_cert=cert_path,
                    client_key=key_path,
                    verify_mode_override="tofu",
                )
                reader, writer = await self._connect(uri, tofu_ssl_context)
                await self._verify_tofu(uri, writer)
                verification_method = "tofu"
        else:
            if ssl_context is None:
                ssl_context = self._create_ssl_context(
                    client_cert=cert_path,
                    client_key=key_path,
                )
                if self._verify_mode in ("ca", "tofu", "off"):
                    verification_method = self._verify_mode
            else:
                if self._verify_mode == "tofu":
                    verification_method = "tofu"
                elif ssl_context.verify_mode == ssl.CERT_REQUIRED:
                    verification_method = "ca"
                else:
                    verification_method = "off"

            reader, writer = await self._connect(uri, ssl_context)

        try:
            if self._verify_mode == "tofu":
                await self._verify_tofu(uri, writer)

            server_cert_der: bytes | None = None
            if verification_method != "off":
                transport = writer.transport
                ssl_object = transport.get_extra_info("ssl_object")
                if ssl_object is not None:
                    cert_bytes = ssl_object.getpeercert(binary_form=True)
                    if isinstance(cert_bytes, bytes) and cert_bytes:
                        server_cert_der = cert_bytes

            await self._send_request_line(uri, writer)
            if payload is not None and len(payload) > 0:
                status_code, meta = await self._send_payload_and_read_response(
                    payload, reader, writer
                )
            else:
                status_code, meta = await self._read_response_line(reader)

            # If the certificate was inherited from a redirect, and the request succeeded
            # or was redirected successfully, register/re-bind the certificate to this URI.
            if (
                cert_inherited
                and cert_path is not None
                and key_path is not None
                and self._client_cert_store is not None
                and (status_code.is_success or status_code.is_redirect)
            ):
                is_transient = False
                if isinstance(self._client_cert_store, FileClientCertificateStore):
                    temp_dir = self._client_cert_store._temp_dir
                    if temp_dir is not None and cert_path.is_relative_to(temp_dir):
                        is_transient = True
                await self._client_cert_store.register_credentials(
                    uri, cert_path, key_path, transient=is_transient
                )

            if status_code.is_success:
                wrapped_reader = WrappedStreamReader(reader, writer)
                return Response(
                    status_code,
                    meta,
                    wrapped_reader,
                    uri,
                    history=history,
                    requested_uri=requested_uri,
                    client_cert_path=cert_path,
                    client_key_path=key_path,
                    server_cert_der=server_cert_der,
                    verification_method=verification_method,
                )
            else:
                writer.close()
                with suppress(Exception):
                    await writer.wait_closed()

                response = Response(
                    status_code,
                    meta,
                    None,
                    uri,
                    history=history,
                    requested_uri=requested_uri,
                    client_cert_path=cert_path,
                    client_key_path=key_path,
                    server_cert_der=server_cert_der,
                    verification_method=verification_method,
                )

                # Handle client certificate required status
                if (
                    response.status == StatusCode.CLIENT_CERTIFICATE_REQUIRED
                    and self._on_client_certificate_required is not None
                    and self._client_cert_store is not None
                ):
                    # Check if a certificate for the exact scope is already in the store
                    has_exact_cert = (
                        await self._client_cert_store.has_exact_credentials(uri)
                    )
                    if not has_exact_cert and not self._client_cert:
                        action = await self._on_client_certificate_required(
                            uri, self._client_cert_store
                        )
                        if action in ("transient", "persistent"):
                            if not await self._client_cert_store.has_exact_credentials(
                                uri
                            ):
                                await self._client_cert_store.create_credentials(
                                    uri,
                                    transient=(action == "transient"),
                                    common_name=uri.host,
                                )
                            # Retry the request
                            return await self._do_request(
                                uri,
                                history=history,
                                requested_uri=requested_uri,
                                payload=payload,
                            )

                return response

        except WasatError:
            writer.close()
            with suppress(Exception):
                await writer.wait_closed()
            raise
        except (TimeoutError, OSError, ssl.SSLError) as error:
            writer.close()
            with suppress(Exception):
                await writer.wait_closed()
            raise ConnectionError(
                f"Connection failed during request: {error}"
            ) from error
        except Exception:
            writer.close()
            with suppress(Exception):
                await writer.wait_closed()
            raise

    async def request(self, uri: str | AnyURI) -> Response:
        """Perform a Gemini or Titan request and return the response.

        Automatically handles redirection if configured.

        Args:
            uri: The target URI as a string, GeminiURI, or TitanURI object.

        Returns:
            The final Response object.

        Raises:
            URIError: If the URI is invalid.
            ConnectionError: If network connection fails or times out.
            SecurityError: If TLS/certificate check fails.
            ProtocolError: If the server response violates the protocol.
            RedirectError: If redirect limits are exceeded or loops are detected.
            ValueError: If client certificate generation parameters are invalid.
            OSError: If creating directories or writing client certificate files fails.
            RuntimeError: If saving the updated client certificate store index fails.
        """
        requested_uri: AnyURI
        if isinstance(uri, str):
            requested_uri = (
                TitanURI(uri) if uri.startswith("titan://") else GeminiURI(uri)
            )
        elif isinstance(uri, (GeminiURI, TitanURI)):
            requested_uri = uri
        else:
            raise URIError(f"Invalid URI type: {type(uri)}")

        if (
            isinstance(requested_uri, TitanURI)
            and not requested_uri.is_edit
            and requested_uri.size is not None
            and requested_uri.size > 0
        ):
            raise URIError(
                "Titan URI specifies size > 0 but no payload was provided. Use client.upload() instead."
            )

        current_uri: AnyURI = requested_uri

        # Resolve permanent redirects cache first
        seen_redirects = {current_uri}
        while current_uri in self._permanent_redirects:
            current_uri = self._permanent_redirects[current_uri]
            if current_uri in seen_redirects:
                raise RedirectError(
                    f"Circular permanent redirect cache loop detected for {current_uri}"
                )
            seen_redirects.add(current_uri)

        visited = {current_uri}
        history: list[Response] = []
        response = await self._do_request(
            current_uri, history=history, requested_uri=requested_uri
        )

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
                new_uri = current_uri.resolve(redirect_str)
            except URIError as error:
                await response.close()
                raise RedirectError(
                    f"Failed to resolve redirect URI '{redirect_str}': {error}"
                ) from error

            if (
                isinstance(new_uri, TitanURI)
                and new_uri.size is not None
                and new_uri.size > 0
            ):
                await response.close()
                raise RedirectError(
                    f"Redirected from Gemini to Titan URI '{new_uri}' with size > 0, "
                    "but no payload is available. Use client.upload() for Titan uploads."
                )

            if new_uri in visited:
                await response.close()
                raise RedirectError(f"Circular redirect detected: {new_uri}")

            # If it's a permanent redirect, cache it
            if response.status == StatusCode.PERMANENT_REDIRECT:
                self._permanent_redirects[current_uri] = new_uri

            visited.add(new_uri)
            current_uri = new_uri

            # Keep track of previous redirect response objects
            history.append(response)

            # Close previous response before making the next request
            await response.close()
            response = await self._do_request(
                current_uri, history=history, requested_uri=requested_uri
            )

        return response

    async def upload(
        self,
        uri: str | GeminiURI | TitanURI,
        data: bytes | str | Path | AsyncIterator[bytes] | BinaryIO,
        *,
        mime: str | None = None,
        token: str | None = None,
    ) -> Response:
        """Upload data to a Titan endpoint.

        Args:
            uri: The target URI as a string, GeminiURI, or TitanURI.
            data: The content to upload. Can be raw bytes, a UTF-8 string, a Path,
                an async byte iterator, or a file-like stream.
            mime: The MIME type of the payload. If None, it is automatically inferred.
            token: Optional authorization token for the Titan transaction.

        Returns:
            A Response instance representing the server's response.

        Raises:
            URIError: If the URI is invalid or cannot be converted to a Titan URI.
            ConnectionError: If connection establishment fails.
            SecurityError: If TLS or certificate validation fails.
            ProtocolError: If the server response violates the protocol.
            RedirectError: If redirect limits are exceeded or loops are detected.
            TypeError: If the provided data type is unsupported.
        """
        target_uri: TitanURI
        if isinstance(uri, str):
            target_uri = (
                GeminiURI(uri).to_titan()
                if uri.startswith("gemini://")
                else TitanURI.with_default_scheme(uri)
            )
        elif isinstance(uri, GeminiURI):
            target_uri = uri.to_titan()
        elif isinstance(uri, TitanURI):
            target_uri = uri
        else:
            raise URIError(f"Invalid URI type: {type(uri)}")

        payload_bytes: bytes
        detected_mime: str | None = mime

        if isinstance(data, str):
            payload_bytes = data.encode("utf-8")
            if detected_mime is None:
                detected_mime = "text/gemini"
        elif isinstance(data, (bytes, bytearray, memoryview)):
            payload_bytes = bytes(data)
            if detected_mime is None and len(payload_bytes) > 0:
                detected_mime = "application/octet-stream"
        elif isinstance(data, Path):
            payload_bytes = data.read_bytes()
            if detected_mime is None:
                detected_mime = guess_mime_type(data)
        elif hasattr(data, "__aiter__"):
            chunks: list[bytes] = []
            async for chunk in data:
                chunks.append(chunk)
            payload_bytes = b"".join(chunks)
            if detected_mime is None and len(payload_bytes) > 0:
                detected_mime = "application/octet-stream"
        elif hasattr(data, "read"):
            read_result = data.read()
            if isinstance(read_result, str):
                payload_bytes = read_result.encode("utf-8")
                if detected_mime is None:
                    detected_mime = "text/gemini"
            else:
                payload_bytes = bytes(read_result)
                if detected_mime is None and len(payload_bytes) > 0:
                    detected_mime = "application/octet-stream"
        else:
            raise TypeError(f"Unsupported payload data type: {type(data)}")

        size = len(payload_bytes)
        base_target_uri = target_uri.without_parameters
        final_uri = base_target_uri.replace(size=size, mime=detected_mime, token=token)

        current_uri: AnyURI = final_uri
        visited = {current_uri}
        history: list[Response] = []

        response = await self._do_request(
            current_uri,
            history=history,
            requested_uri=final_uri,
            payload=payload_bytes,
        )

        while response.status.is_redirect and self._follow_redirects:
            if len(visited) > self._max_redirects:
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
                new_uri = current_uri.resolve(redirect_str)
            except URIError as error:
                await response.close()
                raise RedirectError(
                    f"Failed to resolve redirect URI '{redirect_str}': {error}"
                ) from error

            if new_uri in visited:
                await response.close()
                raise RedirectError(f"Circular redirect detected: {new_uri}")

            visited.add(new_uri)
            current_uri = new_uri
            history.append(response)
            await response.close()

            if isinstance(new_uri, TitanURI):
                redirect_titan = new_uri.without_parameters.replace(
                    size=size,
                    mime=detected_mime,
                    token=token,
                )
                response = await self._do_request(
                    redirect_titan,
                    history=history,
                    requested_uri=final_uri,
                    payload=payload_bytes,
                )
            else:
                response = await self._do_request(
                    new_uri,
                    history=history,
                    requested_uri=final_uri,
                )

        return response

    async def delete(
        self,
        uri: str | AnyURI,
        *,
        token: str | None = None,
    ) -> Response:
        """Delete a resource via the Titan protocol by uploading zero bytes (size=0).

        Args:
            uri: The target URI as a string, GeminiURI, or TitanURI.
            token: Optional authorisation token.

        Returns:
            The final Response object.
        """
        return await self.upload(uri, b"", token=token)

    async def edit(self, uri: str | AnyURI) -> Response:
        """Request the raw content of a resource for editing using the Titan edit extension.

        Sends a Titan request with the ';edit' parameter to lock the resource (if supported
        by the server) and retrieve its raw unrendered content.

        Note:
            The Titan edit parameter is a proposed extension to the Titan specification
            designed for collaborative editing and raw content retrieval. It is supported
            by various Gemini and Titan servers.

        Args:
            uri: The target URI as a string, GeminiURI, or TitanURI.

        Returns:
            A Response instance containing the raw content for editing.

        Raises:
            URIError: If the URI is invalid.
            ConnectionError: If network connection fails or times out.
            SecurityError: If TLS or certificate validation fails.
            ProtocolError: If the server response violates the protocol.
            RedirectError: If redirect limits are exceeded or loops are detected.
            ValueError: If client certificate generation parameters are invalid.
            OSError: If creating directories or writing client certificate files fails.
            RuntimeError: If saving the updated client certificate store index fails.
        """
        target_uri: TitanURI
        if isinstance(uri, str):
            target_uri = (
                GeminiURI(uri).to_titan(edit=True)
                if uri.startswith("gemini://")
                else TitanURI.with_default_scheme(uri).with_edit(True)
            )
        elif isinstance(uri, GeminiURI):
            target_uri = uri.to_titan(edit=True)
        elif isinstance(uri, TitanURI):
            target_uri = uri.with_edit(True)
        else:
            raise URIError(f"Invalid URI type: {type(uri)}")

        return await self.request(target_uri)

    async def close(self) -> None:
        """Close the client and clean up resources, including the client certificate store."""
        if self._client_cert_store is not None:
            await self._client_cert_store.close()

    async def __aenter__(self) -> Self:
        """Enter the async context manager.

        Returns:
            The Client instance.
        """
        return self

    async def __aexit__(
        self,
        exception_type: object,
        exception_value: object,
        exception_traceback: object,
    ) -> None:
        """Exit the async context manager, closing resources."""
        await self.close()


### client.py ends here
