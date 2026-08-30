"""Tests for Gemini client implementation, redirects, and TOFU."""

import asyncio
import pathlib
import ssl
import sys
import tempfile
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.bindings.openssl.binding import Binding

from wasat import (
    GEMINI_DEFAULT_PORT,
    Client,
    ConnectionError,
    FileTrustStore,
    GeminiURI,
    RedirectError,
    SecurityError,
    StatusCode,
)
from wasat.trust import get_cert_fingerprint

_openssl_lib = Binding().lib


class MockSSLObject:
    """Mock for ssl.SSLObject/SSLSocket."""

    def __init__(self, cert_der: bytes = b"mock_der_cert") -> None:
        self._cert_der = cert_der

    def getpeercert(self, binary_form: bool = False) -> bytes | None:
        if binary_form:
            return self._cert_der
        return None


class MockTransport:
    """Mock asyncio.Transport."""

    def __init__(self, ssl_object: Any) -> None:
        self.ssl_object = ssl_object

    def get_extra_info(self, name: str) -> Any:
        if name == "ssl_object":
            return self.ssl_object
        return None


class MockStreamWriter:
    """Mock asyncio.StreamWriter."""

    def __init__(self, ssl_object: Any) -> None:
        self.transport = MockTransport(ssl_object)
        self.write_buf = b""
        self.closed = False

    def write(self, data: bytes) -> None:
        self.write_buf += data

    async def drain(self) -> None:
        pass

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        pass


class MockStreamReader:
    """Mock asyncio.StreamReader."""

    def __init__(self, response_lines: list[bytes]) -> None:
        self._lines = response_lines
        self._line_idx = 0
        self._body_data = b""
        self._body_offset = 0

    def set_body(self, data: bytes) -> None:
        self._body_data = data

    async def readuntil(self, separator: bytes = b"\n") -> bytes:
        if self._line_idx < len(self._lines):
            line = self._lines[self._line_idx]
            self._line_idx += 1
            return line
        raise asyncio.IncompleteReadError(b"", None)

    async def read(self, size: int = -1) -> bytes:
        if self._body_offset >= len(self._body_data):
            return b""
        if size == -1:
            chunk = self._body_data[self._body_offset :]
            self._body_offset = len(self._body_data)
            return chunk
        else:
            chunk = self._body_data[self._body_offset : self._body_offset + size]
            self._body_offset += len(chunk)
            return chunk


class TestClient:
    """Test suite for the Gemini Client class."""

    @pytest.fixture(autouse=True)
    def setup_ssl_object(self) -> None:
        self.ssl_object = MockSSLObject()

    def test_successful_request(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test a simple successful request and reading the body."""

        async def run() -> None:
            reader = MockStreamReader([b"20 text/gemini\r\n"])
            reader.set_body(b"Hello from Gemini!")
            writer = MockStreamWriter(self.ssl_object)

            async def mock_open_connection(
                *args: Any, **kwargs: Any
            ) -> tuple[MockStreamReader, MockStreamWriter]:
                return reader, writer

            monkeypatch.setattr(asyncio, "open_connection", mock_open_connection)

            client = Client(verify_mode="off")
            response = await client.request("gemini://example.com/index.gmi")

            assert response.status == StatusCode.SUCCESS
            assert response.mime_type == "text/gemini"
            assert response.uri == GeminiURI("gemini://example.com/index.gmi")
            assert response.verification_method == "off"
            assert response.server_cert_der is None
            assert response.server_cert_fingerprint is None

            text = await response.text()
            assert text == "Hello from Gemini!"
            assert writer.closed

        asyncio.run(run())

    def test_ssl_eof_error_on_read(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test that ssl.SSLEOFError when reading response line raises ConnectionError."""

        async def run() -> None:
            class FailingReader(MockStreamReader):
                async def readuntil(self, separator: bytes = b"\n") -> bytes:
                    raise ssl.SSLEOFError("EOF occurred in violation of protocol")

            reader = FailingReader([])
            writer = MockStreamWriter(self.ssl_object)

            async def mock_open_connection(
                *args: Any, **kwargs: Any
            ) -> tuple[MockStreamReader, MockStreamWriter]:
                return reader, writer

            monkeypatch.setattr(asyncio, "open_connection", mock_open_connection)

            client = Client(verify_mode="off")
            with pytest.raises(
                ConnectionError,
                match="Connection closed by server before sending response",
            ):
                await client.request("gemini://example.com/")
            assert writer.closed

        asyncio.run(run())

    def test_ssl_eof_error_on_write(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test that ssl.SSLEOFError when sending request line raises ConnectionError."""

        async def run() -> None:
            reader = MockStreamReader([])
            writer = MockStreamWriter(self.ssl_object)

            async def failing_drain() -> None:
                raise ssl.SSLEOFError("EOF occurred in violation of protocol")

            monkeypatch.setattr(writer, "drain", failing_drain)

            async def mock_open_connection(
                *args: Any, **kwargs: Any
            ) -> tuple[MockStreamReader, MockStreamWriter]:
                return reader, writer

            monkeypatch.setattr(asyncio, "open_connection", mock_open_connection)

            client = Client(verify_mode="off")
            with pytest.raises(ConnectionError, match="Failed to send request line"):
                await client.request("gemini://example.com/")
            assert writer.closed

        asyncio.run(run())

    def test_follow_redirects(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test that client follows redirects to the target."""

        async def run() -> None:
            # 1st request -> redirect to /target
            # 2nd request -> success
            reader1 = MockStreamReader([b"30 gemini://example.com/target\r\n"])
            writer1 = MockStreamWriter(self.ssl_object)

            reader2 = MockStreamReader([b"20 text/gemini\r\n"])
            reader2.set_body(b"Target Content")
            writer2 = MockStreamWriter(self.ssl_object)

            connections = [(reader1, writer1), (reader2, writer2)]
            call_count = 0

            async def mock_open_connection(
                *args: Any, **kwargs: Any
            ) -> tuple[MockStreamReader, MockStreamWriter]:
                nonlocal call_count
                connection = connections[call_count]
                call_count += 1
                return connection

            monkeypatch.setattr(asyncio, "open_connection", mock_open_connection)

            client = Client(verify_mode="off")
            response = await client.request("gemini://example.com/source")

            assert response.status == StatusCode.SUCCESS
            assert response.uri == GeminiURI("gemini://example.com/target")
            assert await response.text() == "Target Content"
            assert call_count == 2
            assert response.requested_uri == GeminiURI("gemini://example.com/source")
            assert len(response.history) == 1
            assert response.history[0].status == StatusCode.TEMPORARY_REDIRECT
            assert response.history[0].uri == GeminiURI("gemini://example.com/source")
            assert response.history[0].requested_uri == GeminiURI(
                "gemini://example.com/source"
            )

        asyncio.run(run())

    def test_circular_redirect(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test that circular redirects raise RedirectError."""

        async def run() -> None:
            reader1 = MockStreamReader([b"30 gemini://example.com/two\r\n"])
            writer1 = MockStreamWriter(self.ssl_object)

            reader2 = MockStreamReader([b"30 gemini://example.com/one\r\n"])
            reader2.set_body(b"")
            writer2 = MockStreamWriter(self.ssl_object)

            connections = [(reader1, writer1), (reader2, writer2), (reader1, writer1)]
            call_count = 0

            async def mock_open_connection(
                *args: Any, **kwargs: Any
            ) -> tuple[MockStreamReader, MockStreamWriter]:
                nonlocal call_count
                connection = connections[call_count]
                call_count += 1
                return connection

            monkeypatch.setattr(asyncio, "open_connection", mock_open_connection)

            client = Client(verify_mode="off")
            with pytest.raises(RedirectError):
                await client.request("gemini://example.com/one")

        asyncio.run(run())

    def test_max_redirects(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test that exceeding maximum redirects raises RedirectError."""

        async def run() -> None:
            reader = MockStreamReader([b"30 gemini://example.com/next\r\n"] * 5)
            writer = MockStreamWriter(self.ssl_object)

            async def mock_open_connection(
                *args: Any, **kwargs: Any
            ) -> tuple[MockStreamReader, MockStreamWriter]:
                return reader, writer

            monkeypatch.setattr(asyncio, "open_connection", mock_open_connection)

            client = Client(verify_mode="off", max_redirects=3)
            with pytest.raises(RedirectError):
                await client.request("gemini://example.com/start")

        asyncio.run(run())

    def test_permanent_redirect_cache(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test that permanent redirects (31) are cached and reused."""

        async def run() -> None:
            # 1st request to /old -> 31 redirect to /new
            reader1 = MockStreamReader([b"31 gemini://example.com/new\r\n"])
            writer1 = MockStreamWriter(self.ssl_object)

            # 2nd request to /new -> 20 success
            reader2 = MockStreamReader([b"20 text/gemini\r\n"])
            reader2.set_body(b"New Content")
            writer2 = MockStreamWriter(self.ssl_object)

            # 3rd request (subsequent call to /old) -> should skip /old and connect directly to /new
            reader3 = MockStreamReader([b"20 text/gemini\r\n"])
            reader3.set_body(b"New Content")
            writer3 = MockStreamWriter(self.ssl_object)

            connections = [
                (reader1, writer1),
                (reader2, writer2),
                (reader3, writer3),
            ]
            call_count = 0

            async def mock_open_connection(
                *args: Any, **kwargs: Any
            ) -> tuple[MockStreamReader, MockStreamWriter]:
                nonlocal call_count
                connection = connections[call_count]
                call_count += 1
                return connection

            monkeypatch.setattr(asyncio, "open_connection", mock_open_connection)

            client = Client(verify_mode="off")

            # First request to /old
            response1 = await client.request("gemini://example.com/old")
            assert await response1.text() == "New Content"
            assert call_count == 2
            assert response1.requested_uri == GeminiURI("gemini://example.com/old")
            assert response1.uri == GeminiURI("gemini://example.com/new")
            assert len(response1.history) == 1
            assert response1.history[0].status == StatusCode.PERMANENT_REDIRECT
            assert response1.history[0].uri == GeminiURI("gemini://example.com/old")
            assert response1.history[0].requested_uri == GeminiURI(
                "gemini://example.com/old"
            )

            # Second request to /old (should go directly to /new)
            response2 = await client.request("gemini://example.com/old")
            assert await response2.text() == "New Content"
            assert call_count == 3  # Only 1 additional connection
            assert response2.requested_uri == GeminiURI("gemini://example.com/old")
            assert response2.uri == GeminiURI("gemini://example.com/new")
            assert len(response2.history) == 0

        asyncio.run(run())

    def test_tofu_verification(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test Trust-On-First-Use (TOFU) verification flow."""

        async def run() -> None:
            with tempfile.TemporaryDirectory() as temporary_directory:
                hosts_file = Path(temporary_directory) / "known_hosts"
                trust_store = FileTrustStore(hosts_file)

                cert_der1 = b"cert_one"
                ssl_object1 = MockSSLObject(cert_der1)

                # 1. First request with cert 1: Trusted on First Use, saved.
                reader1 = MockStreamReader([b"20 text/gemini\r\n"])
                writer1 = MockStreamWriter(ssl_object1)

                connections: list[tuple[MockStreamReader, MockStreamWriter]] = [
                    (reader1, writer1)
                ]

                async def mock_open_connection(
                    *args: Any, **kwargs: Any
                ) -> tuple[MockStreamReader, MockStreamWriter]:
                    return connections[0]

                monkeypatch.setattr(asyncio, "open_connection", mock_open_connection)

                client = Client(verify_mode="tofu", trust_store=trust_store)
                response1 = await client.request("gemini://example.com/index.gmi")
                assert response1.status == StatusCode.SUCCESS
                assert response1.verification_method == "tofu"
                assert response1.server_cert_der == cert_der1
                assert response1.server_cert_fingerprint == get_cert_fingerprint(
                    cert_der1
                )

                # Verify saved fingerprint in store
                fingerprint1 = await trust_store.get_fingerprint(
                    "example.com", GEMINI_DEFAULT_PORT
                )
                assert fingerprint1 == get_cert_fingerprint(cert_der1)

                # 2. Second request with same cert: should pass
                reader2 = MockStreamReader([b"20 text/gemini\r\n"])
                writer2 = MockStreamWriter(ssl_object1)
                connections[0] = (reader2, writer2)
                response2 = await client.request("gemini://example.com/index.gmi")
                assert response2.status == StatusCode.SUCCESS

                # 3. Third request with different cert: should fail
                cert_der2 = b"cert_two"
                ssl_object2 = MockSSLObject(cert_der2)
                reader3 = MockStreamReader([b"20 text/gemini\r\n"])
                writer3 = MockStreamWriter(ssl_object2)
                connections[0] = (reader3, writer3)

                with pytest.raises(SecurityError) as exception_context:
                    await client.request("gemini://example.com/index.gmi")
                assert "fingerprint mismatch" in str(exception_context.value)

        asyncio.run(run())

    def test_default_trust_store_path_windows_with_appdata(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test default trust store path on Windows when APPDATA is set."""
        called_path: Path | None = None

        class MockFileTrustStore:
            def __init__(self, path: Path) -> None:
                nonlocal called_path
                called_path = path

        import wasat.client

        monkeypatch.setattr(wasat.client, "FileTrustStore", MockFileTrustStore)
        monkeypatch.setattr(sys, "platform", "win32")
        monkeypatch.setenv("APPDATA", "C:\\MockAppData")

        Client(verify_mode="tofu")

        assert called_path == Path("C:\\MockAppData") / "wasat" / "known_hosts"

    def test_default_trust_store_path_windows_without_appdata(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test default trust store path on Windows when APPDATA is not set."""
        called_path: Path | None = None

        class MockFileTrustStore:
            def __init__(self, path: Path) -> None:
                nonlocal called_path
                called_path = path

        import wasat.client

        monkeypatch.setattr(wasat.client, "FileTrustStore", MockFileTrustStore)
        monkeypatch.setattr(sys, "platform", "win32")
        monkeypatch.delenv("APPDATA", raising=False)
        monkeypatch.setattr(pathlib.Path, "home", lambda: Path("C:\\Users\\MockUser"))

        Client(verify_mode="tofu")

        assert called_path == (
            Path("C:\\Users\\MockUser")
            / "AppData"
            / "Roaming"
            / "wasat"
            / "known_hosts"
        )

    def test_default_trust_store_path_unix(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test default trust store path on Unix-like systems."""
        called_path: Path | None = None

        class MockFileTrustStore:
            def __init__(self, path: Path) -> None:
                nonlocal called_path
                called_path = path

        import wasat.client

        monkeypatch.setattr(wasat.client, "FileTrustStore", MockFileTrustStore)
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setattr(pathlib.Path, "home", lambda: Path("/home/mockuser"))

        Client(verify_mode="tofu")

        assert called_path == (
            Path("/home/mockuser") / ".config" / "wasat" / "known_hosts"
        )

    def test_client_cert_propagation_on_same_host_redirect(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Test that client certificates are reused for same-host redirects."""
        from wasat import generate_self_signed_cert

        async def run() -> None:
            # First request -> 30 redirect to /protected
            reader1 = MockStreamReader([b"30 gemini://example.com/protected\r\n"])
            writer1 = MockStreamWriter(self.ssl_object)

            # Second request -> 20 success
            reader2 = MockStreamReader([b"20 text/gemini\r\n"])
            reader2.set_body(b"Secret Area")
            writer2 = MockStreamWriter(self.ssl_object)

            connections = [(reader1, writer1), (reader2, writer2)]
            call_count = 0

            # Store tracks if cert was used on connect
            ssl_contexts_used: list[Any] = []

            async def mock_connect(
                self_client: Any, uri: GeminiURI, ssl_context: Any
            ) -> tuple[MockStreamReader, MockStreamWriter]:
                nonlocal call_count
                ssl_contexts_used.append(ssl_context)
                connection = connections[call_count]
                call_count += 1
                return connection

            monkeypatch.setattr("wasat.Client._connect", mock_connect)
            monkeypatch.setattr(
                "wasat.Client._create_ssl_context",
                lambda *args, **kwargs: ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT),
            )

            cert_pem, key_pem = generate_self_signed_cert(common_name="mock.client.com")
            cert_path = tmp_path / "cert.crt"
            key_path = tmp_path / "cert.key"
            cert_path.write_bytes(cert_pem)
            key_path.write_bytes(key_pem)

            class MockClientCertStore:
                async def get_credentials(
                    self, uri: GeminiURI
                ) -> tuple[Path, Path] | None:
                    if uri.path == "/start":
                        return cert_path, key_path
                    return None

                async def register_credentials(
                    self,
                    uri: GeminiURI,
                    cert_path: str | Path,
                    key_path: str | Path,
                    *,
                    transient: bool = False,
                ) -> None:
                    pass

                async def close(self) -> None:
                    pass

            mock_cert_store = MockClientCertStore()

            client = Client(
                verify_mode="off",
                client_cert_store=mock_cert_store,  # type: ignore[arg-type]
            )

            response = await client.request("gemini://example.com/start")

            assert response.status == StatusCode.SUCCESS
            assert await response.text() == "Secret Area"
            assert call_count == 2
            assert response.client_cert_used is True
            assert response.client_cert_path == cert_path
            assert response.client_key_path == key_path
            assert response.client_cert is not None
            assert response.client_cert.cert_path == cert_path
            assert response.history[0].client_cert_used is True
            assert response.history[0].client_cert_path == cert_path
            assert response.history[0].client_key_path == key_path

        asyncio.run(run())

    def test_hybrid_mode_ca_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test hybrid mode when CA verification succeeds."""

        async def run() -> None:
            saved_hosts: list[tuple[str, int, bytes]] = []

            class MockTrustStore:
                async def save(self, host: str, port: int, cert_der: bytes) -> None:
                    saved_hosts.append((host, port, cert_der))

                async def verify(self, host: str, port: int, cert_der: bytes) -> bool:
                    return True

                async def get_fingerprint(self, host: str, port: int) -> str | None:
                    return None

                async def get_hosts(self) -> list[tuple[str, int]]:
                    return []

                async def forget(self, host: str, port: int = 1965) -> bool:
                    return False

            mock_store = MockTrustStore()

            class MockSSLObject:
                def getpeercert(self, binary_form: bool = False) -> bytes:
                    return b"mock_ca_cert_der"

            class MockTransport:
                def get_extra_info(self, name: str) -> Any:
                    if name == "ssl_object":
                        return MockSSLObject()
                    return None

            class MockWriter:
                def __init__(self) -> None:
                    self.transport = MockTransport()

                def write(self, data: bytes) -> None:
                    pass

                async def drain(self) -> None:
                    pass

                def close(self) -> None:
                    pass

                async def wait_closed(self) -> None:
                    pass

            class MockReader:
                async def readuntil(self, separator: bytes = b"\r\n") -> bytes:
                    return b"20 text/gemini\r\n"

            async def mock_connect(
                self_client: Any, uri: GeminiURI, ssl_context: Any
            ) -> tuple[MockReader, MockWriter]:
                # CA mode succeeds
                if ssl_context.verify_mode == ssl.CERT_REQUIRED:
                    return MockReader(), MockWriter()
                raise SecurityError("CA handshake failed")

            monkeypatch.setattr("wasat.Client._connect", mock_connect)

            client = Client(verify_mode="hybrid", trust_store=mock_store)
            async with client:
                response = await client.request("gemini://example.com/")
                assert response.status == StatusCode.SUCCESS
                assert response.verification_method == "ca"
                assert response.server_cert_der == b"mock_ca_cert_der"
                assert response.server_cert_fingerprint == get_cert_fingerprint(
                    b"mock_ca_cert_der"
                )
                await response.close()

            assert len(saved_hosts) == 1
            assert saved_hosts[0][0] == "example.com"
            assert saved_hosts[0][2] == b"mock_ca_cert_der"

        asyncio.run(run())

    def test_hybrid_mode_tofu_fallback(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test hybrid mode falling back to TOFU when CA verification fails."""

        async def run() -> None:
            tofu_verified = False

            class MockTrustStore:
                async def save(self, host: str, port: int, cert_der: bytes) -> None:
                    pass

                async def verify(self, host: str, port: int, cert_der: bytes) -> bool:
                    nonlocal tofu_verified
                    tofu_verified = True
                    return True

                async def get_fingerprint(self, host: str, port: int) -> str | None:
                    return None

                async def get_hosts(self) -> list[tuple[str, int]]:
                    return []

                async def forget(self, host: str, port: int = 1965) -> bool:
                    return False

            mock_store = MockTrustStore()

            class MockSSLObject:
                def getpeercert(self, binary_form: bool = False) -> bytes:
                    return b"mock_self_signed_cert_der"

            class MockTransport:
                def get_extra_info(self, name: str) -> Any:
                    if name == "ssl_object":
                        return MockSSLObject()
                    return None

            class MockWriter:
                def __init__(self) -> None:
                    self.transport = MockTransport()

                def write(self, data: bytes) -> None:
                    pass

                async def drain(self) -> None:
                    pass

                def close(self) -> None:
                    pass

                async def wait_closed(self) -> None:
                    pass

            class MockReader:
                async def readuntil(self, separator: bytes = b"\r\n") -> bytes:
                    return b"20 text/gemini\r\n"

            async def mock_connect(
                self_client: Any, uri: GeminiURI, ssl_context: Any
            ) -> tuple[MockReader, MockWriter]:
                # Fail CA verification, succeed TOFU verification
                if ssl_context.verify_mode == ssl.CERT_REQUIRED:
                    raise SecurityError(
                        "CA verification failed: self-signed certificate"
                    )
                return MockReader(), MockWriter()

            monkeypatch.setattr("wasat.Client._connect", mock_connect)

            client = Client(verify_mode="hybrid", trust_store=mock_store)
            async with client:
                response = await client.request("gemini://selfsigned.example.com/")
                assert response.status == StatusCode.SUCCESS
                assert response.verification_method == "tofu"
                assert response.server_cert_der == b"mock_self_signed_cert_der"
                assert response.server_cert_fingerprint == get_cert_fingerprint(
                    b"mock_self_signed_cert_der"
                )
                await response.close()

            assert tofu_verified is True

        asyncio.run(run())

    def test_hybrid_mode_no_fallback_on_expired_cert(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test hybrid mode raises SecurityError on expired CA certificates without falling back to TOFU."""

        async def run() -> None:
            class MockTrustStore:
                async def save(self, host: str, port: int, cert_der: bytes) -> None:
                    pass

                async def verify(self, host: str, port: int, cert_der: bytes) -> bool:
                    return True

                async def get_fingerprint(self, host: str, port: int) -> str | None:
                    return None

                async def get_hosts(self) -> list[tuple[str, int]]:
                    return []

                async def forget(self, host: str, port: int = 1965) -> bool:
                    return False

            mock_store = MockTrustStore()

            async def mock_connect(
                self_client: Any, uri: GeminiURI, ssl_context: Any
            ) -> tuple[Any, Any]:
                if ssl_context.verify_mode == ssl.CERT_REQUIRED:
                    ssl_error = ssl.SSLCertVerificationError(
                        _openssl_lib.X509_V_ERR_CERT_HAS_EXPIRED,
                        "certificate has expired",
                    )
                    security_error = SecurityError(f"TLS handshake failed: {ssl_error}")
                    security_error.__cause__ = ssl_error
                    raise security_error
                raise AssertionError(
                    "Should not attempt TOFU fallback for expired cert"
                )

            monkeypatch.setattr("wasat.Client._connect", mock_connect)

            client = Client(verify_mode="hybrid", trust_store=mock_store)
            async with client:
                with pytest.raises(SecurityError, match="certificate has expired"):
                    await client.request("gemini://expired.example.com/")

        asyncio.run(run())

    def test_hybrid_mode_no_fallback_on_hostname_mismatch(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test hybrid mode raises SecurityError on hostname mismatch without falling back to TOFU."""

        async def run() -> None:
            class MockTrustStore:
                async def save(self, host: str, port: int, cert_der: bytes) -> None:
                    pass

                async def verify(self, host: str, port: int, cert_der: bytes) -> bool:
                    return True

                async def get_fingerprint(self, host: str, port: int) -> str | None:
                    return None

                async def get_hosts(self) -> list[tuple[str, int]]:
                    return []

                async def forget(self, host: str, port: int = 1965) -> bool:
                    return False

            mock_store = MockTrustStore()

            async def mock_connect(
                self_client: Any, uri: GeminiURI, ssl_context: Any
            ) -> tuple[Any, Any]:
                if ssl_context.verify_mode == ssl.CERT_REQUIRED:
                    ssl_error = ssl.SSLCertVerificationError(
                        _openssl_lib.X509_V_ERR_HOSTNAME_MISMATCH,
                        "hostname 'mismatch.example.com' doesn't match 'other.example.com'",
                    )
                    security_error = SecurityError(f"TLS handshake failed: {ssl_error}")
                    security_error.__cause__ = ssl_error
                    raise security_error
                raise AssertionError(
                    "Should not attempt TOFU fallback for hostname mismatch"
                )

            monkeypatch.setattr("wasat.Client._connect", mock_connect)

            client = Client(verify_mode="hybrid", trust_store=mock_store)
            async with client:
                with pytest.raises(SecurityError, match="hostname"):
                    await client.request("gemini://mismatch.example.com/")

        asyncio.run(run())

    def test_ca_verification_method_and_cert_details(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test ca verify_mode exposes verification_method and server cert details."""

        async def run() -> None:
            cert_der = b"ca_server_cert_bytes"
            ssl_object = MockSSLObject(cert_der)
            reader = MockStreamReader([b"20 text/gemini\r\n"])
            writer = MockStreamWriter(ssl_object)

            async def mock_connect(
                self_client: Any, uri: GeminiURI, ssl_context: Any
            ) -> tuple[MockStreamReader, MockStreamWriter]:
                return reader, writer

            monkeypatch.setattr("wasat.Client._connect", mock_connect)

            client = Client(verify_mode="ca")
            response = await client.request("gemini://example.com/")
            assert response.verification_method == "ca"
            assert response.server_cert_der == cert_der
            assert response.server_cert_fingerprint == get_cert_fingerprint(cert_der)

        asyncio.run(run())
