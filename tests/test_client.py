"""Tests for Gemini client implementation, redirects, and TOFU."""

import asyncio
import pathlib
import sys
import tempfile
from pathlib import Path
from typing import Any

import pytest

from wasat import (
    Client,
    FileTrustStore,
    RedirectError,
    SecurityError,
    StatusCode,
)
from wasat.trust import get_cert_fingerprint


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

    async def read(self, n: int = -1) -> bytes:
        if self._body_offset >= len(self._body_data):
            return b""
        if n == -1:
            chunk = self._body_data[self._body_offset :]
            self._body_offset = len(self._body_data)
            return chunk
        else:
            chunk = self._body_data[self._body_offset : self._body_offset + n]
            self._body_offset += len(chunk)
            return chunk


class TestClient:
    """Test suite for the Gemini Client class."""

    @pytest.fixture(autouse=True)
    def setup_ssl_obj(self) -> None:
        self.ssl_obj = MockSSLObject()

    def test_successful_request(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test a simple successful request and reading the body."""

        async def run() -> None:
            reader = MockStreamReader([b"20 text/gemini\r\n"])
            reader.set_body(b"Hello from Gemini!")
            writer = MockStreamWriter(self.ssl_obj)

            async def mock_open_connection(
                *args: Any, **kwargs: Any
            ) -> tuple[MockStreamReader, MockStreamWriter]:
                return reader, writer

            monkeypatch.setattr(asyncio, "open_connection", mock_open_connection)

            client = Client(verify_mode="off")
            response = await client.request("gemini://example.com/index.gmi")

            assert response.status == StatusCode.SUCCESS
            assert response.mime_type == "text/gemini"

            text = await response.text()
            assert text == "Hello from Gemini!"
            assert writer.closed

        asyncio.run(run())

    def test_follow_redirects(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test that client follows redirects to the target."""

        async def run() -> None:
            # 1st request -> redirect to /target
            # 2nd request -> success
            reader1 = MockStreamReader([b"30 gemini://example.com/target\r\n"])
            writer1 = MockStreamWriter(self.ssl_obj)

            reader2 = MockStreamReader([b"20 text/gemini\r\n"])
            reader2.set_body(b"Target Content")
            writer2 = MockStreamWriter(self.ssl_obj)

            connections = [(reader1, writer1), (reader2, writer2)]
            call_count = 0

            async def mock_open_connection(
                *args: Any, **kwargs: Any
            ) -> tuple[MockStreamReader, MockStreamWriter]:
                nonlocal call_count
                conn = connections[call_count]
                call_count += 1
                return conn

            monkeypatch.setattr(asyncio, "open_connection", mock_open_connection)

            client = Client(verify_mode="off")
            response = await client.request("gemini://example.com/source")

            assert response.status == StatusCode.SUCCESS
            assert await response.text() == "Target Content"
            assert call_count == 2

        asyncio.run(run())

    def test_circular_redirect(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test that circular redirects raise RedirectError."""

        async def run() -> None:
            reader1 = MockStreamReader([b"30 gemini://example.com/two\r\n"])
            writer1 = MockStreamWriter(self.ssl_obj)

            reader2 = MockStreamReader([b"30 gemini://example.com/one\r\n"])
            reader2.set_body(b"")
            writer2 = MockStreamWriter(self.ssl_obj)

            connections = [(reader1, writer1), (reader2, writer2), (reader1, writer1)]
            call_count = 0

            async def mock_open_connection(
                *args: Any, **kwargs: Any
            ) -> tuple[MockStreamReader, MockStreamWriter]:
                nonlocal call_count
                conn = connections[call_count]
                call_count += 1
                return conn

            monkeypatch.setattr(asyncio, "open_connection", mock_open_connection)

            client = Client(verify_mode="off")
            with pytest.raises(RedirectError):
                await client.request("gemini://example.com/one")

        asyncio.run(run())

    def test_max_redirects(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test that exceeding maximum redirects raises RedirectError."""

        async def run() -> None:
            reader = MockStreamReader([b"30 gemini://example.com/next\r\n"] * 5)
            writer = MockStreamWriter(self.ssl_obj)

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
            writer1 = MockStreamWriter(self.ssl_obj)

            # 2nd request to /new -> 20 success
            reader2 = MockStreamReader([b"20 text/gemini\r\n"])
            reader2.set_body(b"New Content")
            writer2 = MockStreamWriter(self.ssl_obj)

            # 3rd request (subsequent call to /old) -> should skip /old and connect directly to /new
            reader3 = MockStreamReader([b"20 text/gemini\r\n"])
            reader3.set_body(b"New Content")
            writer3 = MockStreamWriter(self.ssl_obj)

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
                conn = connections[call_count]
                call_count += 1
                return conn

            monkeypatch.setattr(asyncio, "open_connection", mock_open_connection)

            client = Client(verify_mode="off")

            # First request to /old
            resp1 = await client.request("gemini://example.com/old")
            assert await resp1.text() == "New Content"
            assert call_count == 2

            # Second request to /old (should go directly to /new)
            resp2 = await client.request("gemini://example.com/old")
            assert await resp2.text() == "New Content"
            assert call_count == 3  # Only 1 additional connection

        asyncio.run(run())

    def test_tofu_verification(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test Trust-On-First-Use (TOFU) verification flow."""

        async def run() -> None:
            with tempfile.TemporaryDirectory() as tmpdir:
                hosts_file = Path(tmpdir) / "known_hosts"
                trust_store = FileTrustStore(hosts_file)

                cert_der1 = b"cert_one"
                ssl_obj1 = MockSSLObject(cert_der1)

                # 1. First request with cert 1: Trusted on First Use, saved.
                reader1 = MockStreamReader([b"20 text/gemini\r\n"])
                writer1 = MockStreamWriter(ssl_obj1)

                connections: list[tuple[MockStreamReader, MockStreamWriter]] = [
                    (reader1, writer1)
                ]

                async def mock_open_connection(
                    *args: Any, **kwargs: Any
                ) -> tuple[MockStreamReader, MockStreamWriter]:
                    return connections[0]

                monkeypatch.setattr(asyncio, "open_connection", mock_open_connection)

                client = Client(verify_mode="tofu", trust_store=trust_store)
                resp1 = await client.request("gemini://example.com/index.gmi")
                assert resp1.status == StatusCode.SUCCESS

                # Verify saved fingerprint in store
                fingerprint1 = await trust_store.get_fingerprint("example.com", 1965)
                assert fingerprint1 == get_cert_fingerprint(cert_der1)

                # 2. Second request with same cert: should pass
                reader2 = MockStreamReader([b"20 text/gemini\r\n"])
                writer2 = MockStreamWriter(ssl_obj1)
                connections[0] = (reader2, writer2)
                resp2 = await client.request("gemini://example.com/index.gmi")
                assert resp2.status == StatusCode.SUCCESS

                # 3. Third request with different cert: should fail
                cert_der2 = b"cert_two"
                ssl_obj2 = MockSSLObject(cert_der2)
                reader3 = MockStreamReader([b"20 text/gemini\r\n"])
                writer3 = MockStreamWriter(ssl_obj2)
                connections[0] = (reader3, writer3)

                with pytest.raises(SecurityError) as ctx:
                    await client.request("gemini://example.com/index.gmi")
                assert "fingerprint mismatch" in str(ctx.value)

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


### test_client.py ends here
