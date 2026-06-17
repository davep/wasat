"""Tests for Gemini client implementation, redirects, and TOFU."""

import asyncio
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

from wasat.client import Client
from wasat.exceptions import (
    RedirectError,
    SecurityError,
)
from wasat.status import StatusCode
from wasat.trust import FileTrustStore, get_cert_fingerprint


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


class TestClient(unittest.IsolatedAsyncioTestCase):
    """Test suite for the Gemini Client class."""

    def setUp(self) -> None:
        self.ssl_obj = MockSSLObject()

    @patch("asyncio.open_connection")
    async def test_successful_request(self, mock_connect: AsyncMock) -> None:
        """Test a simple successful request and reading the body."""
        reader = MockStreamReader([b"20 text/gemini\r\n"])
        reader.set_body(b"Hello from Gemini!")
        writer = MockStreamWriter(self.ssl_obj)
        mock_connect.return_return_value = (reader, writer)
        mock_connect.side_effect = lambda *a, **k: (reader, writer)

        client = Client(verify_mode="off")
        response = await client.request("gemini://example.com/index.gmi")

        self.assertEqual(response.status, StatusCode.SUCCESS)
        self.assertEqual(response.mime_type, "text/gemini")

        text = await response.text()
        self.assertEqual(text, "Hello from Gemini!")
        self.assertTrue(writer.closed)

    @patch("asyncio.open_connection")
    async def test_follow_redirects(self, mock_connect: AsyncMock) -> None:
        """Test that client follows redirects to the target."""
        # 1st request -> redirect to /target
        # 2nd request -> success
        reader1 = MockStreamReader([b"30 gemini://example.com/target\r\n"])
        writer1 = MockStreamWriter(self.ssl_obj)

        reader2 = MockStreamReader([b"20 text/gemini\r\n"])
        reader2.set_body(b"Target Content")
        writer2 = MockStreamWriter(self.ssl_obj)

        connections = [(reader1, writer1), (reader2, writer2)]
        mock_connect.side_effect = connections

        client = Client(verify_mode="off")
        response = await client.request("gemini://example.com/source")

        self.assertEqual(response.status, StatusCode.SUCCESS)
        self.assertEqual(await response.text(), "Target Content")
        self.assertEqual(mock_connect.call_count, 2)

    @patch("asyncio.open_connection")
    async def test_circular_redirect(self, mock_connect: AsyncMock) -> None:
        """Test that circular redirects raise RedirectError."""
        reader1 = MockStreamReader([b"30 gemini://example.com/two\r\n"])
        writer1 = MockStreamWriter(self.ssl_obj)

        reader2 = MockStreamReader([b"30 gemini://example.com/one\r\n"])
        reader2.set_body(b"")
        writer2 = MockStreamWriter(self.ssl_obj)

        connections = [(reader1, writer1), (reader2, writer2), (reader1, writer1)]
        mock_connect.side_effect = connections

        client = Client(verify_mode="off")
        with self.assertRaises(RedirectError):
            await client.request("gemini://example.com/one")

    @patch("asyncio.open_connection")
    async def test_max_redirects(self, mock_connect: AsyncMock) -> None:
        """Test that exceeding maximum redirects raises RedirectError."""
        reader = MockStreamReader([b"30 gemini://example.com/next\r\n"] * 5)
        writer = MockStreamWriter(self.ssl_obj)
        mock_connect.side_effect = lambda *a, **k: (reader, writer)

        client = Client(verify_mode="off", max_redirects=3)
        with self.assertRaises(RedirectError):
            await client.request("gemini://example.com/start")

    @patch("asyncio.open_connection")
    async def test_permanent_redirect_cache(self, mock_connect: AsyncMock) -> None:
        """Test that permanent redirects (31) are cached and reused."""
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

        mock_connect.side_effect = [
            (reader1, writer1),
            (reader2, writer2),
            (reader3, writer3),
        ]

        client = Client(verify_mode="off")

        # First request to /old
        resp1 = await client.request("gemini://example.com/old")
        self.assertEqual(await resp1.text(), "New Content")
        self.assertEqual(mock_connect.call_count, 2)

        # Second request to /old (should go directly to /new)
        resp2 = await client.request("gemini://example.com/old")
        self.assertEqual(await resp2.text(), "New Content")
        self.assertEqual(mock_connect.call_count, 3)  # Only 1 additional connection

    @patch("asyncio.open_connection")
    async def test_tofu_verification(self, mock_connect: AsyncMock) -> None:
        """Test Trust-On-First-Use (TOFU) verification flow."""
        with tempfile.TemporaryDirectory() as tmpdir:
            hosts_file = Path(tmpdir) / "known_hosts"
            trust_store = FileTrustStore(hosts_file)

            cert_der1 = b"cert_one"
            ssl_obj1 = MockSSLObject(cert_der1)

            # 1. First request with cert 1: Trusted on First Use, saved.
            reader1 = MockStreamReader([b"20 text/gemini\r\n"])
            writer1 = MockStreamWriter(ssl_obj1)
            mock_connect.side_effect = lambda *a, **k: (reader1, writer1)

            client = Client(verify_mode="tofu", trust_store=trust_store)
            resp1 = await client.request("gemini://example.com/index.gmi")
            self.assertEqual(resp1.status, StatusCode.SUCCESS)

            # Verify saved fingerprint in store
            fingerprint1 = await trust_store.get_fingerprint("example.com", 1965)
            self.assertEqual(fingerprint1, get_cert_fingerprint(cert_der1))

            # 2. Second request with same cert: should pass
            reader2 = MockStreamReader([b"20 text/gemini\r\n"])
            writer2 = MockStreamWriter(ssl_obj1)
            mock_connect.side_effect = lambda *a, **k: (reader2, writer2)
            resp2 = await client.request("gemini://example.com/index.gmi")
            self.assertEqual(resp2.status, StatusCode.SUCCESS)

            # 3. Third request with different cert: should fail
            cert_der2 = b"cert_two"
            ssl_obj2 = MockSSLObject(cert_der2)
            reader3 = MockStreamReader([b"20 text/gemini\r\n"])
            writer3 = MockStreamWriter(ssl_obj2)
            mock_connect.side_effect = lambda *a, **k: (reader3, writer3)

            with self.assertRaises(SecurityError) as ctx:
                await client.request("gemini://example.com/index.gmi")
            self.assertIn("fingerprint mismatch", str(ctx.exception))

    @patch("wasat.client.FileTrustStore")
    def test_default_trust_store_path_windows_with_appdata(
        self, mock_file_trust_store: MagicMock
    ) -> None:
        """Test default trust store path on Windows when APPDATA is set."""
        with (
            patch("wasat.client.sys") as mock_sys,
            patch("wasat.client.os.environ", {"APPDATA": "C:\\MockAppData"}),
        ):
            mock_sys.platform = "win32"

            Client(verify_mode="tofu")

            mock_file_trust_store.assert_called_once()
            called_path = mock_file_trust_store.call_args[0][0]
            self.assertEqual(
                called_path, Path("C:\\MockAppData") / "wasat" / "known_hosts"
            )

    @patch("wasat.client.FileTrustStore")
    def test_default_trust_store_path_windows_without_appdata(
        self, mock_file_trust_store: MagicMock
    ) -> None:
        """Test default trust store path on Windows when APPDATA is not set."""
        with (
            patch("wasat.client.sys") as mock_sys,
            patch("wasat.client.os.environ", {}),
            patch("pathlib.Path.home", return_value=Path("C:\\Users\\MockUser")),
        ):
            mock_sys.platform = "win32"

            Client(verify_mode="tofu")

            mock_file_trust_store.assert_called_once()
            called_path = mock_file_trust_store.call_args[0][0]
            self.assertEqual(
                called_path,
                Path("C:\\Users\\MockUser")
                / "AppData"
                / "Roaming"
                / "wasat"
                / "known_hosts",
            )

    @patch("wasat.client.FileTrustStore")
    def test_default_trust_store_path_unix(
        self, mock_file_trust_store: MagicMock
    ) -> None:
        """Test default trust store path on Unix-like systems."""
        with (
            patch("wasat.client.sys") as mock_sys,
            patch("pathlib.Path.home", return_value=Path("/home/mockuser")),
        ):
            mock_sys.platform = "linux"

            Client(verify_mode="tofu")

            mock_file_trust_store.assert_called_once()
            called_path = mock_file_trust_store.call_args[0][0]
            self.assertEqual(
                called_path,
                Path("/home/mockuser") / ".config" / "wasat" / "known_hosts",
            )


if __name__ == "__main__":
    unittest.main()
