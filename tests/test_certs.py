"""Tests for client certificate generation, store, and retry logic."""

import asyncio
import tempfile
from typing import Any, Literal

import pytest

from wasat import (
    Client,
    FileClientCertificateStore,
    GeminiURI,
    StatusCode,
    generate_self_signed_cert,
)
from wasat.certs import _safe_filename, get_candidate_scopes


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


##############################################################################
def test_safe_filename() -> None:
    """Test safe filename conversion of scopes."""
    assert _safe_filename("example.com:1965/") == "example.com_1965"
    assert _safe_filename("example.com/foo/bar/") == "example.com_foo_bar"
    assert _safe_filename("example.com:1965/admin/db") == "example.com_1965_admin_db"


##############################################################################
def test_candidate_scopes() -> None:
    """Test scope candidate generation and specificity ordering."""
    uri = GeminiURI("gemini://example.com:1965/foo/bar/baz.gmi")
    candidates = get_candidate_scopes(uri)
    expected = [
        "example.com:1965/foo/bar/baz.gmi",
        "example.com:1965/foo/bar/",
        "example.com:1965/foo/",
        "example.com:1965/",
        "example.com/foo/bar/baz.gmi",
        "example.com/foo/bar/",
        "example.com/foo/",
        "example.com/",
    ]
    assert candidates == expected


##############################################################################
def test_generate_self_signed_cert() -> None:
    """Test generating self-signed client certificates (ECDSA & RSA)."""
    # ECDSA default with optional fields
    cert_pem, key_pem = generate_self_signed_cert(
        "test_client",
        key_type="ecdsa",
        email="user@example.com",
        user_id="user123",
        domain="example.com",
        organisation="My Org",
        country="GB",
    )
    assert cert_pem.startswith(b"-----BEGIN CERTIFICATE-----")
    assert key_pem.startswith(b"-----BEGIN PRIVATE KEY-----")

    # RSA
    cert_pem_rsa, key_pem_rsa = generate_self_signed_cert(
        "test_client", key_type="rsa", rsa_key_size=2048
    )
    assert cert_pem_rsa.startswith(b"-----BEGIN CERTIFICATE-----")
    assert key_pem_rsa.startswith(b"-----BEGIN PRIVATE KEY-----")

    # Unsupported params raises ValueError
    with pytest.raises(ValueError):
        generate_self_signed_cert("test_client", key_type="rsa", rsa_key_size=1024)

    with pytest.raises(ValueError):
        generate_self_signed_cert(
            "test_client", key_type="ecdsa", ecdsa_curve="invalid"
        )

    # Invalid country raises ValueError
    with pytest.raises(ValueError):
        generate_self_signed_cert("test_client", key_type="ecdsa", country="GBR")


##############################################################################
def test_file_client_cert_store() -> None:
    """Test FileClientCertificateStore CRUD operations."""

    async def run() -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = FileClientCertificateStore(tmpdir)
            uri = GeminiURI("gemini://example.com/admin/")

            # 1. Initially empty
            creds = await store.get_credentials(uri)
            assert creds is None

            # 2. Create persistent credentials
            cert_path, key_path = await store.create_credentials(uri, transient=False)
            assert cert_path.exists()
            assert key_path.exists()

            # 3. Retrieve them
            retrieved = await store.get_credentials(uri)
            assert retrieved is not None
            assert retrieved[0] == cert_path
            assert retrieved[1] == key_path

            # 4. Check scope matching hierarchy
            sub_uri = GeminiURI("gemini://example.com/admin/subpage/test")
            retrieved_sub = await store.get_credentials(sub_uri)
            assert retrieved_sub is not None
            assert retrieved_sub[0] == cert_path

            # 5. Delete credentials
            deleted = await store.delete_credentials(uri)
            assert deleted is True
            assert not cert_path.exists()
            assert not key_path.exists()

            # 6. Transient credentials
            cert_t, key_t = await store.create_credentials(uri, transient=True)
            assert cert_t.exists()
            assert key_t.exists()
            # Must be retrievable
            retrieved_t = await store.get_credentials(uri)
            assert retrieved_t is not None
            assert retrieved_t[0] == cert_t

            # Close cleans up transient directory/files
            await store.close()
            assert not cert_t.exists()
            assert not key_t.exists()

    asyncio.run(run())


##############################################################################
def test_client_dynamic_cert_load_and_callback(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test client retries requests on status 60 with on_client_certificate_required callback."""

    async def run() -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            ssl_obj = MockSSLObject()

            # 1st request returns 60 Client Certificate Required.
            # 2nd request returns 20 Success (since cert was generated and presented).
            reader1 = MockStreamReader([b"60 Certificate required\r\n"])
            writer1 = MockStreamWriter(ssl_obj)

            reader2 = MockStreamReader([b"20 text/gemini\r\n"])
            reader2.set_body(b"Protected resource content")
            writer2 = MockStreamWriter(ssl_obj)

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

            async def on_cert_required(
                uri: GeminiURI, store: Any
            ) -> Literal["transient"]:
                return "transient"

            # Initialise client with custom cert store and callback
            client = Client(
                verify_mode="off",
                client_cert_store_path=tmpdir,
                on_client_certificate_required=on_cert_required,
            )

            async with client:
                response = await client.request("gemini://example.com/protected")
                assert response.status == StatusCode.SUCCESS
                assert await response.text() == "Protected resource content"
                assert call_count == 2

                # Verify a transient certificate was created
                has_cert = await client.client_cert_store.get_credentials(
                    GeminiURI("gemini://example.com/protected")
                )
                assert has_cert is not None

    asyncio.run(run())
