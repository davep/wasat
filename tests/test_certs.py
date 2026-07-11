"""Tests for client certificate generation, store, and retry logic."""

import asyncio
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

import pytest
from cryptography import x509

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
        "example.com:1965/foo/bar/baz.gmi/",
        "example.com:1965/foo/bar",
        "example.com:1965/foo/bar/",
        "example.com:1965/foo",
        "example.com:1965/foo/",
        "example.com:1965/",
        "example.com/foo/bar/baz.gmi",
        "example.com/foo/bar/baz.gmi/",
        "example.com/foo/bar",
        "example.com/foo/bar/",
        "example.com/foo",
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

    # Expiry with valid_days=None (9999-12-31)
    cert_pem_none, _ = generate_self_signed_cert("test_client", valid_days=None)
    cert = x509.load_pem_x509_certificate(cert_pem_none)
    try:
        expiry = cert.not_valid_after_utc
    except AttributeError:
        expiry = cert.not_valid_after.replace(tzinfo=UTC)
    assert expiry == datetime(9999, 12, 31, 23, 59, 59, tzinfo=UTC)


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

            # Test credentials with valid_days=None
            cert_path_none, _ = await store.create_credentials(
                GeminiURI("gemini://example.com/none-expiry"),
                transient=False,
                valid_days=None,
            )
            cert_none = x509.load_pem_x509_certificate(cert_path_none.read_bytes())
            try:
                expiry_none = cert_none.not_valid_after_utc
            except AttributeError:
                expiry_none = cert_none.not_valid_after.replace(tzinfo=UTC)
            assert expiry_none == datetime(9999, 12, 31, 23, 59, 59, tzinfo=UTC)

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
                assert response.client_cert_path == has_cert[0]
                assert response.client_cert_used

    asyncio.run(run())


# ############################################################################
def test_exact_vs_parent_scope_matching() -> None:
    """Test exact scope vs parent scope certificate matching."""

    async def run() -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = FileClientCertificateStore(tmpdir)

            # Register a certificate at /private (no trailing slash)
            uri_parent = GeminiURI("gemini://example.com/private")
            cert_path, key_path = await store.create_credentials(
                uri_parent, transient=False
            )

            # 1. Querying /private/r1/r2 should return the certificate
            uri_sub = GeminiURI("gemini://example.com/private/r1/r2")
            creds = await store.get_credentials(uri_sub)
            assert creds is not None
            assert creds[0] == cert_path

            # 2. Querying exact credentials for /private should return True
            assert await store.has_exact_credentials(uri_parent) is True

            # 3. Querying exact credentials for /private/r1/r2 should return False
            assert await store.has_exact_credentials(uri_sub) is False

            # 4. Register a certificate at /private/r1/r2 (exact match for a subpath)
            cert_sub_path, _ = await store.create_credentials(uri_sub, transient=False)
            assert await store.has_exact_credentials(uri_sub) is True

            # Querying /private/r1/r2 should return the more specific sub-certificate
            creds_new = await store.get_credentials(uri_sub)
            assert creds_new is not None
            assert creds_new[0] == cert_sub_path

    asyncio.run(run())


##############################################################################
def test_client_cert_with_redirect(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test redirection combined with client certificate requests."""

    async def run() -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            ssl_obj = MockSSLObject()

            # Connection sequence:
            # 1. First request to /initial -> returns 60 (Certificate required)
            # 2. Retry to /initial (with cert 1) -> returns 30 /redirected
            # 3. Request to /redirected -> returns 60 (Certificate required)
            # 4. Retry to /redirected (with cert 2) -> returns 20 Success
            reader1 = MockStreamReader([b"60 Certificate required for initial\r\n"])
            writer1 = MockStreamWriter(ssl_obj)

            reader2 = MockStreamReader([b"30 gemini://example.com/redirected\r\n"])
            writer2 = MockStreamWriter(ssl_obj)

            reader3 = MockStreamReader([b"60 Certificate required for redirected\r\n"])
            writer3 = MockStreamWriter(ssl_obj)

            reader4 = MockStreamReader([b"20 text/gemini\r\n"])
            reader4.set_body(b"Success Content")
            writer4 = MockStreamWriter(ssl_obj)

            connections = [
                (reader1, writer1),
                (reader2, writer2),
                (reader3, writer3),
                (reader4, writer4),
            ]
            call_count = 0
            ssl_contexts_used = []

            async def mock_open_connection(
                *args: Any, **kwargs: Any
            ) -> tuple[MockStreamReader, MockStreamWriter]:
                nonlocal call_count
                conn = connections[call_count]
                call_count += 1
                if "ssl" in kwargs:
                    ssl_contexts_used.append(kwargs["ssl"])
                return conn

            monkeypatch.setattr(asyncio, "open_connection", mock_open_connection)

            callback_uris = []

            async def on_cert_required(
                uri: GeminiURI, store: Any
            ) -> Literal["transient"]:
                callback_uris.append(uri)
                return "transient"

            client = Client(
                verify_mode="off",
                client_cert_store_path=tmpdir,
                on_client_certificate_required=on_cert_required,
            )

            async with client:
                response = await client.request("gemini://example.com/initial")
                assert response.status == StatusCode.SUCCESS
                assert await response.text() == "Success Content"
                assert call_count == 4

                # Check the URIs for which the callback was triggered
                assert callback_uris == [
                    GeminiURI("gemini://example.com/initial"),
                    GeminiURI("gemini://example.com/redirected"),
                ]

    asyncio.run(run())


##############################################################################
def test_client_cert_parent_scope_redirect(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test that a certificate stored under a parent scope is used for redirects automatically."""

    async def run() -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            ssl_obj = MockSSLObject()

            # Connection sequence:
            # 1. Request to /initial -> returns 30 /redirected (using client cert)
            # 2. Request to /redirected -> returns 20 Success (using client cert)
            reader1 = MockStreamReader([b"30 gemini://example.com/redirected\r\n"])
            writer1 = MockStreamWriter(ssl_obj)

            reader2 = MockStreamReader([b"20 text/gemini\r\n"])
            reader2.set_body(b"Success Content")
            writer2 = MockStreamWriter(ssl_obj)

            connections = [
                (reader1, writer1),
                (reader2, writer2),
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

            client = Client(
                verify_mode="off",
                client_cert_store_path=tmpdir,
            )

            # Pre-populate store with a certificate for the host scope (example.com:1965/)
            host_uri = GeminiURI("gemini://example.com/")
            cert_path, key_path = await client.client_cert_store.create_credentials(
                host_uri, transient=False
            )

            async with client:
                response = await client.request("gemini://example.com/initial")
                assert response.status == StatusCode.SUCCESS
                assert await response.text() == "Success Content"
                assert call_count == 2

                # Verify that the same certificate was used for the initial request and the redirected request
                assert len(response.history) == 1
                assert response.history[0].client_cert_used is True
                assert response.history[0].client_cert_path == cert_path

                assert response.client_cert_used is True
                assert response.client_cert_path == cert_path

    asyncio.run(run())


##############################################################################
def test_client_cert_redirect_sibling_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test that a certificate generated for a specific path (e.g. /join) is
    automatically reused for a redirect target on a sibling path (e.g. /davep)
    on the same host/port.
    """

    async def run() -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            ssl_obj = MockSSLObject()

            # Connection sequence:
            # 1. First request to /join -> returns 60 (Certificate required)
            # 2. Retry to /join (with cert) -> returns 30 /davep
            # 3. Request to /davep -> returns 20 Success
            reader1 = MockStreamReader([b"60 Certificate required for join\r\n"])
            writer1 = MockStreamWriter(ssl_obj)

            reader2 = MockStreamReader([b"30 gemini://example.com/davep\r\n"])
            writer2 = MockStreamWriter(ssl_obj)

            reader3 = MockStreamReader([b"20 text/gemini\r\n"])
            reader3.set_body(b"Dave's Page")
            writer3 = MockStreamWriter(ssl_obj)

            connections = [
                (reader1, writer1),
                (reader2, writer2),
                (reader3, writer3),
            ]
            call_count = 0
            ssl_contexts_used = []

            async def mock_open_connection(
                *args: Any, **kwargs: Any
            ) -> tuple[MockStreamReader, MockStreamWriter]:
                nonlocal call_count
                conn = connections[call_count]
                call_count += 1
                if "ssl" in kwargs:
                    ssl_contexts_used.append(kwargs["ssl"])
                return conn

            monkeypatch.setattr(asyncio, "open_connection", mock_open_connection)

            async def on_cert_required(
                uri: GeminiURI, store: Any
            ) -> Literal["transient"]:
                return "transient"

            client = Client(
                verify_mode="off",
                client_cert_store_path=tmpdir,
                on_client_certificate_required=on_cert_required,
            )

            async with client:
                response = await client.request("gemini://example.com/join")
                assert response.status == StatusCode.SUCCESS
                assert await response.text() == "Dave's Page"
                assert call_count == 3

                # The first request was the initial /join without cert.
                # The second request was the retry of /join with cert.
                # The third request was the redirect to /davep, which should reuse the cert.
                assert len(response.history) == 1
                assert response.history[0].client_cert_used is True
                # The final response should have reused the same certificate
                assert response.client_cert_used is True
                assert response.client_cert_path == response.history[0].client_cert_path

    asyncio.run(run())


##############################################################################
def test_register_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test register_credentials CRUD and file copying behavior."""

    async def run() -> None:
        with (
            tempfile.TemporaryDirectory() as tmpdir1,
            tempfile.TemporaryDirectory() as tmpdir2,
        ):
            # Generate a cert in tmpdir1
            store1 = FileClientCertificateStore(tmpdir1)
            uri = GeminiURI("gemini://example.com/join")
            cert_path, key_path = await store1.create_credentials(uri)

            # Register it in store2 (which uses tmpdir2)
            store2 = FileClientCertificateStore(tmpdir2)
            uri2 = GeminiURI("gemini://example.com/davep")
            await store2.register_credentials(
                uri2, cert_path, key_path, transient=False
            )

            # Check that the credentials were copied to store2's directory
            retrieved = await store2.get_credentials(uri2)
            assert retrieved is not None
            c_path, k_path = retrieved
            assert c_path.parent == Path(tmpdir2)
            assert k_path.parent == Path(tmpdir2)
            assert c_path.exists()
            assert k_path.exists()

            # Test transient registration
            uri3 = GeminiURI("gemini://example.com/transient")
            await store2.register_credentials(uri3, cert_path, key_path, transient=True)
            retrieved_transient = await store2.get_credentials(uri3)
            assert retrieved_transient is not None
            assert retrieved_transient[0] == cert_path
            assert retrieved_transient[1] == key_path

            await store2.close()

    asyncio.run(run())


##############################################################################
def test_client_cert_manual_registration_in_callback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test that manual registration in the callback correctly retries with the registered cert."""

    async def run() -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            ssl_obj = MockSSLObject()

            # Connection sequence:
            # 1. Request to /davep -> returns 60 (Certificate required)
            # 2. Retry to /davep (with the registered /join certificate) -> returns 20 Success
            reader1 = MockStreamReader([b"60 Certificate required\r\n"])
            writer1 = MockStreamWriter(ssl_obj)

            reader2 = MockStreamReader([b"20 text/gemini\r\n"])
            reader2.set_body(b"Dave's Content")
            writer2 = MockStreamWriter(ssl_obj)

            connections = [
                (reader1, writer1),
                (reader2, writer2),
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

            client = Client(
                verify_mode="off",
                client_cert_store_path=tmpdir,
            )

            # Pre-populate /join
            join_uri = GeminiURI("gemini://example.com/join")
            cert_path, key_path = await client.client_cert_store.create_credentials(
                join_uri
            )

            async def on_cert_required(
                uri: GeminiURI, store: Any
            ) -> Literal["persistent"]:
                # Retrieve the /join credentials and register them for /davep
                creds = await store.get_credentials(
                    GeminiURI("gemini://example.com/join")
                )
                assert creds is not None
                await store.register_credentials(uri, creds[0], creds[1])
                return "persistent"

            client._on_client_certificate_required = on_cert_required

            async with client:
                response = await client.request("gemini://example.com/davep")
                assert response.status == StatusCode.SUCCESS
                assert await response.text() == "Dave's Content"
                assert call_count == 2
                # The certificate used should be the /join certificate
                assert response.client_cert_used is True
                # It should point to the newly registered path in the store dir
                retrieved_davep = await client.client_cert_store.get_credentials(
                    GeminiURI("gemini://example.com/davep")
                )
                assert retrieved_davep is not None
                assert response.client_cert_path == retrieved_davep[0]

    asyncio.run(run())
