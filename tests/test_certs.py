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
    ClientCertificate,
    FileClientCertificateStore,
    GeminiURI,
    ServerCertificate,
    StatusCode,
    generate_self_signed_cert,
    normalize_scope,
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
    on the same host/port, and is successfully re-bound to the sibling path
    for future direct requests.
    """

    async def run() -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            ssl_obj = MockSSLObject()

            # Connection sequence:
            # 1. First request to /join -> returns 60 (Certificate required)
            # 2. Retry to /join (with cert) -> returns 30 /davep
            # 3. Request to /davep (inherited cert) -> returns 20 Success
            # 4. Direct request to /davep (should automatically reuse the re-bound cert) -> returns 20 Success
            reader1 = MockStreamReader([b"60 Certificate required for join\r\n"])
            writer1 = MockStreamWriter(ssl_obj)

            reader2 = MockStreamReader([b"30 gemini://example.com/davep\r\n"])
            writer2 = MockStreamWriter(ssl_obj)

            reader3 = MockStreamReader([b"20 text/gemini\r\n"])
            reader3.set_body(b"Dave's Page")
            writer3 = MockStreamWriter(ssl_obj)

            reader4 = MockStreamReader([b"20 text/gemini\r\n"])
            reader4.set_body(b"Dave's Page (Direct)")
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

                cert_path = response.client_cert_path

                # Perform a direct request to /davep. It should automatically reuse the cert
                # without requiring a redirect chain or triggering a client cert callback again.
                response2 = await client.request("gemini://example.com/davep")
                assert response2.status == StatusCode.SUCCESS
                assert await response2.text() == "Dave's Page (Direct)"
                assert response2.client_cert_used is True
                assert response2.client_cert_path == cert_path
                assert call_count == 4

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


class TestServerCertificate:
    """Test suite for ServerCertificate wrapper."""

    def test_server_certificate_properties(self) -> None:
        """Test properties of ServerCertificate."""
        from cryptography.hazmat.primitives import serialization

        cert_pem, _ = generate_self_signed_cert(
            common_name="test.example.com", domain="test.example.com"
        )
        cert_x509 = x509.load_pem_x509_certificate(cert_pem)
        der_bytes = cert_x509.public_bytes(serialization.Encoding.DER)

        server_cert = ServerCertificate.from_der(der_bytes)

        assert server_cert.raw_der == der_bytes
        assert server_cert.subject_common_name == "test.example.com"
        assert server_cert.issuer_common_name == "test.example.com"
        assert "CN=test.example.com" in server_cert.subject
        assert "CN=test.example.com" in server_cert.issuer
        assert isinstance(server_cert.not_before, datetime)
        assert isinstance(server_cert.not_after, datetime)
        assert server_cert.subject_alternative_names == ("test.example.com",)
        assert isinstance(server_cert.serial_number, int)
        assert isinstance(server_cert.fingerprint, str)
        assert len(server_cert.fingerprint) == 64
        assert server_cert.is_expired is False
        assert server_cert.is_self_signed is True
        assert server_cert.raw_x509 == cert_x509


##############################################################################
def test_normalize_scope() -> None:
    """Test scope normalisation with various input types and formats."""
    # GeminiURI inputs
    assert normalize_scope(GeminiURI("gemini://example.com")) == "example.com:1965/"
    assert normalize_scope(GeminiURI("gemini://example.com/")) == "example.com:1965/"
    assert (
        normalize_scope(GeminiURI("gemini://example.com/admin/login"))
        == "example.com:1965/admin/login"
    )
    assert (
        normalize_scope(GeminiURI("gemini://example.com:1967/admin/login"))
        == "example.com:1967/admin/login"
    )

    # String inputs
    assert normalize_scope("gemini://example.com") == "example.com:1965/"
    assert normalize_scope("gemini://example.com/foo") == "example.com:1965/foo"
    assert normalize_scope("gemini://example.com:2000/foo") == "example.com:2000/foo"
    assert normalize_scope("example.com") == "example.com:1965/"
    assert normalize_scope("example.com/foo") == "example.com:1965/foo"
    assert normalize_scope("example.com:1965/foo") == "example.com:1965/foo"
    assert normalize_scope("example.com:2000/foo") == "example.com:2000/foo"
    assert normalize_scope("EXAMPLE.COM:1965/Foo") == "example.com:1965/Foo"


##############################################################################
class TestClientCertificate:
    """Test suite for ClientCertificate wrapper."""

    def test_client_certificate_properties_ecdsa(self) -> None:
        """Test properties of ClientCertificate with ECDSA key."""
        cert_pem, key_pem = generate_self_signed_cert(
            common_name="test_user",
            key_type="ecdsa",
            email="test@example.com",
            user_id="usr_42",
            domain="auth.example.com",
            organisation="ACME Corp",
            country="GB",
        )
        client_cert = ClientCertificate(
            cert_pem=cert_pem,
            key_pem=key_pem,
            scopes=["example.com:1965/admin", "example.com:1965/user"],
        )

        assert client_cert.cert_pem == cert_pem
        assert client_cert.raw_pem == cert_pem
        assert client_cert.key_pem == key_pem
        assert client_cert.cert_path is None
        assert client_cert.key_path is None
        assert client_cert.scopes == (
            "example.com:1965/admin",
            "example.com:1965/user",
        )
        assert client_cert.subject_common_name == "test_user"
        assert client_cert.issuer_common_name == "test_user"
        assert client_cert.email == "test@example.com"
        assert client_cert.user_id == "usr_42"
        assert client_cert.organisation == "ACME Corp"
        assert client_cert.country == "GB"
        assert "CN=test_user" in client_cert.subject
        assert "CN=test_user" in client_cert.issuer
        assert isinstance(client_cert.not_before, datetime)
        assert isinstance(client_cert.not_after, datetime)
        assert client_cert.is_expired is False
        assert client_cert.is_self_signed is True
        assert client_cert.subject_alternative_names == ("auth.example.com",)
        assert isinstance(client_cert.serial_number, int)
        assert len(client_cert.fingerprint) == 64
        assert client_cert.key_type == "ecdsa"
        assert client_cert.key_size == 256
        assert isinstance(client_cert.raw_x509, x509.Certificate)
        assert "test_user" in repr(client_cert)

    def test_client_certificate_properties_rsa(self) -> None:
        """Test properties of ClientCertificate with RSA key."""
        cert_pem, key_pem = generate_self_signed_cert(
            common_name="test_rsa_user",
            key_type="rsa",
            rsa_key_size=2048,
        )
        client_cert = ClientCertificate(
            cert_pem=cert_pem,
            key_pem=key_pem,
        )
        assert client_cert.key_type == "rsa"
        assert client_cert.key_size == 2048
        assert client_cert.email is None
        assert client_cert.user_id is None
        assert client_cert.organisation is None
        assert client_cert.country is None

    def test_client_certificate_from_file(self) -> None:
        """Test constructing ClientCertificate from file paths."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cert_pem, key_pem = generate_self_signed_cert("file_user")
            c_path = Path(tmpdir) / "test.crt"
            k_path = Path(tmpdir) / "test.key"
            c_path.write_bytes(cert_pem)
            k_path.write_bytes(key_pem)

            cert = ClientCertificate.from_file(c_path, k_path, scopes=["example.com/"])
            assert cert.cert_path == c_path
            assert cert.key_path == k_path
            assert cert.cert_pem == cert_pem
            assert cert.key_pem == key_pem
            assert cert.scopes == ("example.com/",)
            assert cert.subject_common_name == "file_user"


##############################################################################
class TestClientCertificateStoreManagement:
    """Test suite for certificate store listing, multi-scope, and management methods."""

    def test_create_and_list_standalone_and_multiscope_certificates(
        self,
    ) -> None:
        """Test creating standalone and multi-scope certificates and listing them."""

        async def run() -> None:
            with tempfile.TemporaryDirectory() as tmpdir:
                store = FileClientCertificateStore(tmpdir)

                # Initially empty
                assert await store.list_certificates() == []

                # 1. Create standalone certificate with no scopes
                standalone = await store.create_certificate(
                    name="my_persona",
                    common_name="Dave's Persona",
                    email="dave@example.com",
                )
                assert standalone.subject_common_name == "Dave's Persona"
                assert standalone.email == "dave@example.com"
                assert standalone.scopes == ()
                assert (
                    standalone.cert_path is not None and standalone.cert_path.exists()
                )
                assert standalone.key_path is not None and standalone.key_path.exists()

                # 2. Create multi-scope certificate
                multi = await store.create_certificate(
                    name="shared_identity",
                    scopes=[
                        GeminiURI("gemini://example.com/admin"),
                        "gemini://example.com/user",
                        "station.martinrue.com/davep",
                    ],
                    common_name="Shared Identity",
                )
                assert multi.scopes == (
                    "example.com:1965/admin",
                    "example.com:1965/user",
                    "station.martinrue.com:1965/davep",
                )

                # 3. List certificates
                all_certs = await store.list_certificates()
                assert len(all_certs) == 2

                cert_names = {c.subject_common_name for c in all_certs}
                assert cert_names == {"Dave's Persona", "Shared Identity"}

                # Verify that credentials can be retrieved for all scopes of multi
                creds_admin = await store.get_credentials(
                    GeminiURI("gemini://example.com/admin/settings")
                )
                creds_user = await store.get_credentials(
                    GeminiURI("gemini://example.com/user/profile")
                )
                creds_station = await store.get_credentials(
                    GeminiURI("gemini://station.martinrue.com/davep/feed.gmi")
                )

                assert creds_admin is not None
                assert creds_user is not None
                assert creds_station is not None
                assert creds_admin[0] == multi.cert_path
                assert creds_user[0] == multi.cert_path
                assert creds_station[0] == multi.cert_path

        asyncio.run(run())

    def test_get_certificate_by_various_identifiers(self) -> None:
        """Test get_certificate with URI, scope string, fingerprint, and file path."""

        async def run() -> None:
            with tempfile.TemporaryDirectory() as tmpdir:
                store = FileClientCertificateStore(tmpdir)
                created = await store.create_certificate(
                    name="ident1",
                    scopes=["example.com/forum"],
                    common_name="Forum User",
                )

                # 1. By GeminiURI
                by_uri = await store.get_certificate(
                    GeminiURI("gemini://example.com/forum/topic1")
                )
                assert by_uri is not None
                assert by_uri.subject_common_name == "Forum User"

                # 2. By scope string (with or without port)
                by_scope = await store.get_certificate("example.com:1965/forum")
                assert by_scope is not None
                assert by_scope.subject_common_name == "Forum User"

                by_scope_no_port = await store.get_certificate("example.com/forum")
                assert by_scope_no_port is not None
                assert by_scope_no_port.subject_common_name == "Forum User"

                # 3. By SHA-256 fingerprint
                by_fp = await store.get_certificate(created.fingerprint)
                assert by_fp is not None
                assert by_fp.subject_common_name == "Forum User"

                # 4. By Path and filename
                assert created.cert_path is not None
                by_path = await store.get_certificate(created.cert_path)
                assert by_path is not None
                assert by_path.subject_common_name == "Forum User"

                by_filename = await store.get_certificate(created.cert_path.name)
                assert by_filename is not None
                assert by_filename.subject_common_name == "Forum User"

                # Nonexistent identifier
                assert await store.get_certificate("unknown.domain.org") is None
                assert await store.get_certificate("0" * 64) is None

        asyncio.run(run())

    def test_associate_and_disassociate_scope(self) -> None:
        """Test associating new scopes to an existing certificate and disassociating them."""

        async def run() -> None:
            with tempfile.TemporaryDirectory() as tmpdir:
                store = FileClientCertificateStore(tmpdir)

                # Create certificate for scope 1
                cert = await store.create_certificate(
                    name="user_cert",
                    scopes=["example.com/page1"],
                    common_name="User Cert",
                )

                # Associate scope 2 using ClientCertificate object
                await store.associate_scope(cert, "example.com/page2")

                # Associate scope 3 using fingerprint
                await store.associate_scope(
                    cert.fingerprint, GeminiURI("gemini://other.org/app")
                )

                # Verify all scopes resolve to the same certificate files
                c1 = await store.get_credentials(
                    GeminiURI("gemini://example.com/page1")
                )
                c2 = await store.get_credentials(
                    GeminiURI("gemini://example.com/page2")
                )
                c3 = await store.get_credentials(GeminiURI("gemini://other.org/app"))

                assert c1 is not None and c2 is not None and c3 is not None
                assert c1[0] == c2[0] == c3[0] == cert.cert_path
                assert c1[1] == c2[1] == c3[1] == cert.key_path

                # Disassociate scope 2
                removed = await store.disassociate_scope("example.com/page2")
                assert removed is True

                # Scope 2 no longer resolves
                assert (
                    await store.get_credentials(GeminiURI("gemini://example.com/page2"))
                    is None
                )

                # Scope 1 and 3 still resolve and file still exists
                assert (
                    await store.get_credentials(GeminiURI("gemini://example.com/page1"))
                    is not None
                )
                assert cert.cert_path is not None and cert.cert_path.exists()

                # Disassociating unknown scope returns False
                assert await store.disassociate_scope("nonexistent.org") is False

                # Associating non-existent cert raises ValueError
                with pytest.raises(ValueError):
                    await store.associate_scope("0" * 64, "some.site.org")

        asyncio.run(run())

    def test_delete_certificate(self) -> None:
        """Test delete_certificate removes files and all associated scopes."""

        async def run() -> None:
            with tempfile.TemporaryDirectory() as tmpdir:
                store = FileClientCertificateStore(tmpdir)

                cert = await store.create_certificate(
                    name="to_delete",
                    scopes=["example.com/a", "example.com/b"],
                    common_name="To Delete",
                )
                cert_path = cert.cert_path
                key_path = cert.key_path
                assert cert_path is not None and cert_path.exists()
                assert key_path is not None and key_path.exists()

                # Delete certificate
                deleted = await store.delete_certificate(cert)
                assert deleted is True

                # Files are removed
                assert not cert_path.exists()
                assert not key_path.exists()

                # Scopes are removed
                assert (
                    await store.get_credentials(GeminiURI("gemini://example.com/a"))
                    is None
                )
                assert (
                    await store.get_credentials(GeminiURI("gemini://example.com/b"))
                    is None
                )
                assert await store.list_certificates() == []

                # Deleting again returns False
                assert await store.delete_certificate(cert) is False

        asyncio.run(run())

    def test_delete_exact_scope_shared_file(self) -> None:
        """Test delete_exact_scope removes the scope and only removes files when last scope is removed."""

        async def run() -> None:
            with tempfile.TemporaryDirectory() as tmpdir:
                store = FileClientCertificateStore(tmpdir)

                cert = await store.create_certificate(
                    name="shared",
                    scopes=["example.com/first", "example.com/second"],
                )
                cert_path = cert.cert_path
                key_path = cert.key_path
                assert cert_path is not None and cert_path.exists()
                assert key_path is not None and key_path.exists()

                # Delete first scope
                deleted_first = await store.delete_exact_scope("example.com/first")
                assert deleted_first is True

                # First scope gone, second scope remains, files still exist
                assert (
                    await store.get_credentials(GeminiURI("gemini://example.com/first"))
                    is None
                )
                assert (
                    await store.get_credentials(
                        GeminiURI("gemini://example.com/second")
                    )
                    is not None
                )
                assert cert_path.exists()

                # Delete second (last) scope
                deleted_second = await store.delete_exact_scope("example.com/second")
                assert deleted_second is True

                # Second scope gone, files now unlinked
                assert (
                    await store.get_credentials(
                        GeminiURI("gemini://example.com/second")
                    )
                    is None
                )
                assert not cert_path.exists()
                assert not key_path.exists()

        asyncio.run(run())

    def test_transient_certificate_management(self) -> None:
        """Test transient certificate lifecycle and management."""

        async def run() -> None:
            with tempfile.TemporaryDirectory() as tmpdir:
                store = FileClientCertificateStore(tmpdir)

                # Create transient certificate with multiple scopes
                trans_cert = await store.create_certificate(
                    name="trans_user",
                    scopes=["example.com/trans1"],
                    transient=True,
                    common_name="Transient User",
                )
                assert (
                    trans_cert.cert_path is not None and trans_cert.cert_path.exists()
                )

                # Appears in list_certificates
                listed = await store.list_certificates()
                assert len(listed) == 1
                assert listed[0].subject_common_name == "Transient User"

                # Associate additional transient scope
                await store.associate_scope(trans_cert, "example.com/trans2")
                assert (
                    await store.get_credentials(
                        GeminiURI("gemini://example.com/trans2")
                    )
                    is not None
                )

                # Disassociate transient scope
                assert await store.disassociate_scope("example.com/trans1") is True
                assert (
                    await store.get_credentials(
                        GeminiURI("gemini://example.com/trans1")
                    )
                    is None
                )

                # Delete transient cert
                deleted = await store.delete_certificate(trans_cert)
                assert deleted is True
                assert not trans_cert.cert_path.exists()

        asyncio.run(run())
