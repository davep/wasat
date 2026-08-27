"""Tests for Response class and body streaming."""

import asyncio
from pathlib import Path

import pytest

from wasat import GeminiURI, ProtocolError, Response, StatusCode


class MockStreamReader:
    """Mock StreamReader for testing async body reads."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.offset = 0
        self.closed = False

    async def read(self, size: int = -1) -> bytes:
        if self.offset >= len(self.data):
            return b""
        if size == -1:
            chunk = self.data[self.offset :]
            self.offset = len(self.data)
            return chunk
        else:
            chunk = self.data[self.offset : self.offset + size]
            self.offset += len(chunk)
            return chunk

    async def close(self) -> None:
        self.closed = True


class TestResponse:
    """Test suite for the Response class."""

    def test_mime_parsing(self) -> None:
        """Test MIME type, content type, and charset parsing."""
        # Success with empty meta defaults to text/gemini
        response_default = Response(StatusCode.SUCCESS, "")
        assert response_default.mime_type == "text/gemini; charset=utf-8"
        assert response_default.content_type == "text/gemini"
        assert response_default.charset == "utf-8"

    def test_uri_property(self) -> None:
        """Test that the uri property is correctly exposed and returned."""
        uri = GeminiURI("gemini://example.com/foo")
        response = Response(StatusCode.SUCCESS, "", uri=uri)
        assert response.uri == uri
        assert response.uri.host == "example.com"
        assert response.uri.path == "/foo"

        # Defaults to None
        response_without_uri = Response(StatusCode.SUCCESS, "")
        assert response_without_uri.uri is None

        # Success with custom MIME type and charset
        response_custom_mime = Response(
            StatusCode.SUCCESS, "text/plain; charset=iso-8859-1; foo=bar"
        )
        assert (
            response_custom_mime.mime_type == "text/plain; charset=iso-8859-1; foo=bar"
        )
        assert response_custom_mime.content_type == "text/plain"
        assert response_custom_mime.charset == "iso-8859-1"

        # Non-success code has no MIME type
        response_not_found = Response(StatusCode.NOT_FOUND, "Resource not found")
        assert response_not_found.mime_type == ""
        assert response_not_found.content_type == ""

    def test_read_body_all(self) -> None:
        """Test reading the entire response body."""

        async def run() -> None:
            data = b"Hello, Gemini!"
            reader = MockStreamReader(data)
            response = Response(StatusCode.SUCCESS, "", reader)

            # Check raw bytes
            body = await response.read()
            assert body == data

            # Repeated read returns cached body
            assert await response.read() == data

        asyncio.run(run())

    def test_read_body_text(self) -> None:
        """Test reading the response body as text."""

        async def run() -> None:
            # Test default UTF-8
            reader1 = MockStreamReader("αβγ".encode())
            response_utf8 = Response(StatusCode.SUCCESS, "", reader1)
            assert await response_utf8.text() == "αβγ"

            # Test custom charset (e.g. latin-1)
            reader2 = MockStreamReader("hello".encode("latin-1"))
            response_latin1 = Response(
                StatusCode.SUCCESS, "text/plain; charset=latin-1", reader2
            )
            assert await response_latin1.text() == "hello"

            # Test decode failure
            reader3 = MockStreamReader(b"\xff\xff")
            response_invalid = Response(StatusCode.SUCCESS, "", reader3)
            with pytest.raises(ProtocolError):
                await response_invalid.text()

        asyncio.run(run())

    def test_iter_chunks(self) -> None:
        """Test streaming chunks from response body."""

        async def run() -> None:
            data = b"abcdefgh"
            reader = MockStreamReader(data)
            response = Response(StatusCode.SUCCESS, "", reader)

            chunks = []
            async for chunk in response.iter_chunks(chunk_size=3):
                chunks.append(chunk)

            assert chunks == [b"abc", b"def", b"gh"]

        asyncio.run(run())

    def test_async_context_manager(self) -> None:
        """Test that Response behaves as an async context manager and closes."""

        async def run() -> None:
            reader = MockStreamReader(b"data")
            async with Response(StatusCode.SUCCESS, "", reader) as response:
                assert await response.read() == b"data"
                assert not reader.closed

            assert reader.closed

        asyncio.run(run())

    def test_history_and_requested_uri(self) -> None:
        """Test that history and requested_uri properties are correctly exposed."""
        uri = GeminiURI("gemini://example.com/foo")
        requested_uri = GeminiURI("gemini://example.com/original")

        # Test default values.
        default_response = Response(StatusCode.SUCCESS, "")
        assert default_response.history == []
        assert default_response.requested_uri is None

        # Test customised values.
        history_response = Response(
            StatusCode.TEMPORARY_REDIRECT, "gemini://example.com/foo"
        )
        response = Response(
            StatusCode.SUCCESS,
            "",
            uri=uri,
            history=[history_response],
            requested_uri=requested_uri,
        )
        assert response.history == [history_response]
        assert response.requested_uri == requested_uri

    def test_client_cert_properties(self, tmp_path: Path) -> None:
        """Test client_cert_path, client_key_path, client_cert_used, and direct client_cert."""
        from wasat import ClientCertificate, generate_self_signed_cert

        # Test default values.
        default_response = Response(StatusCode.SUCCESS, "")
        assert default_response.client_cert_path is None
        assert default_response.client_key_path is None
        assert default_response.client_cert is None
        assert not default_response.client_cert_used

        # Test customised path values.
        cert_path = tmp_path / "client.crt"
        key_path = tmp_path / "client.key"
        response = Response(
            StatusCode.SUCCESS,
            "",
            client_cert_path=cert_path,
            client_key_path=key_path,
        )
        assert response.client_cert_path == cert_path
        assert response.client_key_path == key_path
        assert response.client_cert_used

        # Non-existent file returns None gracefully for client_cert
        assert response.client_cert is None

        # Test passing ClientCertificate instance directly
        cert_pem, key_pem = generate_self_signed_cert(common_name="direct.example.com")
        cert = ClientCertificate.from_pem(cert_pem, key_pem=key_pem)
        direct_response = Response(StatusCode.SUCCESS, "", client_cert=cert)
        assert direct_response.client_cert is cert
        assert direct_response.client_cert_used
        assert direct_response.client_cert.subject_common_name == "direct.example.com"

    def test_client_cert_lazy_property(self, tmp_path: Path) -> None:
        """Test that client_cert lazily loads and caches the ClientCertificate instance."""
        from wasat import ClientCertificate, generate_self_signed_cert

        cert_pem, key_pem = generate_self_signed_cert(common_name="lazy.client.com")
        cert_path = tmp_path / "client.pem"
        cert_path.write_bytes(cert_pem + b"\n" + key_pem)

        response = Response(StatusCode.SUCCESS, "", client_cert_path=cert_path)
        assert response._client_cert is None

        client_certificate = response.client_cert
        assert isinstance(client_certificate, ClientCertificate)
        assert client_certificate.subject_common_name == "lazy.client.com"
        assert response.client_cert is client_certificate

    def test_server_cert_properties(self) -> None:
        """Test server_cert_der, server_cert_fingerprint, and verification_method properties."""
        # Test default values.
        default_response = Response(StatusCode.SUCCESS, "")
        assert default_response.server_cert_der is None
        assert default_response.server_cert_fingerprint is None
        assert default_response.verification_method is None

        # Test populated values.
        cert_der = b"mock_server_cert_der_bytes"
        response = Response(
            StatusCode.SUCCESS,
            "",
            server_cert_der=cert_der,
            verification_method="ca",
        )
        assert response.server_cert_der == cert_der
        assert response.verification_method == "ca"
        assert response.server_cert_fingerprint is not None
        assert len(response.server_cert_fingerprint) == 64

    def test_server_cert_lazy_property(self) -> None:
        """Test that server_cert lazily loads and caches the ServerCertificate instance."""
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization

        from wasat import ServerCertificate, generate_self_signed_cert

        default_response = Response(StatusCode.SUCCESS, "")
        assert default_response.server_cert is None

        cert_pem, _ = generate_self_signed_cert(common_name="lazy.example.com")
        cert_x509 = x509.load_pem_x509_certificate(cert_pem)
        der_bytes = cert_x509.public_bytes(serialization.Encoding.DER)

        response = Response(StatusCode.SUCCESS, "", server_cert_der=der_bytes)
        assert response._server_cert is None

        server_certificate = response.server_cert
        assert isinstance(server_certificate, ServerCertificate)
        assert server_certificate.subject_common_name == "lazy.example.com"
        assert response.server_cert is server_certificate


### test_response.py ends here
