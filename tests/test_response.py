"""Tests for Response class and body streaming."""

import asyncio

import pytest

from wasat import GeminiURI, ProtocolError, Response, StatusCode


class MockStreamReader:
    """Mock StreamReader for testing async body reads."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.offset = 0
        self.closed = False

    async def read(self, n: int = -1) -> bytes:
        if self.offset >= len(self.data):
            return b""
        if n == -1:
            chunk = self.data[self.offset :]
            self.offset = len(self.data)
            return chunk
        else:
            chunk = self.data[self.offset : self.offset + n]
            self.offset += len(chunk)
            return chunk

    async def close(self) -> None:
        self.closed = True


class TestResponse:
    """Test suite for the Response class."""

    def test_mime_parsing(self) -> None:
        """Test MIME type, content type, and charset parsing."""
        # Success with empty meta defaults to text/gemini
        r1 = Response(StatusCode.SUCCESS, "")
        assert r1.mime_type == "text/gemini; charset=utf-8"
        assert r1.content_type == "text/gemini"
        assert r1.charset == "utf-8"

    def test_uri_property(self) -> None:
        """Test that the uri property is correctly exposed and returned."""
        uri = GeminiURI("gemini://example.com/foo")
        r = Response(StatusCode.SUCCESS, "", uri=uri)
        assert r.uri == uri
        assert r.uri.host == "example.com"
        assert r.uri.path == "/foo"

        # Defaults to None
        r_none = Response(StatusCode.SUCCESS, "")
        assert r_none.uri is None

        # Success with custom MIME type and charset
        r2 = Response(StatusCode.SUCCESS, "text/plain; charset=iso-8859-1; foo=bar")
        assert r2.mime_type == "text/plain; charset=iso-8859-1; foo=bar"
        assert r2.content_type == "text/plain"
        assert r2.charset == "iso-8859-1"

        # Non-success code has no MIME type
        r3 = Response(StatusCode.NOT_FOUND, "Resource not found")
        assert r3.mime_type == ""
        assert r3.content_type == ""

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
            r1 = Response(StatusCode.SUCCESS, "", reader1)
            assert await r1.text() == "αβγ"

            # Test custom charset (e.g. latin-1)
            reader2 = MockStreamReader("hello".encode("latin-1"))
            r2 = Response(StatusCode.SUCCESS, "text/plain; charset=latin-1", reader2)
            assert await r2.text() == "hello"

            # Test decode failure
            reader3 = MockStreamReader(b"\xff\xff")
            r3 = Response(StatusCode.SUCCESS, "", reader3)
            with pytest.raises(ProtocolError):
                await r3.text()

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
            async with Response(StatusCode.SUCCESS, "", reader) as r:
                assert await r.read() == b"data"
                assert not reader.closed

            assert reader.closed

        asyncio.run(run())


### test_response.py ends here
