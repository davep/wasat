"""Tests for Response class and body streaming."""

import unittest

from wasat import ProtocolError, Response, StatusCode


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


class TestResponse(unittest.IsolatedAsyncioTestCase):
    """Test suite for the Response class."""

    def test_mime_parsing(self) -> None:
        """Test MIME type, content type, and charset parsing."""
        # Success with empty meta defaults to text/gemini
        r1 = Response(StatusCode.SUCCESS, "")
        self.assertEqual(r1.mime_type, "text/gemini; charset=utf-8")
        self.assertEqual(r1.content_type, "text/gemini")
        self.assertEqual(r1.charset, "utf-8")

        # Success with custom MIME type and charset
        r2 = Response(StatusCode.SUCCESS, "text/plain; charset=iso-8859-1; foo=bar")
        self.assertEqual(r2.mime_type, "text/plain; charset=iso-8859-1; foo=bar")
        self.assertEqual(r2.content_type, "text/plain")
        self.assertEqual(r2.charset, "iso-8859-1")

        # Non-success code has no MIME type
        r3 = Response(StatusCode.NOT_FOUND, "Resource not found")
        self.assertEqual(r3.mime_type, "")
        self.assertEqual(r3.content_type, "")

    async def test_read_body_all(self) -> None:
        """Test reading the entire response body."""
        data = b"Hello, Gemini!"
        reader = MockStreamReader(data)
        response = Response(StatusCode.SUCCESS, "", reader)

        # Check raw bytes
        body = await response.read()
        self.assertEqual(body, data)

        # Repeated read returns cached body
        self.assertEqual(await response.read(), data)

    async def test_read_body_text(self) -> None:
        """Test reading the response body as text."""
        # Test default UTF-8
        reader1 = MockStreamReader("αβγ".encode())
        r1 = Response(StatusCode.SUCCESS, "", reader1)
        self.assertEqual(await r1.text(), "αβγ")

        # Test custom charset (e.g. latin-1)
        reader2 = MockStreamReader("hello".encode("latin-1"))
        r2 = Response(StatusCode.SUCCESS, "text/plain; charset=latin-1", reader2)
        self.assertEqual(await r2.text(), "hello")

        # Test decode failure
        reader3 = MockStreamReader(b"\xff\xff")
        r3 = Response(StatusCode.SUCCESS, "", reader3)
        with self.assertRaises(ProtocolError):
            await r3.text()

    async def test_iter_chunks(self) -> None:
        """Test streaming chunks from response body."""
        data = b"abcdefgh"
        reader = MockStreamReader(data)
        response = Response(StatusCode.SUCCESS, "", reader)

        chunks = []
        async for chunk in response.iter_chunks(chunk_size=3):
            chunks.append(chunk)

        self.assertEqual(chunks, [b"abc", b"def", b"gh"])

    async def test_async_context_manager(self) -> None:
        """Test that Response behaves as an async context manager and closes."""
        reader = MockStreamReader(b"data")
        async with Response(StatusCode.SUCCESS, "", reader) as r:
            self.assertEqual(await r.read(), b"data")
            self.assertFalse(reader.closed)

        self.assertTrue(reader.closed)


### test_response.py ends here
