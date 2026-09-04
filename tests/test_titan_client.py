"""Tests for Client Titan protocol operations (upload and delete)."""

##############################################################################
# Python imports.
import asyncio
import io
from pathlib import Path
from typing import Any

import pytest

##############################################################################
# Local imports.
from wasat import (
    Client,
    RedirectError,
    StatusCode,
    TitanURI,
    URIError,
)


##############################################################################
@pytest.fixture
def mock_server(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Fixture providing a mock stream connection for client testing."""
    state: dict[str, Any] = {
        "sent_request_lines": [],
        "sent_payloads": [],
        "responses_to_send": [],
        "connection_fail": False,
        "write_fail": False,
    }

    class MockReader:
        def __init__(self) -> None:
            self._buffer = bytearray()

        def feed(self, data: bytes) -> None:
            self._buffer.extend(data)

        async def readuntil(self, separator: bytes = b"\r\n") -> bytes:
            sep_idx = self._buffer.find(separator)
            if sep_idx == -1:
                data = bytes(self._buffer)
                self._buffer.clear()
                return data
            data = bytes(self._buffer[: sep_idx + len(separator)])
            self._buffer = self._buffer[sep_idx + len(separator) :]
            return data

        async def read(self, size: int = -1) -> bytes:
            if size == -1 or size >= len(self._buffer):
                data = bytes(self._buffer)
                self._buffer.clear()
                return data
            data = bytes(self._buffer[:size])
            self._buffer = self._buffer[size:]
            return data

    class MockWriter:
        def __init__(self, reader: MockReader) -> None:
            self.reader = reader
            self.transport = MockTransport()
            self.closed = False
            self._request_line_sent = False

        def write(self, data: bytes) -> None:
            if b"\r\n" in data and not self._request_line_sent:
                self._request_line_sent = True
                state["sent_request_lines"].append(
                    data.decode("utf-8", errors="replace")
                )
            else:
                if state["write_fail"]:
                    raise BrokenPipeError("Server closed connection")
                state["sent_payloads"].append(data)

        async def drain(self) -> None:
            if state["sent_payloads"] and state["write_fail"]:
                raise BrokenPipeError("Server closed connection")

        def close(self) -> None:
            self.closed = True

        async def wait_closed(self) -> None:
            self.closed = True

    class MockTransport:
        def get_extra_info(self, name: str) -> Any:
            return None

    async def mock_open_connection(
        host: str, port: int, ssl: Any = None, server_hostname: Any = None
    ) -> tuple[MockReader, MockWriter]:
        if state["connection_fail"]:
            raise OSError("Connection refused")

        reader = MockReader()
        writer = MockWriter(reader)

        if state["responses_to_send"]:
            resp_data = state["responses_to_send"].pop(0)
            reader.feed(resp_data)

        return reader, writer

    monkeypatch.setattr(asyncio, "open_connection", mock_open_connection)
    return state


##############################################################################
class TestTitanClient:
    """Test suite for Client Titan protocol support."""

    def test_upload_bytes(self, mock_server: dict[str, Any]) -> None:
        """Test uploading raw bytes via client.upload."""

        async def run() -> None:
            mock_server["responses_to_send"].append(
                b"20 text/gemini\r\nUpload successful\r\n"
            )

            async with Client(verify_mode="off") as client:
                response = await client.upload(
                    "titan://example.com/upload",
                    b"Hello, Titan!",
                    mime="text/plain",
                    token="auth123",
                )
                assert response.status == StatusCode.SUCCESS
                body = await response.text()
                assert "Upload successful" in body

            assert len(mock_server["sent_request_lines"]) == 1
            req_line = mock_server["sent_request_lines"][0]
            assert "titan://example.com/upload;" in req_line
            assert "size=13" in req_line
            assert "mime=text/plain" in req_line
            assert "token=auth123" in req_line
            assert mock_server["sent_payloads"] == [b"Hello, Titan!"]

        asyncio.run(run())

    def test_upload_string_defaults_text_gemini(
        self, mock_server: dict[str, Any]
    ) -> None:
        """Test uploading string defaults to text/gemini MIME type."""

        async def run() -> None:
            mock_server["responses_to_send"].append(b"20 text/gemini\r\nCreated\r\n")

            async with Client(verify_mode="off") as client:
                response = await client.upload(
                    "titan://example.com/new_page.gmi",
                    "# Hello World\nThis is Gemini content",
                )
                assert response.status == StatusCode.SUCCESS

            req_line = mock_server["sent_request_lines"][0]
            assert "mime=text/gemini" in req_line
            assert "size=" in req_line

        asyncio.run(run())

    def test_upload_path(self, tmp_path: Path, mock_server: dict[str, Any]) -> None:
        """Test uploading file by Path object with MIME inference."""

        async def run() -> None:
            file_path = tmp_path / "document.gmi"
            file_path.write_text("# Document\nContent", encoding="utf-8")

            mock_server["responses_to_send"].append(b"20 text/gemini\r\nOK\r\n")

            async with Client(verify_mode="off") as client:
                response = await client.upload(
                    "titan://example.com/files/doc",
                    file_path,
                )
                assert response.status == StatusCode.SUCCESS

            req_line = mock_server["sent_request_lines"][0]
            assert "mime=text/gemini" in req_line
            assert mock_server["sent_payloads"] == [b"# Document\nContent"]

        asyncio.run(run())

    def test_upload_io_stream(self, mock_server: dict[str, Any]) -> None:
        """Test uploading from BytesIO stream."""

        async def run() -> None:
            data_stream = io.BytesIO(b"Stream data")
            mock_server["responses_to_send"].append(b"20 text/gemini\r\nOK\r\n")

            async with Client(verify_mode="off") as client:
                response = await client.upload(
                    "titan://example.com/stream",
                    data_stream,
                    mime="application/custom",
                )
                assert response.status == StatusCode.SUCCESS

            assert mock_server["sent_payloads"] == [b"Stream data"]

        asyncio.run(run())

    def test_upload_async_iterator(self, mock_server: dict[str, Any]) -> None:
        """Test uploading from an async generator."""

        async def run() -> None:
            async def chunk_generator() -> Any:
                yield b"chunk1"
                yield b"chunk2"

            mock_server["responses_to_send"].append(b"20 text/gemini\r\nOK\r\n")

            async with Client(verify_mode="off") as client:
                response = await client.upload(
                    "titan://example.com/chunks",
                    chunk_generator(),
                )
                assert response.status == StatusCode.SUCCESS

            assert mock_server["sent_payloads"] == [b"chunk1chunk2"]

        asyncio.run(run())

    def test_upload_unsupported_type(self) -> None:
        """Test that unsupported payload types raise TypeError."""

        async def run() -> None:
            async with Client(verify_mode="off") as client:
                with pytest.raises(TypeError, match="Unsupported payload data type"):
                    await client.upload("titan://example.com/test", 12345)  # type: ignore[arg-type]

        asyncio.run(run())

    def test_delete(self, mock_server: dict[str, Any]) -> None:
        """Test client.delete uploads size=0."""

        async def run() -> None:
            mock_server["responses_to_send"].append(b"20 text/gemini\r\nDeleted\r\n")

            async with Client(verify_mode="off") as client:
                response = await client.delete(
                    "titan://example.com/item_to_delete",
                    token="delete_token",
                )
                assert response.status == StatusCode.SUCCESS

            req_line = mock_server["sent_request_lines"][0]
            assert "size=0" in req_line
            assert "token=delete_token" in req_line

        asyncio.run(run())

    def test_broken_pipe_early_server_rejection(
        self, mock_server: dict[str, Any]
    ) -> None:
        """Test that early server rejection during upload is handled gracefully."""

        async def run() -> None:
            mock_server["write_fail"] = True
            mock_server["responses_to_send"].append(b"51 Resource does not exist\r\n")

            async with Client(verify_mode="off") as client:
                response = await client.upload(
                    "titan://example.com/fail",
                    b"Large payload that fails to send",
                )
                assert response.status == StatusCode.NOT_FOUND
                assert response.meta == "Resource does not exist"

        asyncio.run(run())

    def test_upload_redirect_to_titan(self, mock_server: dict[str, Any]) -> None:
        """Test that redirect to another Titan URI re-uploads the payload."""

        async def run() -> None:
            mock_server["responses_to_send"].append(
                b"30 titan://example.com/new_target\r\n"
            )
            mock_server["responses_to_send"].append(
                b"20 text/gemini\r\nSuccess at target\r\n"
            )

            async with Client(verify_mode="off", follow_redirects=True) as client:
                response = await client.upload(
                    "titan://example.com/initial",
                    b"Upload data",
                )
                assert response.status == StatusCode.SUCCESS
                assert len(response.history) == 1
                assert response.history[0].status == StatusCode.TEMPORARY_REDIRECT

        asyncio.run(run())

    def test_upload_redirect_to_gemini(self, mock_server: dict[str, Any]) -> None:
        """Test that redirect to Gemini URI follows via GET."""

        async def run() -> None:
            mock_server["responses_to_send"].append(
                b"30 gemini://example.com/view_page\r\n"
            )
            mock_server["responses_to_send"].append(
                b"20 text/gemini\r\nViewing page\r\n"
            )

            async with Client(verify_mode="off", follow_redirects=True) as client:
                response = await client.upload(
                    "titan://example.com/initial",
                    b"Upload data",
                )
                assert response.status == StatusCode.SUCCESS
                assert response.uri is not None
                assert response.uri.scheme == "gemini"

        asyncio.run(run())

    def test_request_titan_uri(self, mock_server: dict[str, Any]) -> None:
        """Test calling request() with a TitanURI."""

        async def run() -> None:
            mock_server["responses_to_send"].append(b"20 text/gemini\r\nOK\r\n")

            async with Client(verify_mode="off") as client:
                uri = TitanURI("titan://example.com/page")
                response = await client.request(uri)
                assert response.status == StatusCode.SUCCESS

        asyncio.run(run())

    def test_request_titan_uri_with_size_error(self) -> None:
        """Test that calling request() with TitanURI having size > 0 raises URIError."""

        async def run() -> None:
            async with Client(verify_mode="off") as client:
                uri = TitanURI("titan://example.com/page;size=50")
                with pytest.raises(URIError, match="Titan URI specifies size > 0"):
                    await client.request(uri)

        asyncio.run(run())

    def test_upload_ignores_existing_target_parameters(
        self, mock_server: dict[str, Any]
    ) -> None:
        """Test that upload ignores existing parameters on the target URI."""

        async def run() -> None:
            mock_server["responses_to_send"].append(b"20 text/gemini\r\nOK\r\n")

            async with Client(verify_mode="off") as client:
                # Link contains existing parameters that should be ignored
                response = await client.upload(
                    "titan://example.com/upload;size=999;mime=old/mime;token=old_tok;extra=param",
                    b"Hello World",
                    token="my_token",
                )
                assert response.status == StatusCode.SUCCESS

            req_line = mock_server["sent_request_lines"][0]
            assert "size=11" in req_line
            assert "token=my_token" in req_line
            assert "size=999" not in req_line
            assert "old_tok" not in req_line
            assert "old/mime" not in req_line
            assert "extra=param" not in req_line

        asyncio.run(run())

    def test_upload_redirect_ignores_existing_parameters(
        self, mock_server: dict[str, Any]
    ) -> None:
        """Test that following a redirect to a Titan URI ignores all parameters in the redirect URI."""

        async def run() -> None:
            # Server redirects to a Titan URI containing dummy parameters
            mock_server["responses_to_send"].append(
                b"30 titan://example.com/dest;size=999;token=dummy_tok;foo=bar\r\n"
            )
            mock_server["responses_to_send"].append(b"20 text/gemini\r\nUploaded\r\n")

            async with Client(verify_mode="off", follow_redirects=True) as client:
                response = await client.upload(
                    "titan://example.com/initial",
                    b"Payload data",
                    token="valid_token",
                )
                assert response.status == StatusCode.SUCCESS

            # Check the second request line (re-upload to /dest)
            re_upload_req = mock_server["sent_request_lines"][1]
            assert "titan://example.com/dest" in re_upload_req
            assert "size=12" in re_upload_req
            assert "token=valid_token" in re_upload_req
            assert "size=999" not in re_upload_req
            assert "dummy_tok" not in re_upload_req
            assert "foo=bar" not in re_upload_req

        asyncio.run(run())

    def test_delete_does_not_include_dummy_mime(
        self, mock_server: dict[str, Any]
    ) -> None:
        """Test that delete (size=0) does not include a dummy application/octet-stream MIME type."""

        async def run() -> None:
            mock_server["responses_to_send"].append(b"20 text/gemini\r\nDeleted\r\n")

            async with Client(verify_mode="off") as client:
                response = await client.delete(
                    "titan://example.com/item",
                    token="del_token",
                )
                assert response.status == StatusCode.SUCCESS

            req_line = mock_server["sent_request_lines"][0]
            assert "size=0" in req_line
            assert "token=del_token" in req_line
            assert "mime=" not in req_line

        asyncio.run(run())

    def test_request_redirect_to_titan_with_size_raises_redirect_error(
        self, mock_server: dict[str, Any]
    ) -> None:
        """Test that redirect from Gemini to Titan URI with size > 0 in client.request() raises RedirectError."""

        async def run() -> None:
            mock_server["responses_to_send"].append(
                b"30 titan://example.com/upload;size=100\r\n"
            )

            async with Client(verify_mode="off", follow_redirects=True) as client:
                with pytest.raises(
                    RedirectError, match="Redirected from Gemini to Titan URI"
                ):
                    await client.request("gemini://example.com/edit")

        asyncio.run(run())
