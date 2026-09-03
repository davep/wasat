"""Tests for CLI Titan features (--upload, --data, --delete, etc.)."""

##############################################################################
# Python imports.
import asyncio
from pathlib import Path
from typing import Any

import pytest

##############################################################################
# Local imports.
from wasat import Response, StatusCode, TitanURI
from wasat.__main__ import run_cli


##############################################################################
class DummyResponse(Response):
    """Dummy response class for testing the CLI without real network requests."""

    def __init__(
        self,
        status: StatusCode,
        meta: str,
        body: str = "",
        uri: Any = None,
        history: list[Response] | None = None,
        requested_uri: Any = None,
    ) -> None:
        super().__init__(
            status=status,
            meta=meta,
            uri=uri,
            history=history,
            requested_uri=requested_uri,
        )
        self._body = body.encode("utf-8")


##############################################################################
def test_cli_data_upload(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Test CLI --data upload flag."""
    recorded_calls: list[dict[str, Any]] = []

    monkeypatch.setattr(
        "sys.argv",
        [
            "wasat",
            "--data",
            "Hello from CLI",
            "--mime",
            "text/plain",
            "--token",
            "secret123",
            "titan://example.com/upload",
        ],
    )

    async def mock_upload(
        self: Any, uri: Any, data: Any, *, mime: Any = None, token: Any = None
    ) -> DummyResponse:
        recorded_calls.append({"uri": uri, "data": data, "mime": mime, "token": token})
        return DummyResponse(
            StatusCode.SUCCESS,
            "text/gemini",
            "Data uploaded successfully!",
            uri=TitanURI("titan://example.com/upload"),
        )

    monkeypatch.setattr("wasat.Client.upload", mock_upload)

    asyncio.run(run_cli())

    assert len(recorded_calls) == 1
    assert recorded_calls[0]["data"] == "Hello from CLI"
    assert recorded_calls[0]["mime"] == "text/plain"
    assert recorded_calls[0]["token"] == "secret123"

    captured = capsys.readouterr()
    assert "Data uploaded successfully!" in captured.out


def test_cli_file_upload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Test CLI --upload FILE flag."""
    test_file = tmp_path / "upload_me.gmi"
    test_file.write_text("# Test file content", encoding="utf-8")

    recorded_calls: list[dict[str, Any]] = []

    monkeypatch.setattr(
        "sys.argv",
        [
            "wasat",
            "-u",
            str(test_file),
            "titan://example.com/file",
        ],
    )

    async def mock_upload(
        self: Any, uri: Any, data: Any, *, mime: Any = None, token: Any = None
    ) -> DummyResponse:
        recorded_calls.append({"uri": uri, "data": data, "mime": mime, "token": token})
        return DummyResponse(
            StatusCode.SUCCESS,
            "text/gemini",
            "File uploaded!",
            uri=TitanURI("titan://example.com/file"),
        )

    monkeypatch.setattr("wasat.Client.upload", mock_upload)

    asyncio.run(run_cli())

    assert len(recorded_calls) == 1
    assert recorded_calls[0]["data"] == test_file

    captured = capsys.readouterr()
    assert "File uploaded!" in captured.out


def test_cli_file_upload_not_found(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Test CLI --upload with non-existent file."""
    monkeypatch.setattr(
        "sys.argv",
        [
            "wasat",
            "-u",
            "/path/to/nonexistent/file.gmi",
            "titan://example.com/file",
        ],
    )

    with pytest.raises(SystemExit) as exit_info:
        asyncio.run(run_cli())

    assert exit_info.value.code == 1
    captured = capsys.readouterr()
    assert "Error: Upload file not found" in captured.err


def test_cli_delete(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Test CLI --delete flag."""
    recorded_calls: list[dict[str, Any]] = []

    monkeypatch.setattr(
        "sys.argv",
        [
            "wasat",
            "--delete",
            "--token",
            "del_tok",
            "titan://example.com/delete_item",
        ],
    )

    async def mock_delete(self: Any, uri: Any, *, token: Any = None) -> DummyResponse:
        recorded_calls.append({"uri": uri, "token": token})
        return DummyResponse(
            StatusCode.SUCCESS,
            "text/gemini",
            "Deleted successfully",
            uri=TitanURI("titan://example.com/delete_item"),
        )

    monkeypatch.setattr("wasat.Client.delete", mock_delete)

    asyncio.run(run_cli())

    assert len(recorded_calls) == 1
    assert recorded_calls[0]["token"] == "del_tok"

    captured = capsys.readouterr()
    assert "Deleted successfully" in captured.out
