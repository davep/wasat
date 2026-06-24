"""Tests for the Wasat CLI entry point."""

from __future__ import annotations

# Python imports.
import asyncio
from getpass import getpass
from typing import Any

import pytest

from wasat import GeminiURI, StatusCode
from wasat.__main__ import run_cli


class DummyResponse:
    """A dummy Response object for testing."""

    def __init__(
        self,
        status: StatusCode,
        meta: str,
        text_content: str = "",
        uri: GeminiURI | None = None,
        history: list[Any] | None = None,
        requested_uri: GeminiURI | None = None,
    ) -> None:
        """Initialise dummy response.

        Args:
            status: The status code of response.
            meta: The meta string.
            text_content: The mock text body.
            uri: The Gemini URI of response.
            history: Optional redirection history.
            requested_uri: Optional originally requested URI.
        """
        self.status = status
        self.meta = meta
        self._text_content = text_content
        self.uri = uri
        self.history = history if history is not None else []
        self.requested_uri = requested_uri

    async def text(self) -> str:
        """Get the text body.

        Returns:
            Mock text body.
        """
        return self._text_content

    async def close(self) -> None:
        """Close the response."""
        pass

    async def __aenter__(self) -> DummyResponse:
        """Enter context manager.

        Returns:
            The DummyResponse instance.
        """
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Exit context manager."""
        pass


def test_cli_input_handling(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Test that INPUT status (10) prompts the user and repeats the request.

    Args:
        monkeypatch: Pytest monkeypatch fixture.
        capsys: Pytest capture stdout/stderr fixture.
    """
    monkeypatch.setattr("sys.argv", ["wasat", "gemini://example.com/ask"])

    # First request returns status 10 (INPUT) with prompt "Name"
    # Second request returns status 20 (SUCCESS)
    resp1 = DummyResponse(StatusCode.INPUT, "Enter name")
    resp2 = DummyResponse(StatusCode.SUCCESS, "text/gemini", "Hello Dave!")

    requests = [resp1, resp2]
    call_index = 0
    requested_uris: list[Any] = []

    async def mock_request(self: Any, uri: Any) -> DummyResponse:
        nonlocal call_index
        requested_uris.append(uri)
        resp = requests[call_index]
        call_index += 1
        return resp

    monkeypatch.setattr("wasat.Client.request", mock_request)

    # Mock asyncio.to_thread to return mock user input when called with input
    async def mock_to_thread(func: Any, *args: Any, **kwargs: Any) -> str:
        if func == input:
            assert args[0] == "Enter name: "
            return "Dave"
        return ""

    monkeypatch.setattr("wasat.__main__.to_thread", mock_to_thread)

    asyncio.run(run_cli())

    captured = capsys.readouterr()
    assert "Hello Dave!" in captured.out
    assert len(requested_uris) == 2
    # Verify the second request had the query parameter
    assert str(requested_uris[1]) == "gemini://example.com/ask?Dave"


def test_cli_sensitive_input_handling(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Test that SENSITIVE_INPUT status (11) prompts the user securely and repeats the request.

    Args:
        monkeypatch: Pytest monkeypatch fixture.
        capsys: Pytest capture stdout/stderr fixture.
    """
    monkeypatch.setattr("sys.argv", ["wasat", "gemini://example.com/secret"])

    resp1 = DummyResponse(StatusCode.SENSITIVE_INPUT, "Password")
    resp2 = DummyResponse(StatusCode.SUCCESS, "text/gemini", "Success page")

    requests = [resp1, resp2]
    call_index = 0
    requested_uris: list[Any] = []

    async def mock_request(self: Any, uri: Any) -> DummyResponse:
        nonlocal call_index
        requested_uris.append(uri)
        resp = requests[call_index]
        call_index += 1
        return resp

    monkeypatch.setattr("wasat.Client.request", mock_request)

    async def mock_to_thread(func: Any, *args: Any, **kwargs: Any) -> str:
        if func == getpass:
            assert args[0] == "Password: "
            return "secret123"
        return ""

    monkeypatch.setattr("wasat.__main__.to_thread", mock_to_thread)

    asyncio.run(run_cli())

    captured = capsys.readouterr()
    assert "Success page" in captured.out
    assert len(requested_uris) == 2
    assert str(requested_uris[1]) == "gemini://example.com/secret?secret123"


def test_cli_input_interrupted(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Test that EOFError during user input causes a clean exit.

    Args:
        monkeypatch: Pytest monkeypatch fixture.
        capsys: Pytest capture stdout/stderr fixture.
    """
    monkeypatch.setattr("sys.argv", ["wasat", "gemini://example.com/ask"])

    resp1 = DummyResponse(StatusCode.INPUT, "Enter name")

    async def mock_request(self: Any, uri: Any) -> DummyResponse:
        return resp1

    monkeypatch.setattr("wasat.Client.request", mock_request)

    async def mock_to_thread(func: Any, *args: Any, **kwargs: Any) -> str:
        raise EOFError()

    monkeypatch.setattr("wasat.__main__.to_thread", mock_to_thread)

    with pytest.raises(SystemExit) as exc_info:
        asyncio.run(run_cli())

    assert exc_info.value.code == 1


def test_cli_verbose_output(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Test that CLI with --verbose option prints the URI and response details.

    Args:
        monkeypatch: Pytest monkeypatch fixture.
        capsys: Pytest capture stdout/stderr fixture.
    """
    monkeypatch.setattr("sys.argv", ["wasat", "-v", "gemini://example.com/index.gmi"])

    uri = GeminiURI("gemini://example.com/index.gmi")
    resp = DummyResponse(StatusCode.SUCCESS, "text/gemini", "Hello verbose!", uri=uri)

    async def mock_request(self: Any, uri: Any) -> DummyResponse:
        return resp

    monkeypatch.setattr("wasat.Client.request", mock_request)

    asyncio.run(run_cli())

    captured = capsys.readouterr()
    assert "--- Gemini Response ---" in captured.out
    assert "URI: gemini://example.com/index.gmi" in captured.out
    assert "Status: 20 (SUCCESS)" in captured.out
    assert "Meta: text/gemini" in captured.out
    assert "Hello verbose!" in captured.out


def test_cli_verbose_output_with_redirect(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Test that CLI with --verbose option prints requested URI and history on redirects.

    Args:
        monkeypatch: Pytest monkeypatch fixture.
        capsys: Pytest capture stdout/stderr fixture.
    """
    monkeypatch.setattr("sys.argv", ["wasat", "-v", "gemini://example.com/redirect"])

    requested_uri = GeminiURI("gemini://example.com/redirect")
    final_uri = GeminiURI("gemini://example.com/target")
    hist_resp = DummyResponse(
        StatusCode.TEMPORARY_REDIRECT,
        "gemini://example.com/target",
        uri=requested_uri,
        requested_uri=requested_uri,
    )
    resp = DummyResponse(
        StatusCode.SUCCESS,
        "text/gemini",
        "Hello redirect verbose!",
        uri=final_uri,
        history=[hist_resp],
        requested_uri=requested_uri,
    )

    async def mock_request(self: Any, uri: Any) -> DummyResponse:
        return resp

    monkeypatch.setattr("wasat.Client.request", mock_request)

    asyncio.run(run_cli())

    captured = capsys.readouterr()
    assert "--- Gemini Response ---" in captured.out
    assert "Requested URI: gemini://example.com/redirect" in captured.out
    assert "Redirections:" in captured.out
    assert (
        "  gemini://example.com/redirect -> gemini://example.com/target" in captured.out
    )
    assert "URI: gemini://example.com/target" in captured.out
    assert "Status: 20 (SUCCESS)" in captured.out
    assert "Meta: text/gemini" in captured.out
    assert "Hello redirect verbose!" in captured.out
