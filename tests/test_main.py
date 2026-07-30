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
        verification_method: str | None = None,
        server_cert_fingerprint: str | None = None,
        server_cert: Any | None = None,
    ) -> None:
        """Initialise dummy response.

        Args:
            status: The status code of response.
            meta: The meta string.
            text_content: The mock text body.
            uri: The Gemini URI of response.
            history: Optional redirection history.
            requested_uri: Optional originally requested URI.
            verification_method: Optional certificate verification method.
            server_cert_fingerprint: Optional server certificate fingerprint.
            server_cert: Optional server certificate object.
        """
        self.status = status
        self.meta = meta
        self._text_content = text_content
        self.uri = uri
        self.history = history if history is not None else []
        self.requested_uri = requested_uri
        self.verification_method = verification_method
        self.server_cert_fingerprint = server_cert_fingerprint
        self.server_cert = server_cert

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
    resp = DummyResponse(
        StatusCode.SUCCESS,
        "text/gemini",
        "Hello verbose!",
        uri=uri,
        verification_method="tofu",
        server_cert_fingerprint="abc123def456",
    )

    async def mock_request(self: Any, uri: Any) -> DummyResponse:
        return resp

    monkeypatch.setattr("wasat.Client.request", mock_request)

    asyncio.run(run_cli())

    captured = capsys.readouterr()
    assert "--- Gemini Response ---" in captured.out
    assert "URI: gemini://example.com/index.gmi" in captured.out
    assert "Verification Method: tofu" in captured.out
    assert "Certificate Fingerprint: sha256:abc123def456" in captured.out
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


@pytest.mark.parametrize("verify_mode", ["tofu", "ca", "off"])
def test_cli_verify_mode_option(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    verify_mode: str,
) -> None:
    """Test that CLI --verify-mode passes the chosen verification mode to Client.

    Args:
        monkeypatch: Pytest monkeypatch fixture.
        capsys: Pytest capture stdout/stderr fixture.
        verify_mode: The verification mode parameter value to test.
    """
    monkeypatch.setattr(
        "sys.argv",
        ["wasat", "--verify-mode", verify_mode, "gemini://example.com/index.gmi"],
    )

    uri = GeminiURI("gemini://example.com/index.gmi")
    resp = DummyResponse(
        StatusCode.SUCCESS, "text/gemini", "Hello verify mode!", uri=uri
    )

    created_client_verify_mode: str | None = None

    class MockClient:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            nonlocal created_client_verify_mode
            created_client_verify_mode = kwargs.get("verify_mode")

        async def request(self, uri: Any) -> DummyResponse:
            return resp

        async def __aenter__(self) -> MockClient:
            return self

        async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
            pass

    monkeypatch.setattr("wasat.__main__.Client", MockClient)

    asyncio.run(run_cli())

    assert created_client_verify_mode == verify_mode
    captured = capsys.readouterr()
    assert "Hello verify mode!" in captured.out


def test_cli_show_cert(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Test that CLI with --show-cert prints server certificate information.

    Args:
        monkeypatch: Pytest monkeypatch fixture.
        capsys: Pytest capture stdout/stderr fixture.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    from wasat import ServerCertificate, generate_self_signed_cert

    cert_pem, _ = generate_self_signed_cert(
        common_name="cli.example.com", domain="cli.example.com"
    )
    cert_x509 = x509.load_pem_x509_certificate(cert_pem)
    der_bytes = cert_x509.public_bytes(serialization.Encoding.DER)
    server_cert = ServerCertificate.from_der(der_bytes)

    monkeypatch.setattr(
        "sys.argv", ["wasat", "--show-cert", "gemini://cli.example.com/"]
    )

    uri = GeminiURI("gemini://cli.example.com/")
    resp = DummyResponse(
        StatusCode.SUCCESS,
        "text/gemini",
        "Hello cert!",
        uri=uri,
        server_cert=server_cert,
    )

    async def mock_request(self: Any, uri: Any) -> DummyResponse:
        return resp

    monkeypatch.setattr("wasat.Client.request", mock_request)

    asyncio.run(run_cli())

    captured = capsys.readouterr()
    assert "--- Server Certificate ---" in captured.out
    assert "Subject CN: cli.example.com" in captured.out
    assert "Issuer CN: cli.example.com" in captured.out
    assert "SANs: cli.example.com" in captured.out
    assert "Fingerprint: sha256:" in captured.out
    assert "Hello cert!" in captured.out


def test_cli_show_cert_with_verbose(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Test that CLI with --show-cert and -v prints response headers and certificate info.

    Args:
        monkeypatch: Pytest monkeypatch fixture.
        capsys: Pytest capture stdout/stderr fixture.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    from wasat import ServerCertificate, generate_self_signed_cert

    cert_pem, _ = generate_self_signed_cert(
        common_name="verbose.example.com", domain="verbose.example.com"
    )
    cert_x509 = x509.load_pem_x509_certificate(cert_pem)
    der_bytes = cert_x509.public_bytes(serialization.Encoding.DER)
    server_cert = ServerCertificate.from_der(der_bytes)

    monkeypatch.setattr(
        "sys.argv", ["wasat", "-v", "--show-cert", "gemini://verbose.example.com/"]
    )

    uri = GeminiURI("gemini://verbose.example.com/")
    resp = DummyResponse(
        StatusCode.SUCCESS,
        "text/gemini",
        "Hello verbose cert!",
        uri=uri,
        verification_method="tofu",
        server_cert_fingerprint="123456",
        server_cert=server_cert,
    )

    async def mock_request(self: Any, uri: Any) -> DummyResponse:
        return resp

    monkeypatch.setattr("wasat.Client.request", mock_request)

    asyncio.run(run_cli())

    captured = capsys.readouterr()
    assert "--- Gemini Response ---" in captured.out
    assert "URI: gemini://verbose.example.com/" in captured.out
    assert "Verification Method: tofu" in captured.out
    assert "--- Server Certificate ---" in captured.out
    assert "Subject CN: verbose.example.com" in captured.out
    assert "Hello verbose cert!" in captured.out
