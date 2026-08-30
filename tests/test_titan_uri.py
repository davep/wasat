"""Tests for TitanURI and related URI utilities."""

##############################################################################
# Python imports.
from pathlib import Path

import pytest

##############################################################################
# Local imports.
from wasat import (
    GEMINI_DEFAULT_PORT,
    TITAN_DEFAULT_PORT,
    TITAN_PREFIX,
    TITAN_SCHEME,
    GeminiURI,
    TitanURI,
    URIError,
    guess_mime_type,
)


##############################################################################
class TestTitanURI:
    """Test suite for TitanURI."""

    def test_constants(self) -> None:
        """Test module-level Titan constants."""
        assert TITAN_SCHEME == "titan"
        assert TITAN_PREFIX == "titan://"
        assert TITAN_DEFAULT_PORT == 1965
        assert GEMINI_DEFAULT_PORT == 1965

    def test_valid_parsing_simple(self) -> None:
        """Test parsing a simple Titan URI without parameters."""
        uri = TitanURI("titan://example.com/upload")
        assert uri.scheme == "titan"
        assert uri.host == "example.com"
        assert uri.port == 1965
        assert uri.path == "/upload"
        assert uri.query is None
        assert uri.size is None
        assert uri.mime is None
        assert uri.token is None
        assert str(uri) == "titan://example.com/upload"

    def test_valid_parsing_with_parameters(self) -> None:
        """Test parsing a Titan URI with size, mime, and token parameters."""
        uri = TitanURI(
            "titan://example.com:1967/upload/file.gmi;size=42;mime=text/gemini;token=secret?query=val"
        )
        assert uri.scheme == "titan"
        assert uri.host == "example.com"
        assert uri.port == 1967
        assert uri.path == "/upload/file.gmi"
        assert uri.size == 42
        assert uri.mime == "text/gemini"
        assert uri.token == "secret"
        assert uri.query == "query=val"
        assert "size=42" in str(uri)
        assert "mime=text/gemini" in str(uri)
        assert "token=secret" in str(uri)
        assert "?query=val" in str(uri)

    def test_size_zero_parsing(self) -> None:
        """Test parsing size=0 representing delete or empty creation."""
        uri = TitanURI("titan://example.com/delete_me;size=0")
        assert uri.size == 0
        assert str(uri) == "titan://example.com/delete_me;size=0"

    def test_invalid_scheme(self) -> None:
        """Test that invalid schemes are rejected."""
        with pytest.raises(URIError, match="Invalid URI scheme"):
            TitanURI("gemini://example.com/path")

        with pytest.raises(URIError, match="Invalid URI scheme"):
            TitanURI("https://example.com/path")

    def test_missing_host(self) -> None:
        """Test that TitanURI requires a valid host."""
        with pytest.raises(URIError, match="URI host is missing or invalid"):
            TitanURI("titan:///path")

    def test_empty_uri(self) -> None:
        """Test that empty URI raises URIError."""
        with pytest.raises(URIError, match="cannot be empty"):
            TitanURI("")

    def test_with_default_scheme(self) -> None:
        """Test TitanURI.with_default_scheme helper."""
        uri1 = TitanURI.with_default_scheme("example.com/upload")
        assert uri1.scheme == "titan"
        assert uri1.host == "example.com"
        assert uri1.path == "/upload"

        uri2 = TitanURI.with_default_scheme("titan://example.com:1968/path;size=10")
        assert uri2.port == 1968
        assert uri2.size == 10

        with pytest.raises(URIError):
            TitanURI.with_default_scheme("http://example.com")

    def test_isinstance_separation(self) -> None:
        """Test that isinstance cleanly differentiates GeminiURI and TitanURI."""
        gemini = GeminiURI("gemini://example.com/page")
        titan = TitanURI("titan://example.com/page")

        assert isinstance(gemini, GeminiURI)
        assert not isinstance(gemini, TitanURI)

        assert isinstance(titan, TitanURI)
        assert not isinstance(titan, GeminiURI)

    def test_to_titan_conversion(self) -> None:
        """Test converting GeminiURI to TitanURI."""
        gemini = GeminiURI("gemini://example.com:1967/resource.gmi?search=foo")
        titan = gemini.to_titan(size=100, mime="text/gemini", token="tok123")

        assert isinstance(titan, TitanURI)
        assert titan.scheme == "titan"
        assert titan.host == "example.com"
        assert titan.port == 1967
        assert titan.path == "/resource.gmi"
        assert titan.query == "search=foo"
        assert titan.size == 100
        assert titan.mime == "text/gemini"
        assert titan.token == "tok123"

    def test_to_gemini_conversion(self) -> None:
        """Test converting TitanURI to GeminiURI."""
        titan = TitanURI(
            "titan://example.com:1967/resource.gmi;size=100;mime=text/gemini;token=tok?search=foo"
        )
        gemini = titan.to_gemini()

        assert isinstance(gemini, GeminiURI)
        assert gemini.scheme == "gemini"
        assert gemini.host == "example.com"
        assert gemini.port == 1967
        assert gemini.path == "/resource.gmi"
        assert gemini.query == "search=foo"
        assert str(gemini) == "gemini://example.com:1967/resource.gmi?search=foo"

    def test_builder_methods(self) -> None:
        """Test TitanURI builder methods."""
        uri = TitanURI("titan://example.com/upload")

        u1 = uri.with_size(500)
        assert u1.size == 500
        assert str(u1) == "titan://example.com/upload;size=500"

        u2 = u1.with_mime("text/plain")
        assert u2.mime == "text/plain"
        assert u2.size == 500

        u3 = u2.with_token("abc")
        assert u3.token == "abc"

        u4 = u3.without_parameters
        assert u4.size is None
        assert u4.mime is None
        assert u4.token is None
        assert str(u4) == "titan://example.com/upload"

        u5 = uri.with_parameters({"size": "200", "mime": "image/png", "token": "t"})
        assert u5.size == 200
        assert u5.mime == "image/png"
        assert u5.token == "t"

    def test_replace_method(self) -> None:
        """Test replace method on TitanURI."""
        uri = TitanURI("titan://example.com:1965/foo;size=10;mime=text/gemini")
        replaced = uri.replace(
            host="other.com",
            port=1968,
            path="/bar",
            size=20,
            mime="text/plain",
            token="secret",
            query="q=1",
        )
        assert replaced.host == "other.com"
        assert replaced.port == 1968
        assert replaced.path == "/bar"
        assert replaced.size == 20
        assert replaced.mime == "text/plain"
        assert replaced.token == "secret"
        assert replaced.query == "q%3D1"

    def test_resolve_relative(self) -> None:
        """Test resolving relative links against TitanURI."""
        base = TitanURI("titan://example.com/docs/file;size=10;token=abc")

        # Relative path keeps base scheme and clears upload params on new path
        resolved = base.resolve("subfile.gmi")
        assert isinstance(resolved, TitanURI)
        assert resolved.path == "/docs/subfile.gmi"
        assert resolved.size is None

        # Cross scheme resolve to Gemini URI
        resolved_gemini = base.resolve("gemini://example.com/home")
        assert isinstance(resolved_gemini, GeminiURI)
        assert resolved_gemini.scheme == "gemini"
        assert resolved_gemini.path == "/home"

    def test_parent_and_root(self) -> None:
        """Test parent and root properties."""
        uri = TitanURI("titan://example.com/a/b/c;size=10")
        assert uri.parent.path == "/a/b"
        assert uri.root.path == "/"

    def test_equality_and_hashing(self) -> None:
        """Test equality and hashing for TitanURI."""
        u1 = TitanURI("titan://example.com/foo;size=10;mime=text/gemini")
        u2 = TitanURI("titan://example.com/foo;mime=text/gemini;size=10")
        u3 = TitanURI("titan://example.com/foo;size=20")
        gemini = GeminiURI("gemini://example.com/foo")

        assert u1 == u2
        assert hash(u1) == hash(u2)
        assert u1 != u3
        assert u1 != gemini
        assert u1 == "titan://example.com/foo;size=10;mime=text/gemini"
        assert u1 != "titan://example.com/foo;size=20"
        assert u1 != 12345

    def test_bytes_left_and_len(self) -> None:
        """Test length and bytes_left on TitanURI."""
        uri = TitanURI("titan://example.com/path;size=10")
        assert len(uri) == len(str(uri))
        assert uri.bytes_left == 1024 - len(str(uri).encode("utf-8"))
        assert uri.is_too_long is False


class TestGuessMimeType:
    """Test suite for guess_mime_type helper."""

    def test_common_gemini_and_web_extensions(self) -> None:
        """Test extension inference for common files."""
        assert guess_mime_type("file.gmi") == "text/gemini"
        assert guess_mime_type("file.gemini") == "text/gemini"
        assert guess_mime_type("index.txt") == "text/plain"
        assert guess_mime_type("page.html") == "text/html"
        assert guess_mime_type("photo.png") == "image/png"
        assert guess_mime_type("photo.jpg") == "image/jpeg"
        assert guess_mime_type("data.json") == "application/json"
        assert guess_mime_type(Path("doc.pdf")) == "application/pdf"
        assert (
            guess_mime_type("unknown_extension.xyzabc123") == "application/octet-stream"
        )
        assert guess_mime_type("no_extension") == "application/octet-stream"
