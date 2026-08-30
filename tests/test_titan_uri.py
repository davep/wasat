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
        assert uri.parameters == {}
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
        assert uri.parameters == {
            "size": "42",
            "mime": "text/gemini",
            "token": "secret",
        }
        assert "size=42" in str(uri)
        assert "mime=text/gemini" in str(uri)
        assert "token=secret" in str(uri)
        assert "?query=val" in str(uri)

    def test_default_port(self) -> None:
        """Test that default port is TITAN_DEFAULT_PORT if none is specified."""
        uri = TitanURI("titan://example.com")
        assert uri.port == TITAN_DEFAULT_PORT
        assert uri.path == "/"
        assert uri.query is None
        assert str(uri) == "titan://example.com/"

    def test_custom_port(self) -> None:
        """Test parsing of custom ports."""
        uri = TitanURI("titan://example.com:1966/path")
        assert uri.port == 1966
        assert uri.path == "/path"
        assert str(uri) == "titan://example.com:1966/path"

    def test_size_zero_parsing(self) -> None:
        """Test parsing size=0 representing delete or empty creation."""
        uri = TitanURI("titan://example.com/delete_me;size=0")
        assert uri.size == 0
        assert str(uri) == "titan://example.com/delete_me;size=0"

    def test_parameter_variations(self) -> None:
        """Test parsing various semicolon parameter styles."""
        # Valueless flag parameter
        uri1 = TitanURI("titan://example.com/path;flag")
        assert uri1.parameters == {"flag": None}

        # Custom arbitrary key-value parameters
        uri2 = TitanURI("titan://example.com/path;foo=bar;custom=123")
        assert uri2.parameters["foo"] == "bar"
        assert uri2.parameters["custom"] == "123"

        # Case-insensitive parameter names
        uri3 = TitanURI(
            "titan://example.com/path;SIZE=100;MIME=text/plain;TOKEN=auth123"
        )
        assert uri3.size == 100
        assert uri3.mime == "text/plain"
        assert uri3.token == "auth123"

        # Extra / empty semicolons
        uri4 = TitanURI("titan://example.com/path;;size=50;;")
        assert uri4.size == 50
        assert uri4.path == "/path"

    def test_invalid_parameters(self) -> None:
        """Test that invalid parameter values raise URIError."""
        with pytest.raises(URIError, match="Invalid Titan size parameter"):
            TitanURI("titan://example.com/path;size=not_a_number")

        with pytest.raises(URIError, match="Invalid Titan size parameter"):
            TitanURI("titan://example.com/path;size=-10")

    def test_invalid_scheme(self) -> None:
        """Test that invalid schemes are rejected."""
        with pytest.raises(URIError, match="Invalid URI scheme"):
            TitanURI("gemini://example.com/path")

        with pytest.raises(URIError, match="Invalid URI scheme"):
            TitanURI("https://example.com/path")

        with pytest.raises(URIError, match="Invalid URI scheme"):
            TitanURI("gopher://example.com/path")

    def test_missing_host(self) -> None:
        """Test that TitanURI requires a valid host."""
        with pytest.raises(URIError, match="URI host is missing or invalid"):
            TitanURI("titan:///path")

        with pytest.raises(URIError, match="URI host is missing or invalid"):
            TitanURI("titan://")

        with pytest.raises(URIError, match="URI host is missing or invalid"):
            TitanURI("titan://:1965/path")

    def test_missing_scheme(self) -> None:
        """Test that a missing scheme raises URIError."""
        with pytest.raises(URIError):
            TitanURI("example.com/path")

    def test_empty_uri(self) -> None:
        """Test that empty or whitespace URIs raise URIError."""
        with pytest.raises(URIError, match="cannot be empty"):
            TitanURI("")
        with pytest.raises(URIError, match="cannot be empty"):
            TitanURI("   ")

    def test_clone_from_titan_uri(self) -> None:
        """Test cloning a TitanURI from an existing TitanURI instance."""
        original = TitanURI(
            "titan://example.com:1967/upload/file.gmi;size=10;mime=text/plain;token=tok?query=1"
        )
        clone = TitanURI(original)

        assert clone.scheme == "titan"
        assert clone.host == "example.com"
        assert clone.port == 1967
        assert clone.path == "/upload/file.gmi"
        assert clone.size == 10
        assert clone.mime == "text/plain"
        assert clone.token == "tok"
        assert clone.query == "query=1"
        assert clone == original

    @pytest.mark.parametrize(
        "invalid_uri",
        [
            # Unmatched IPv6 brackets in netloc
            "titan://[::1",
            "titan://]::1",
            # Malformed bracketed netloc structures
            "titan://invalid[::1]",
            "titan://[::1]extra",
            "titan://[invalid_ipv6_address]",
            "titan://[127.0.0.1]",
            # NFKC normalisation issues (invalid characters under NFKC normalisation)
            "titan://example.com\uff0fpath",
            "titan://example\uff1acom",
        ],
    )
    def test_parsing_failures_from_urlparse(self, invalid_uri: str) -> None:
        """Test that URIs causing URL parsing exceptions raise URIError.

        Args:
            invalid_uri: The invalid URI string to parse.
        """
        with pytest.raises(URIError, match="Failed to parse URI"):
            TitanURI(invalid_uri)

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

        # with_host
        assert uri.with_host("newhost.org") == TitanURI("titan://newhost.org/upload")

        # with_port
        assert uri.with_port(2000) == TitanURI("titan://example.com:2000/upload")

        # with_path
        assert uri.with_path("/new/path") == TitanURI("titan://example.com/new/path")
        assert uri.with_path(None) == TitanURI("titan://example.com/")

        # with_query
        assert uri.with_query("new_query") == TitanURI(
            "titan://example.com/upload?new_query"
        )
        assert TitanURI("titan://example.com/upload?query").with_query(
            None
        ) == TitanURI("titan://example.com/upload")

        # with_size
        u1 = uri.with_size(500)
        assert u1.size == 500
        assert str(u1) == "titan://example.com/upload;size=500"
        assert u1.with_size(None).size is None

        # with_mime
        u2 = u1.with_mime("text/plain")
        assert u2.mime == "text/plain"
        assert u2.size == 500
        assert u2.with_mime(None).mime is None

        # with_token
        u3 = u2.with_token("abc")
        assert u3.token == "abc"
        assert u3.with_token(None).token is None

        # without_parameters
        u4 = u3.without_parameters
        assert u4.size is None
        assert u4.mime is None
        assert u4.token is None
        assert str(u4) == "titan://example.com/upload"

        # with_parameters
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

        # Clear path and parameters
        cleared = uri.replace(path=None, size=None, mime=None)
        assert cleared.path == "/"
        assert cleared.size is None
        assert cleared.mime is None

    def test_replace_invalid(self) -> None:
        """Test that replace raises URIError when given invalid values."""
        uri = TitanURI("titan://example.com/")

        with pytest.raises(URIError):
            uri.replace(host="")

        with pytest.raises(URIError):
            uri.replace(port=-1)

        with pytest.raises(URIError, match="Invalid Titan size parameter"):
            uri.replace(size=-10)

    @pytest.mark.parametrize(
        "text, scheme, port, host, path",
        [
            ("example.com", "titan", TITAN_DEFAULT_PORT, "example.com", "/"),
            (
                "example.com/upload",
                "titan",
                TITAN_DEFAULT_PORT,
                "example.com",
                "/upload",
            ),
            ("example.com:1967/path", "titan", 1967, "example.com", "/path"),
            (
                "titan://example.com/path",
                "titan",
                TITAN_DEFAULT_PORT,
                "example.com",
                "/path",
            ),
        ],
    )
    def test_maybe_adding_scheme(
        self, text: str, scheme: str, port: int, host: str, path: str
    ) -> None:
        """Test that a scheme is added if missing when creating a TitanURI via with_default_scheme.

        Args:
            text: Input string.
            scheme: Expected scheme.
            port: Expected port.
            host: Expected host.
            path: Expected path.
        """
        uri = TitanURI.with_default_scheme(text)
        assert uri.scheme == scheme
        assert uri.port == port
        assert uri.host == host
        assert uri.path == path

    def test_maybe_adding_scheme_invalid(self) -> None:
        """Test that invalid URIs raise URIError with with_default_scheme."""
        with pytest.raises(URIError):
            TitanURI.with_default_scheme("http://example.com/path")
        with pytest.raises(URIError):
            TitanURI.with_default_scheme("")

    def test_resolve_relative(self) -> None:
        """Test resolving relative links against TitanURI."""
        base = TitanURI("titan://example.com/docs/file;size=10;token=abc?query=1")

        # Relative path keeps base scheme and clears parameters on new path
        resolved = base.resolve("subfile.gmi")
        assert isinstance(resolved, TitanURI)
        assert resolved.path == "/docs/subfile.gmi"
        assert resolved.size is None
        assert resolved.token is None

        # Parent path
        parent_res = base.resolve("../other.gmi")
        assert parent_res.path == "/other.gmi"

        # Absolute path
        abs_res = base.resolve("/root.gmi")
        assert abs_res.path == "/root.gmi"

        # Absolute Titan URI
        titan_res = base.resolve("titan://other.com:1968/dest;size=20")
        assert isinstance(titan_res, TitanURI)
        assert titan_res.host == "other.com"
        assert titan_res.port == 1968
        assert titan_res.size == 20

        # Cross-scheme resolve to Gemini URI
        resolved_gemini = base.resolve("gemini://example.com/home")
        assert isinstance(resolved_gemini, GeminiURI)
        assert resolved_gemini.scheme == "gemini"
        assert resolved_gemini.path == "/home"

    def test_resolve_relative_error(self) -> None:
        """Test that resolving a non-Gemini / non-Titan URI raises URIError."""
        with pytest.raises(URIError, match="Failed to resolve relative URI"):
            TitanURI("titan://example.com/").resolve("http://google.com")

    @pytest.mark.parametrize(
        "uri",
        [
            (TitanURI("titan://example.com/path")),
            (TitanURI("titan://example.com:1966/path")),
            (TitanURI("titan://example.com/")),
            (TitanURI("titan://example.com")),
            (TitanURI("titan://example.com").with_query("query")),
            (TitanURI("titan://example.com/path;size=100;mime=text/gemini")),
        ],
    )
    def test_len(self, uri: TitanURI) -> None:
        """Test that the length of a TitanURI is the length of its string representation.

        Args:
            uri: The TitanURI instance.
        """
        assert len(uri) == len(str(uri))

    @pytest.mark.parametrize(
        "uri, bytes_left, too_long",
        [
            (TitanURI("titan://example.com/abc"), 1001, False),
            (TitanURI("titan://example.com:1966/path"), 995, False),
            (
                TitanURI("titan://example.com/").with_query(
                    "q"
                    * (TitanURI.MAXIMUM_LENGTH - len(TitanURI("titan://example.com/")))
                ),
                0,
                True,
            ),
            (
                TitanURI("titan://example.com/").with_query(
                    "q" * TitanURI.MAXIMUM_LENGTH
                ),
                0,
                True,
            ),
        ],
    )
    def test_bytes_left(self, uri: TitanURI, bytes_left: int, too_long: bool) -> None:
        """Test that bytes_left returns the correct number of characters left for a given max length.

        Args:
            uri: The TitanURI instance.
            bytes_left: Expected bytes left under 1024-byte limit.
            too_long: Whether is_too_long should be true.
        """
        assert uri.bytes_left == bytes_left
        assert uri.is_too_long is too_long

    @pytest.mark.parametrize(
        "initial, result",
        [
            ("titan://example.com/path?query", "titan://example.com/path"),
            (
                "titan://example.com/path;size=10?query",
                "titan://example.com/path;size=10",
            ),
            (
                "titan://example.com/path;size=10;mime=text/plain?query",
                "titan://example.com/path;size=10;mime=text/plain",
            ),
            ("titan://example.com/?query", "titan://example.com/"),
            ("titan://example.com/", "titan://example.com/"),
        ],
    )
    def test_without_query(self, initial: str, result: str) -> None:
        """Test that without_query returns a TitanURI without the query string while preserving parameters.

        Args:
            initial: The input URI string.
            result: The expected resulting URI string.
        """
        assert TitanURI(initial).without_query == TitanURI(result)

    @pytest.mark.parametrize(
        "initial, result",
        [
            ("titan://example.com/path/to/resource", "titan://example.com/path/to"),
            (
                "titan://example.com/path/to/resource/?foo",
                "titan://example.com/path/to",
            ),
            (
                "titan://example.com/path/to/resource;size=10",
                "titan://example.com/path/to",
            ),
            (
                "titan://example.com/path/to/resource.gmi;size=10;token=abc",
                "titan://example.com/path/to",
            ),
            ("titan://example.com/path/", "titan://example.com/"),
            ("titan://example.com/file.gmi", "titan://example.com/"),
            ("titan://example.com/", "titan://example.com/"),
            ("titan://example.com/?foo", "titan://example.com/"),
        ],
    )
    def test_parent(self, initial: str, result: str) -> None:
        """Test that parent returns the parent TitanURI.

        Args:
            initial: The input URI string.
            result: The expected parent URI string.
        """
        assert TitanURI(initial).parent == TitanURI(result)

    @pytest.mark.parametrize(
        "initial",
        [
            "titan://example.com/path/to/resource",
            "titan://example.com/path/to/resource?foo",
            "titan://example.com/path/to/resource;size=10",
            "titan://example.com/path/to/resource.gmi;size=10;token=abc",
            "titan://example.com/path/",
            "titan://example.com/file.gmi",
            "titan://example.com/file.gmi?foo",
            "titan://example.com/",
            "titan://example.com/?foo",
        ],
    )
    def test_root(self, initial: str) -> None:
        """Test that root returns the root TitanURI.

        Args:
            initial: The input URI string.
        """
        assert TitanURI(initial).root == TitanURI("titan://example.com/")

    def test_equality_and_hashing(self) -> None:
        """Test equality and hashing for TitanURI."""
        u1 = TitanURI("titan://example.com/foo;size=10;mime=text/gemini")
        u2 = TitanURI("titan://example.com/foo;mime=text/gemini;size=10")
        u3 = TitanURI("titan://example.com/foo;size=20")
        gemini = GeminiURI("gemini://example.com/foo")

        # Parameter ordering invariance
        assert u1 == u2
        assert hash(u1) == hash(u2)

        # Different parameter values
        assert u1 != u3
        assert u1 != gemini

        # String equality
        assert u1 == "titan://example.com/foo;size=10;mime=text/gemini"
        assert u1 != "titan://example.com/foo;size=20"

        # Non-matching types
        assert u1 != 12345
        assert u1 is not None
        assert u1 != "http://example.com/foo"


##############################################################################
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
        assert guess_mime_type("FILE.GMI") == "text/gemini"
