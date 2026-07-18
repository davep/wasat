"""Tests for GeminiURI parsing and resolution."""

import pytest

from wasat import GEMINI_DEFAULT_PORT, GeminiURI, URIError


class TestGeminiURI:
    """Test suite for the GeminiURI class."""

    def test_valid_parsing(self) -> None:
        """Test parsing of standard valid Gemini URIs."""
        uri = GeminiURI("gemini://example.com/path/to/resource?query")
        assert uri.scheme == "gemini"
        assert uri.host == "example.com"
        assert uri.port == GEMINI_DEFAULT_PORT
        assert uri.path == "/path/to/resource"
        assert uri.query == "query"
        assert str(uri) == "gemini://example.com/path/to/resource?query"

    def test_default_port(self) -> None:
        """Test that default port is GEMINI_DEFAULT_PORT if none is specified."""
        uri = GeminiURI("gemini://example.com")
        assert uri.port == GEMINI_DEFAULT_PORT
        assert uri.path == "/"
        assert uri.query is None
        assert str(uri) == "gemini://example.com/"

    def test_default_port_value(self) -> None:
        """Test that the GEMINI_DEFAULT_PORT constant is 1965."""
        assert GEMINI_DEFAULT_PORT == 1965

    def test_custom_port(self) -> None:
        """Test parsing of custom ports."""
        uri = GeminiURI("gemini://example.com:1966/path")
        assert uri.port == 1966
        assert uri.path == "/path"
        assert str(uri) == "gemini://example.com:1966/path"

    def test_invalid_scheme(self) -> None:
        """Test that non-gemini schemes raise URIError."""
        with pytest.raises(URIError, match="Invalid URI scheme"):
            GeminiURI("http://example.com")

    def test_missing_host(self) -> None:
        """Test that missing host raises URIError."""
        with pytest.raises(URIError):
            GeminiURI("gemini://")

    def test_missing_scheme(self) -> None:
        """Test that a missing scheme raises URIError."""
        with pytest.raises(URIError):
            GeminiURI("example.com/path")

    def test_empty_uri(self) -> None:
        """Test that empty or whitespace URIs raise URIError."""
        with pytest.raises(URIError):
            GeminiURI("")
        with pytest.raises(URIError):
            GeminiURI("   ")

    def test_with_query(self) -> None:
        """Test replacing or adding a query string."""
        uri = GeminiURI("gemini://example.com/path?old_query")
        new_uri = uri.with_query("new query & value")
        assert str(new_uri) == "gemini://example.com/path?new%20query%20%26%20value"

    def test_resolve_relative(self) -> None:
        """Test resolving relative URIs against a base GeminiURI."""
        base = GeminiURI("gemini://example.com/path/file.gmi?query")

        # Relative path
        assert str(base.resolve("other.gmi")) == "gemini://example.com/path/other.gmi"
        # Parent directory path
        assert (
            str(base.resolve("../sibling/file.gmi"))
            == "gemini://example.com/sibling/file.gmi"
        )
        # Absolute path
        assert str(base.resolve("/root.gmi")) == "gemini://example.com/root.gmi"
        # Absolute URI
        assert str(base.resolve("gemini://other.com/path")) == "gemini://other.com/path"

    def test_resolve_relative_error(self) -> None:
        """Test that resolving a non-Gemini URI raises URIError."""
        with pytest.raises(URIError, match="Failed to resolve relative URI"):
            GeminiURI("gemini://example.com/").resolve("http://google.com")

    def test_equality(self) -> None:
        """Test comparison of GeminiURI instances."""
        uri1 = GeminiURI("gemini://example.com/path")
        uri2 = GeminiURI("gemini://example.com/path")
        uri3 = GeminiURI("gemini://example.com/other")
        assert uri1 == uri2
        assert uri1 == "gemini://example.com/path"
        assert uri1 != uri3
        assert uri1 != "gemini://example.com/other"
        assert uri1 != "http://example.com/path"
        assert uri1 != None  # noqa: E711

    def test_clone_from_gemini_uri(self) -> None:
        """Test instantiating a GeminiURI with another GeminiURI instance (cloning)."""
        original = GeminiURI("gemini://example.com:1966/path/to/resource?query")
        clone = GeminiURI(original)

        assert clone.scheme == "gemini"
        assert clone.host == "example.com"
        assert clone.port == 1966
        assert clone.path == "/path/to/resource"
        assert clone.query == "query"
        assert clone == original

    @pytest.mark.parametrize(
        "invalid_uri",
        [
            # Unmatched IPv6 brackets in netloc
            "gemini://[::1",
            "gemini://]::1",
            # Malformed bracketed netloc structures
            "gemini://invalid[::1]",
            "gemini://[::1]extra",
            "gemini://[invalid_ipv6_address]",
            "gemini://[127.0.0.1]",
            # NFKC normalisation issues (invalid characters under NFKC normalisation)
            "gemini://example.com\uff0fpath",
            "gemini://example\uff1acom",
        ],
    )
    def test_parsing_failures_from_urlparse(self, invalid_uri: str) -> None:
        """Test that URIs causing urlparse exceptions raise URIError.

        This test checks that malformed IPv6 brackets, invalid bracketed netloc
        structures, and netlocs with NFKC normalisation issues all trigger
        the urlparse error path.

        Args:
            invalid_uri: The invalid URI string to parse.
        """
        with pytest.raises(URIError, match="Failed to parse URI"):
            GeminiURI(invalid_uri)

    def test_replace_method(self) -> None:
        """Test replacing parts of a GeminiURI using the replace method."""
        uri = GeminiURI("gemini://example.com:1966/path/to/resource?query")

        # Replace host
        assert uri.replace(host="newhost.org") == GeminiURI(
            "gemini://newhost.org:1966/path/to/resource?query"
        )

        # Replace port
        assert uri.replace(port=2000) == GeminiURI(
            "gemini://example.com:2000/path/to/resource?query"
        )

        # Replace path
        assert uri.replace(path="/new/path") == GeminiURI(
            "gemini://example.com:1966/new/path?query"
        )

        # Clear path (sets to /)
        assert uri.replace(path=None) == GeminiURI("gemini://example.com:1966/?query")

        # Replace query
        assert uri.replace(query="new_query") == GeminiURI(
            "gemini://example.com:1966/path/to/resource?new_query"
        )

        # Clear query
        assert uri.replace(query=None) == GeminiURI(
            "gemini://example.com:1966/path/to/resource"
        )

        # Replace multiple
        assert uri.replace(
            host="other.net", port=1965, path=None, query=None
        ) == GeminiURI("gemini://other.net/")

    def test_builder_methods(self) -> None:
        """Test builder methods for modifying a GeminiURI."""
        uri = GeminiURI("gemini://example.com:1966/path/to/resource?query")

        # with_host
        assert uri.with_host("newhost.org") == GeminiURI(
            "gemini://newhost.org:1966/path/to/resource?query"
        )

        # with_port
        assert uri.with_port(2000) == GeminiURI(
            "gemini://example.com:2000/path/to/resource?query"
        )

        # with_path
        assert uri.with_path("/new/path") == GeminiURI(
            "gemini://example.com:1966/new/path?query"
        )
        assert uri.with_path(None) == GeminiURI("gemini://example.com:1966/?query")

        # with_query
        assert uri.with_query("new_query") == GeminiURI(
            "gemini://example.com:1966/path/to/resource?new_query"
        )
        assert uri.with_query(None) == GeminiURI(
            "gemini://example.com:1966/path/to/resource"
        )

    def test_replace_invalid(self) -> None:
        """Test that replace raises URIError when given invalid values."""
        uri = GeminiURI("gemini://example.com/")

        with pytest.raises(URIError):
            uri.replace(host="")

        with pytest.raises(URIError):
            uri.replace(port=-1)

    @pytest.mark.parametrize(
        "text, scheme, port, host, path",
        [
            ("example.com", "gemini", GEMINI_DEFAULT_PORT, "example.com", "/"),
            ("example.com/path", "gemini", GEMINI_DEFAULT_PORT, "example.com", "/path"),
            ("example.com:1967/path", "gemini", 1967, "example.com", "/path"),
            (
                "gemini://example.com/path",
                "gemini",
                GEMINI_DEFAULT_PORT,
                "example.com",
                "/path",
            ),
        ],
    )
    def test_maybe_adding_scheme(
        self, text: str, scheme: str, port: int, host: str, path: str
    ) -> None:
        """Test that a scheme is added if missing when creating a GeminiURI."""
        uri = GeminiURI.with_default_scheme(text)
        assert uri.scheme == scheme
        assert uri.port == port
        assert uri.host == host
        assert uri.path == path

    def test_maybe_adding_scheme_invalid(self) -> None:
        """Test that invalid URIs raise URIError when using maybe_adding_scheme."""
        with pytest.raises(URIError):
            GeminiURI.with_default_scheme("http://example.com/path")
        with pytest.raises(URIError):
            GeminiURI.with_default_scheme("")

    @pytest.mark.parametrize(
        "uri",
        [
            (GeminiURI("gemini://example.com/path")),
            (GeminiURI("gemini://example.com:1966/path")),
            (GeminiURI("gemini://example.com/")),
            (GeminiURI("gemini://example.com")),
            (GeminiURI("gemini://example.com").with_query("query")),
        ],
    )
    def test_len(self, uri: GeminiURI) -> None:
        """Test that the length of a GeminiURI is the length of its string representation."""
        assert len(uri) == len(str(uri))

    @pytest.mark.parametrize(
        "uri, bytes_left, too_long",
        [
            (GeminiURI("gemini://example.com/abc"), 1000, False),
            (GeminiURI("gemini://example.com:1966/path"), 994, False),
            (
                GeminiURI("gemini://example.com/").with_query(
                    "q"
                    * (
                        GeminiURI.MAXIMUM_LENGTH
                        - len(GeminiURI("gemini://example.com/"))
                    )
                ),
                0,
                True,
            ),
            (
                GeminiURI("gemini://example.com/").with_query(
                    "q" * GeminiURI.MAXIMUM_LENGTH
                ),
                0,
                True,
            ),
        ],
    )
    def test_bytes_left(self, uri: GeminiURI, bytes_left: int, too_long: bool) -> None:
        """Test that bytes_left returns the correct number of characters left for a given max length."""
        assert uri.bytes_left == bytes_left
        assert uri.is_too_long is too_long

    @pytest.mark.parametrize(
        "initial, result",
        [
            ("gemini://example.com/path?query", "gemini://example.com/path"),
            ("gemini://example.com/?query", "gemini://example.com/"),
            ("gemini://example.com/", "gemini://example.com/"),
        ],
    )
    def test_without_query(self, initial: str, result: str) -> None:
        """Test that without_query returns a GeminiURI without the query string."""
        assert GeminiURI(initial).without_query == GeminiURI(result)

    @pytest.mark.parametrize(
        "initial, result",
        [
            ("gemini://example.com/path/to/resource", "gemini://example.com/path/to"),
            (
                "gemini://example.com/path/to/resource/?foo",
                "gemini://example.com/path/to",
            ),
            ("gemini://example.com/path/to/resource/", "gemini://example.com/path/to"),
            (
                "gemini://example.com/path/to/resource?foo",
                "gemini://example.com/path/to",
            ),
            (
                "gemini://example.com/path/to/resource.gmi",
                "gemini://example.com/path/to",
            ),
            ("gemini://example.com/path/", "gemini://example.com/"),
            ("gemini://example.com/file.gmi", "gemini://example.com/"),
            ("gemini://example.com/", "gemini://example.com/"),
            ("gemini://example.com/?foo", "gemini://example.com/"),
        ],
    )
    def test_parent(self, initial: str, result: str) -> None:
        """Test that parent returns the parent GeminiURI."""
        assert GeminiURI(initial).parent == GeminiURI(result)

    @pytest.mark.parametrize(
        "initial",
        [
            "gemini://example.com/path/to/resource",
            "gemini://example.com/path/to/resource?foo",
            "gemini://example.com/path/to/resource/",
            "gemini://example.com/path/to/resource.gmi",
            "gemini://example.com/path/",
            "gemini://example.com/file.gmi",
            "gemini://example.com/file.gmi?foo",
            "gemini://example.com/",
            "gemini://example.com/?foo",
        ],
    )
    def test_root(self, initial: str) -> None:
        """Test that root returns the root GeminiURI."""
        assert GeminiURI(initial).root == GeminiURI("gemini://example.com/")


### test_uri.py ends here
