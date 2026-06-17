"""Tests for GeminiURI parsing and resolution."""

import unittest

from wasat.exceptions import URIError
from wasat.uri import GeminiURI


class TestGeminiURI(unittest.TestCase):
    """Test suite for the GeminiURI class."""

    def test_valid_parsing(self) -> None:
        """Test parsing of standard valid Gemini URIs."""
        uri = GeminiURI("gemini://example.com/path/to/resource?query")
        self.assertEqual(uri.scheme, "gemini")
        self.assertEqual(uri.host, "example.com")
        self.assertEqual(uri.port, 1965)
        self.assertEqual(uri.path, "/path/to/resource")
        self.assertEqual(uri.query, "query")
        self.assertEqual(str(uri), "gemini://example.com/path/to/resource?query")

    def test_default_port(self) -> None:
        """Test that default port is 1965 if none is specified."""
        uri = GeminiURI("gemini://example.com")
        self.assertEqual(uri.port, 1965)
        self.assertEqual(uri.path, "/")
        self.assertIsNone(uri.query)
        self.assertEqual(str(uri), "gemini://example.com/")

    def test_custom_port(self) -> None:
        """Test parsing of custom ports."""
        uri = GeminiURI("gemini://example.com:1966/path")
        self.assertEqual(uri.port, 1966)
        self.assertEqual(uri.path, "/path")
        self.assertEqual(str(uri), "gemini://example.com:1966/path")

    def test_invalid_scheme(self) -> None:
        """Test that non-gemini schemes raise URIError."""
        with self.assertRaises(URIError) as context:
            GeminiURI("http://example.com")
        self.assertIn("Invalid URI scheme", str(context.exception))

    def test_missing_host(self) -> None:
        """Test that missing host raises URIError."""
        with self.assertRaises(URIError):
            GeminiURI("gemini://")

    def test_empty_uri(self) -> None:
        """Test that empty or whitespace URIs raise URIError."""
        with self.assertRaises(URIError):
            GeminiURI("")
        with self.assertRaises(URIError):
            GeminiURI("   ")

    def test_with_query(self) -> None:
        """Test replacing or adding a query string."""
        uri = GeminiURI("gemini://example.com/path?old_query")
        new_uri = uri.with_query("new query & value")
        self.assertEqual(
            str(new_uri),
            "gemini://example.com/path?new%20query%20%26%20value",
        )

    def test_resolve_relative(self) -> None:
        """Test resolving relative URIs against a base GeminiURI."""
        base = GeminiURI("gemini://example.com/path/file.gmi?query")

        # Relative path
        self.assertEqual(
            str(base.resolve("other.gmi")), "gemini://example.com/path/other.gmi"
        )
        # Parent directory path
        self.assertEqual(
            str(base.resolve("../sibling/file.gmi")),
            "gemini://example.com/sibling/file.gmi",
        )
        # Absolute path
        self.assertEqual(
            str(base.resolve("/root.gmi")), "gemini://example.com/root.gmi"
        )
        # Absolute URI
        self.assertEqual(
            str(base.resolve("gemini://other.com/path")),
            "gemini://other.com/path",
        )

    def test_equality(self) -> None:
        """Test comparison of GeminiURI instances."""
        uri1 = GeminiURI("gemini://example.com/path")
        uri2 = GeminiURI("gemini://example.com/path")
        uri3 = GeminiURI("gemini://example.com/other")
        self.assertEqual(uri1, uri2)
        self.assertNotEqual(uri1, uri3)
        self.assertNotEqual(uri1, "gemini://example.com/path")

    def test_clone_from_gemini_uri(self) -> None:
        """Test instantiating a GeminiURI with another GeminiURI instance (cloning)."""
        original = GeminiURI("gemini://example.com:1966/path/to/resource?query")
        clone = GeminiURI(original)

        self.assertEqual(clone.scheme, "gemini")
        self.assertEqual(clone.host, "example.com")
        self.assertEqual(clone.port, 1966)
        self.assertEqual(clone.path, "/path/to/resource")
        self.assertEqual(clone.query, "query")
        self.assertEqual(clone, original)


if __name__ == "__main__":
    unittest.main()
