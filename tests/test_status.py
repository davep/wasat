"""Tests for StatusCode Enum and parsing."""

import unittest

from wasat import StatusCode


class TestStatusCode(unittest.TestCase):
    """Test suite for the StatusCode enum."""

    def test_categories(self) -> None:
        """Test category extraction for various status codes."""
        self.assertEqual(StatusCode.INPUT.category, 1)
        self.assertEqual(StatusCode.SUCCESS.category, 2)
        self.assertEqual(StatusCode.TEMPORARY_REDIRECT.category, 3)
        self.assertEqual(StatusCode.TEMPORARY_FAILURE.category, 4)
        self.assertEqual(StatusCode.PERMANENT_FAILURE.category, 5)
        self.assertEqual(StatusCode.CLIENT_CERTIFICATE_REQUIRED.category, 6)

    def test_status_helpers(self) -> None:
        """Test specific status property checkers."""
        self.assertTrue(StatusCode.INPUT.is_input)
        self.assertFalse(StatusCode.INPUT.is_success)

        self.assertTrue(StatusCode.SUCCESS.is_success)
        self.assertFalse(StatusCode.SUCCESS.is_redirect)

        self.assertTrue(StatusCode.TEMPORARY_REDIRECT.is_redirect)
        self.assertTrue(StatusCode.PERMANENT_REDIRECT.is_redirect)

        self.assertTrue(StatusCode.TEMPORARY_FAILURE.is_temporary_failure)
        self.assertTrue(StatusCode.TEMPORARY_FAILURE.is_failure)
        self.assertFalse(StatusCode.TEMPORARY_FAILURE.is_permanent_failure)

        self.assertTrue(StatusCode.PERMANENT_FAILURE.is_permanent_failure)
        self.assertTrue(StatusCode.PERMANENT_FAILURE.is_failure)

        self.assertTrue(
            StatusCode.CLIENT_CERTIFICATE_REQUIRED.is_client_certificate_required
        )

    def test_from_int_valid(self) -> None:
        """Test parsing valid integer status codes."""
        self.assertEqual(StatusCode.from_int(10), StatusCode.INPUT)
        self.assertEqual(StatusCode.from_int(20), StatusCode.SUCCESS)

    def test_from_int_fallback(self) -> None:
        """Test fallback resolution for unallocated/unknown codes in a group."""
        # Code 23 is not allocated, should fallback to 20
        self.assertEqual(StatusCode.from_int(23), StatusCode.SUCCESS)
        # Code 58 is not allocated, should fallback to 50
        self.assertEqual(StatusCode.from_int(58), StatusCode.PERMANENT_FAILURE)

    def test_from_int_invalid_category(self) -> None:
        """Test that invalid category codes (e.g. 70) raise ValueError."""
        with self.assertRaises(ValueError):
            StatusCode.from_int(70)
        with self.assertRaises(ValueError):
            StatusCode.from_int(5)


### test_status.py ends here
