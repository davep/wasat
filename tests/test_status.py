"""Tests for StatusCode Enum and parsing."""

import pytest

from wasat import StatusCode


class TestStatusCode:
    """Test suite for the StatusCode enum."""

    def test_categories(self) -> None:
        """Test category extraction for various status codes."""
        assert StatusCode.INPUT.category == 1
        assert StatusCode.SUCCESS.category == 2
        assert StatusCode.TEMPORARY_REDIRECT.category == 3
        assert StatusCode.TEMPORARY_FAILURE.category == 4
        assert StatusCode.PERMANENT_FAILURE.category == 5
        assert StatusCode.CLIENT_CERTIFICATE_REQUIRED.category == 6

    def test_status_helpers(self) -> None:
        """Test specific status property checkers."""
        assert StatusCode.INPUT.is_input
        assert not StatusCode.INPUT.is_success

        assert StatusCode.SUCCESS.is_success
        assert not StatusCode.SUCCESS.is_redirect

        assert StatusCode.TEMPORARY_REDIRECT.is_redirect
        assert StatusCode.PERMANENT_REDIRECT.is_redirect

        assert StatusCode.TEMPORARY_FAILURE.is_temporary_failure
        assert StatusCode.TEMPORARY_FAILURE.is_failure
        assert not StatusCode.TEMPORARY_FAILURE.is_permanent_failure

        assert StatusCode.PERMANENT_FAILURE.is_permanent_failure
        assert StatusCode.PERMANENT_FAILURE.is_failure

        assert StatusCode.CLIENT_CERTIFICATE_REQUIRED.is_client_certificate_required

    def test_from_int_valid(self) -> None:
        """Test parsing valid integer status codes."""
        assert StatusCode.from_int(10) == StatusCode.INPUT
        assert StatusCode.from_int(20) == StatusCode.SUCCESS

    def test_from_int_fallback(self) -> None:
        """Test fallback resolution for unallocated/unknown codes in a group."""
        # Code 23 is not allocated, should fallback to 20
        assert StatusCode.from_int(23) == StatusCode.SUCCESS
        # Code 58 is not allocated, should fallback to 50
        assert StatusCode.from_int(58) == StatusCode.PERMANENT_FAILURE

    def test_from_int_invalid_category(self) -> None:
        """Test that invalid category codes (e.g. 70) raise ValueError."""
        with pytest.raises(ValueError):
            StatusCode.from_int(70)
        with pytest.raises(ValueError):
            StatusCode.from_int(5)


### test_status.py ends here
