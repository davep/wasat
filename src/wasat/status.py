"""Gemini protocol status codes and categories."""

##############################################################################
# Add extra type checking support.
from __future__ import annotations

##############################################################################
# Python imports.
from enum import IntEnum


##############################################################################
class StatusCode(IntEnum):
    """Gemini protocol status codes."""

    # 1x Input
    INPUT = 10
    SENSITIVE_INPUT = 11

    # 2x Success
    SUCCESS = 20

    # 3x Redirect
    TEMPORARY_REDIRECT = 30
    PERMANENT_REDIRECT = 31

    # 4x Temporary Failure
    TEMPORARY_FAILURE = 40
    SERVER_UNAVAILABLE = 41
    CGI_ERROR = 42
    PROXY_ERROR = 43
    SLOW_DOWN = 44

    # 5x Permanent Failure
    PERMANENT_FAILURE = 50
    NOT_FOUND = 51
    GONE = 52
    PROXY_REQUEST_REFUSED = 53
    BAD_REQUEST = 59

    # 6x Client Certificate Required
    CLIENT_CERTIFICATE_REQUIRED = 60
    CERTIFICATE_NOT_AUTHORISED = 61
    CERTIFICATE_NOT_VALID = 62

    @property
    def category(self) -> int:
        """Returns the primary status code category (1-6).

        Returns:
            The category as an integer (e.g. 2 for SUCCESS).
        """
        return self.value // 10

    @property
    def is_input(self) -> bool:
        """Check if the status requires client input.

        Returns:
            True if the status is in the 1x range, False otherwise.
        """
        return self.category == 1

    @property
    def is_success(self) -> bool:
        """Check if the status indicates success.

        Returns:
            True if the status is 20, False otherwise.
        """
        return self.category == 2

    @property
    def is_redirect(self) -> bool:
        """Check if the status indicates a redirect.

        Returns:
            True if the status is in the 3x range, False otherwise.
        """
        return self.category == 3

    @property
    def is_temporary_failure(self) -> bool:
        """Check if the status indicates a temporary failure.

        Returns:
            True if the status is in the 4x range, False otherwise.
        """
        return self.category == 4

    @property
    def is_permanent_failure(self) -> bool:
        """Check if the status indicates a permanent failure.

        Returns:
            True if the status is in the 5x range, False otherwise.
        """
        return self.category == 5

    @property
    def is_failure(self) -> bool:
        """Check if the status indicates a failure (4x or 5x).

        Returns:
            True if the status is in the 4x or 5x range, False otherwise.
        """
        return self.category in (4, 5)

    @property
    def is_client_certificate_required(self) -> bool:
        """Check if the status indicates a client certificate issue.

        Returns:
            True if the status is in the 6x range, False otherwise.
        """
        return self.category == 6

    @classmethod
    def from_int(cls, value: int) -> StatusCode:
        """Resolve a status code integer, falling back to the group's primary code if unallocated.

        Args:
            value: The status code integer value.

        Returns:
            The resolved StatusCode.

        Raises:
            ValueError: If the status code or its group/category (1-6) is invalid.
        """
        try:
            return cls(value)
        except ValueError:
            primary_value = (value // 10) * 10
            try:
                return cls(primary_value)
            except ValueError as e:
                raise ValueError(f"Invalid status code: {value}") from e


### status.py ends here
