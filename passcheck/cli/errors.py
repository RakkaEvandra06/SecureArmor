"""Internal exception types used to carry CLI-facing error messages."""
from __future__ import annotations

from ..constants import LENGTH_MAXIMUM

__all__ = ["AnalysisError", "PasswordTooLongError"]

class AnalysisError(Exception):
    """Raised by :func:`_run_analysis` when the analyser returns a ValueError."""

    def __init__(self, detail: str) -> None:
        self.detail = detail
        super().__init__(detail)

class PasswordTooLongError(ValueError):
    """Raised by :func:`_nfc_and_check_length` when a password is too long to analyse."""

    def __init__(self, length: int) -> None:
        self.length = length
        super().__init__(
            f"Error: password exceeds the maximum analysable length "
            f"of {LENGTH_MAXIMUM} characters."
        )
