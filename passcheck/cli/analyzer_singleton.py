"""Lazily-constructed, thread-safe shared PasswordAnalyzer instance."""
from __future__ import annotations

import os
import threading

from ..analyzer import PasswordAnalyzer

__all__ = ["get_analyzer", "set_analyzer"]

_analyzer:      PasswordAnalyzer | None = None
_analyzer_lock: threading.Lock = threading.Lock()

def get_analyzer() -> PasswordAnalyzer:
    """Return the shared PasswordAnalyzer instance, constructing it lazily."""
    global _analyzer
    if _analyzer is None:
        with _analyzer_lock:
            if _analyzer is None:   # second check inside the lock
                _analyzer = PasswordAnalyzer()
    return _analyzer

def set_analyzer(analyzer: PasswordAnalyzer) -> None:
    """Override the shared analyser instance (test suite only)."""
    if os.environ.get("PASSCHECK_TEST_MODE") != "1":
        raise RuntimeError(
            "_set_analyzer() is reserved for the test suite. "
            "Set the PASSCHECK_TEST_MODE=1 environment variable to enable it."
        )
    global _analyzer
    with _analyzer_lock:
        _analyzer = analyzer
