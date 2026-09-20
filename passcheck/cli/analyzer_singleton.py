"""Lazily-constructed, thread-safe shared PasswordAnalyzer instance."""
from __future__ import annotations

import threading

from ..analyzer import PasswordAnalyzer

__all__ = ["get_analyzer"]   # set_analyzer intentionally not exported (SA-L02)

_analyzer:      PasswordAnalyzer | None = None
_analyzer_lock: threading.Lock = threading.Lock()

def get_analyzer() -> PasswordAnalyzer:
    """Return the shared PasswordAnalyzer instance, constructing it lazily."""
    global _analyzer
    with _analyzer_lock:
        if _analyzer is None:
            _analyzer = PasswordAnalyzer()
        return _analyzer