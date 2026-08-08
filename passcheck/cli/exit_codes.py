"""Process exit codes used across the CLI."""
from __future__ import annotations

from enum import IntEnum

__all__ = ["ExitCode"]

class ExitCode(IntEnum):
    OK          = 0
    ERROR       = 1
    PARTIAL     = 3
    INTERRUPTED = 130  # POSIX convention: 128 + SIGINT(2)
