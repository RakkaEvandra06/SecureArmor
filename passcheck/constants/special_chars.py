"""Definition of which characters count as "special" for scoring."""
from __future__ import annotations

__all__ = [
    "SPECIAL_CHARS",
    "SPECIAL_CHARS_INCLUDES_SPACE",
    "SPECIAL_CHARS_SET",
]

# The 32 standard ASCII printable special characters (ASCII 33-47, 58-64,
# 91-96, 123-126).  Space (ASCII 32) is intentionally excluded — see SA-D01.
SPECIAL_CHARS: str = """!"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"""

# Reflects the current policy; external callers can inspect this flag to
# determine whether to include space in their own policy displays.
SPECIAL_CHARS_INCLUDES_SPACE: bool = " " in SPECIAL_CHARS   # False after SA-D01

SPECIAL_CHARS_SET: frozenset[str] = frozenset(SPECIAL_CHARS)