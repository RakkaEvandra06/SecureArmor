"""Definition of which characters count as "special" for scoring."""
from __future__ import annotations

__all__ = [
    "SPECIAL_CHARS",
    "SPECIAL_CHARS_INCLUDES_SPACE",
    "SPECIAL_CHARS_SET",
]

SPECIAL_CHARS: str = """ !"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"""
SPECIAL_CHARS_INCLUDES_SPACE: bool = " " in SPECIAL_CHARS
SPECIAL_CHARS_SET: frozenset[str] = frozenset(SPECIAL_CHARS)
