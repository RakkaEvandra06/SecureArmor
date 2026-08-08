"""Tunable constants, thresholds, and reference data for PassCheck's scorer.

This used to be a single 650-line ``constants.py``. It is now a package
split by *reason to change* (Single Responsibility Principle):

    weights.py                  — how much each criterion is worth
    thresholds.py                — numeric pass/fail thresholds + strength bands
    special_chars.py              — what counts as a "special" character
    keyboard_patterns.py           — keyboard-walk pattern data
    common_passwords_data.py        — built-in fallback word list (pure data)
    common_passwords_loader.py       — file loading / caching / validation logic

Every file stays well under the ~400-line point where AI coding agents lose
indexing accuracy. This __init__ re-exports the exact same public surface
the old flat ``constants.py`` had, so ``from .constants import LENGTH_MINIMUM``
(and every other existing import elsewhere in the codebase) keeps working
unchanged.
"""
from __future__ import annotations

from .common_passwords_loader import get_common_passwords
from .keyboard_patterns import KEYBOARD_PATTERNS
from .special_chars import (
    SPECIAL_CHARS,
    SPECIAL_CHARS_INCLUDES_SPACE,
    SPECIAL_CHARS_SET,
)
from .thresholds import (
    CHAR_CLASS_COUNT,
    CHAR_UNIQUENESS_MIN_RATIO,
    CHAR_VARIETY_MIN_CLASSES,
    ENTROPY_GOOD_THRESHOLD,
    LENGTH_EXCELLENT,
    LENGTH_GOOD,
    LENGTH_MAXIMUM,
    LENGTH_MINIMUM,
    MAX_PERCENT_FOR_KNOWN_WEAK_PATTERN,
    NON_ASCII_POOL_SIZE,
    REPEATED_CHAR_RATIO,
    SHANNON_WEIGHT,
    STRENGTH_BANDS,
    VALID_COLOUR_KEYS,
)
from .weights import SCORE_WEIGHTS

__all__ = [
    "SCORE_WEIGHTS",
    "LENGTH_MINIMUM",
    "LENGTH_GOOD",
    "LENGTH_EXCELLENT",
    "LENGTH_MAXIMUM",
    "ENTROPY_GOOD_THRESHOLD",
    "NON_ASCII_POOL_SIZE",
    "REPEATED_CHAR_RATIO",
    "SHANNON_WEIGHT",
    "STRENGTH_BANDS",
    "VALID_COLOUR_KEYS",
    "SPECIAL_CHARS",
    "SPECIAL_CHARS_SET",
    "SPECIAL_CHARS_INCLUDES_SPACE",
    "KEYBOARD_PATTERNS",
    "get_common_passwords",
    "CHAR_UNIQUENESS_MIN_RATIO",
    "CHAR_VARIETY_MIN_CLASSES",
    "CHAR_CLASS_COUNT",
    "MAX_PERCENT_FOR_KNOWN_WEAK_PATTERN",
]
