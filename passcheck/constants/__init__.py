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

from .common_passwords_loader import get_common_passwords, is_wordlist_sufficient
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
    # NON_ASCII_POOL_SIZE intentionally omitted — deprecated in BUG-003.
    # The value was 32 768 and caused entropy overestimation for small Unicode
    # scripts; entropy.py now uses per-block pool sizes with a 128-entry
    # fallback.  Access via `passcheck.constants.NON_ASCII_POOL_SIZE` still
    # works (issues DeprecationWarning); star-imports no longer carry it.
    "REPEATED_CHAR_RATIO",
    "SHANNON_WEIGHT",
    "STRENGTH_BANDS",
    "VALID_COLOUR_KEYS",
    "SPECIAL_CHARS",
    "SPECIAL_CHARS_SET",
    "SPECIAL_CHARS_INCLUDES_SPACE",
    "KEYBOARD_PATTERNS",
    "get_common_passwords",
    "is_wordlist_sufficient",
    "CHAR_UNIQUENESS_MIN_RATIO",
    "CHAR_VARIETY_MIN_CLASSES",
    "CHAR_CLASS_COUNT",
    "MAX_PERCENT_FOR_KNOWN_WEAK_PATTERN",
]


def __getattr__(name: str) -> object:
    """BUG-003: Backward-compatible shim for the deprecated NON_ASCII_POOL_SIZE.

    Allows ``from passcheck.constants import NON_ASCII_POOL_SIZE`` to keep
    working for one release cycle while emitting a :class:`DeprecationWarning`.
    """
    if name == "NON_ASCII_POOL_SIZE":
        import warnings
        warnings.warn(
            "passcheck.constants.NON_ASCII_POOL_SIZE is deprecated and will be "
            "removed in a future release.  The constant is no longer used for "
            "entropy calculation — passcheck.analyzer.entropy now derives "
            "per-block pool sizes from _UNICODE_BLOCK_POOLS (fallback: 128). "
            "Remove any references to NON_ASCII_POOL_SIZE from your code.",
            DeprecationWarning,
            stacklevel=2,
        )
        # Import from the defining module so we don't duplicate the literal.
        from .thresholds import NON_ASCII_POOL_SIZE as _v  # noqa: PLC0415
        return _v
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
