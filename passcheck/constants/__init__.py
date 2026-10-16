"""Tunable constants, thresholds, and reference data for PassCheck's scorer."""
from __future__ import annotations

from .common_passwords_loader import (
    get_common_passwords,
    is_external_wordlist_loaded,
    is_wordlist_sufficient,
)
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
    DICT_ATTACK_ADVISORY_ENTROPY_BITS,
    ENTROPY_FLOOR_MEDIUM_BITS,
    ENTROPY_FLOOR_WEAK_BITS,
    ENTROPY_GOOD_THRESHOLD,
    KEYBOARD_PATTERN_MIN_ABS_CHARS,
    KEYBOARD_PATTERN_MIN_FRACTION,
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
    "ENTROPY_FLOOR_WEAK_BITS",
    "ENTROPY_FLOOR_MEDIUM_BITS",
    "REPEATED_CHAR_RATIO",
    "SHANNON_WEIGHT",
    "STRENGTH_BANDS",
    "VALID_COLOUR_KEYS",
    "SPECIAL_CHARS",
    "SPECIAL_CHARS_SET",
    "SPECIAL_CHARS_INCLUDES_SPACE",
    "KEYBOARD_PATTERNS",
    "KEYBOARD_PATTERN_MIN_FRACTION",
    "KEYBOARD_PATTERN_MIN_ABS_CHARS",
    "get_common_passwords",
    "is_wordlist_sufficient",
    "is_external_wordlist_loaded",
    "DICT_ATTACK_ADVISORY_ENTROPY_BITS",
    "CHAR_UNIQUENESS_MIN_RATIO",
    "CHAR_VARIETY_MIN_CLASSES",
    "CHAR_CLASS_COUNT",
    "MAX_PERCENT_FOR_KNOWN_WEAK_PATTERN",
]

def __getattr__(name: str) -> object:

    if name == "NON_ASCII_POOL_SIZE":
        import warnings
        warnings.warn(
            "passcheck.constants.NON_ASCII_POOL_SIZE is deprecated and will be "
            "removed in v2.0.0.  The constant is no longer used for entropy "
            "calculation, passcheck.analyzer.entropy now derives per-block "
            "pool sizes from _UNICODE_BLOCK_POOLS (fallback: 128). "
            "Remove any references to NON_ASCII_POOL_SIZE from your code.",
            DeprecationWarning,
            stacklevel=2,
        )
        # Import from the defining module so we don't duplicate the literal.
        from .thresholds import NON_ASCII_POOL_SIZE as _v  # noqa: PLC0415
        return _v
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")