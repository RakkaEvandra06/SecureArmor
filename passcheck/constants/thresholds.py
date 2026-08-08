"""Numeric thresholds, strength bands, and the weak-pattern score cap.

Grouped together because they share one trait: every value here is a
tunable knob compared against a number computed for the password
(length, entropy, ratios), as opposed to pattern/word *data* 
(see keyboard_patterns.py and common_passwords_data.py).
"""
from __future__ import annotations

__all__ = [
    "LENGTH_MINIMUM",
    "LENGTH_GOOD",
    "LENGTH_EXCELLENT",
    "LENGTH_MAXIMUM",
    "ENTROPY_GOOD_THRESHOLD",
    "SHANNON_WEIGHT",
    "NON_ASCII_POOL_SIZE",
    "REPEATED_CHAR_RATIO",
    "CHAR_UNIQUENESS_MIN_RATIO",
    "CHAR_CLASS_COUNT",
    "CHAR_VARIETY_MIN_CLASSES",
    "STRENGTH_BANDS",
    "VALID_COLOUR_KEYS",
    "MAX_PERCENT_FOR_KNOWN_WEAK_PATTERN",
]

# ---------------------------------------------------------------------------
# Length thresholds
# ---------------------------------------------------------------------------

LENGTH_MINIMUM:   int = 8
LENGTH_GOOD:      int = 12
LENGTH_EXCELLENT: int = 20
LENGTH_MAXIMUM:   int = 128

if not (LENGTH_MINIMUM < LENGTH_GOOD < LENGTH_EXCELLENT < LENGTH_MAXIMUM):
    raise ValueError(
        "Length thresholds must be strictly increasing: "
        f"LENGTH_MINIMUM={LENGTH_MINIMUM}, LENGTH_GOOD={LENGTH_GOOD}, "
        f"LENGTH_EXCELLENT={LENGTH_EXCELLENT}, LENGTH_MAXIMUM={LENGTH_MAXIMUM}."
    )

# ---------------------------------------------------------------------------
# Entropy (bits)
# ---------------------------------------------------------------------------

ENTROPY_GOOD_THRESHOLD: float = 50.0

SHANNON_WEIGHT: float = 0.6   # blend factor: 40 % pool, 60 % Shannon

if not (0.0 < SHANNON_WEIGHT < 1.0):
    raise ValueError(f"SHANNON_WEIGHT must be in (0, 1), got {SHANNON_WEIGHT!r}.")

NON_ASCII_POOL_SIZE: int = 32_768

# ---------------------------------------------------------------------------
# Repeated-character threshold
# ---------------------------------------------------------------------------

REPEATED_CHAR_RATIO: float = 0.4  # fails at >= this ratio (strict less-than check)

if not (0.0 < REPEATED_CHAR_RATIO < 1.0):
    raise ValueError(
        f"REPEATED_CHAR_RATIO must be in (0, 1), got {REPEATED_CHAR_RATIO!r}."
    )

# ---------------------------------------------------------------------------
# Composition thresholds
# ---------------------------------------------------------------------------

CHAR_UNIQUENESS_MIN_RATIO: float = 0.6

if not (0.0 < CHAR_UNIQUENESS_MIN_RATIO <= 1.0):
    raise ValueError(
        f"CHAR_UNIQUENESS_MIN_RATIO must be in (0, 1], "
        f"got {CHAR_UNIQUENESS_MIN_RATIO!r}."
    )

CHAR_CLASS_COUNT: int = 5

CHAR_VARIETY_MIN_CLASSES: int = 3

if not (2 <= CHAR_VARIETY_MIN_CLASSES <= CHAR_CLASS_COUNT):
    raise ValueError(
        f"CHAR_VARIETY_MIN_CLASSES must be in [2, {CHAR_CLASS_COUNT}] "
        f"(the analyser measures at most {CHAR_CLASS_COUNT} character classes). "
        f"Got {CHAR_VARIETY_MIN_CLASSES!r}."
    )

# ---------------------------------------------------------------------------
# Strength bands  (threshold, label, colour_key) — sorted descending by threshold
# ---------------------------------------------------------------------------

# Immutable tuple so post-import mutation raises TypeError.
STRENGTH_BANDS: tuple[tuple[int, str, str], ...] = (
    (80, "Very Strong", "bright_green"),
    (60, "Strong",      "green"),
    (40, "Medium",      "yellow"),
    (20, "Weak",        "red"),
    ( 0, "Very Weak",   "bright_red"),
)

_sorted_bands = tuple(sorted(STRENGTH_BANDS, key=lambda t: t[0], reverse=True))
if STRENGTH_BANDS != _sorted_bands:
    raise ValueError(
        "STRENGTH_BANDS must be sorted by threshold descending. "
        f"Expected order: {list(_sorted_bands)}."
    )
del _sorted_bands

if STRENGTH_BANDS[-1][0] != 0:
    raise ValueError(
        "STRENGTH_BANDS must contain a catch-all entry with threshold 0 "
        f"as its last element. Last entry found: {STRENGTH_BANDS[-1]}."
    )

# Derive the set of valid colour keys directly from the bands definition.
VALID_COLOUR_KEYS: frozenset[str] = frozenset(colour for _, _, colour in STRENGTH_BANDS)

# ---------------------------------------------------------------------------
# Known-weak-pattern score cap
# ---------------------------------------------------------------------------

MAX_PERCENT_FOR_KNOWN_WEAK_PATTERN: int = 25

if not (0 <= MAX_PERCENT_FOR_KNOWN_WEAK_PATTERN <= 100):
    raise ValueError(
        "MAX_PERCENT_FOR_KNOWN_WEAK_PATTERN must be in [0, 100], got "
        f"{MAX_PERCENT_FOR_KNOWN_WEAK_PATTERN!r}."
    )
