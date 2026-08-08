"""Keyboard-walk pattern data (e.g. "qwerty", "123456") and its expansion."""
from __future__ import annotations

__all__ = ["KEYBOARD_PATTERNS"]

_KEYBOARD_PATTERN_MIN_LEN: int = 4

_BASE_KEYBOARD_PATTERNS: tuple[str, ...] = (
    # ── Horizontal rows (left-to-right) ─────────────────────────────────────
    "qwerty", "qwertz", "azerty",
    # Middle row
    "asdfgh",
    # Bottom row
    "zxcvbn",
    "ytrewq",        # reverse of qwerty top row
    "poiuyt",        # right half of top row, reversed
    "lkjhgf",        # right half of middle row, reversed
    "lkjhgfdsa",     # full middle row, reversed
    "mnbvcxz",       # bottom row, reversed

    # ── Numeric sequences ────────────────────────────────────────────────────
    "123456",
    "234567", "345678", "456789", "567890",
    "987654", "876543", "765432",
    "0987654321",

    # ── Alphabetical sequences ───────────────────────────────────────────────
    "abcdef", "abcdefg", "abcdefgh",

    # ── Vertical single-column walks ─────────────────────────────────────────
    "1qaz", "2wsx", "3edc",

    # ── Multi-column vertical walks ──────────────────────────────────────────
    "qazwsx", "wsxedc", "edcrfv", "rfvtgb",

    # ── Mixed numeric-alpha diagonal walks ───────────────────────────────────
    "1q2w3e", "q2w3e4", "1q2w3e4r",

    # ── Shifted-key numeric sequences (Shift+1..6 on QWERTY = !@#$%^) ───────
    "!@#$%^", "!@#$%^&",

    # ── Numpad walks ─────────────────────────────────────────────────────────
    "7894561230",    # numpad rows top-to-bottom
    "0321654987",    # numpad rows bottom-to-top
    "741852963",     # numpad left column → middle → right (vertical sweep)
    "369258147",     # numpad right column → middle → left
    "159357",        # numpad diagonal
    "753159",        # reverse diagonal
)

# Expand each base pattern to include its reverse; deduplicate while preserving
# order; drop any variant shorter than the minimum length.
KEYBOARD_PATTERNS: tuple[str, ...] = tuple(dict.fromkeys(
    variant
    for base in _BASE_KEYBOARD_PATTERNS
    for variant in (base, base[::-1])
    if len(variant) >= _KEYBOARD_PATTERN_MIN_LEN
))

_short_patterns = [p for p in KEYBOARD_PATTERNS if len(p) < _KEYBOARD_PATTERN_MIN_LEN]
if _short_patterns:
    raise ValueError(
        f"Every KEYBOARD_PATTERNS entry must be at least "
        f"{_KEYBOARD_PATTERN_MIN_LEN} characters. "
        f"Offending entries: {_short_patterns}."
    )
del _short_patterns
