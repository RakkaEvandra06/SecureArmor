from __future__ import annotations

__all__ = [
    "SCORE_WEIGHTS",
    "LENGTH_MINIMUM",
    "LENGTH_GOOD",
    "LENGTH_EXCELLENT",
    "LENGTH_MAXIMUM",
    "ENTROPY_GOOD_THRESHOLD",
    "REPEATED_CHAR_RATIO",
    "STRENGTH_BANDS",
    "SPECIAL_CHARS",
    "KEYBOARD_PATTERNS",
    "KEYBOARD_PATTERN_MIN_LEN",
    "COMMON_PASSWORDS",
]

# ---------------------------------------------------------------------------
# Scoring weights
# ---------------------------------------------------------------------------
SCORE_WEIGHTS: dict[str, int] = {
    "length_minimum":      10,  # meets bare minimum length
    "length_good":         10,  # meets recommended length
    "length_excellent":     5,  # extra credit for very long passwords
    "has_uppercase":       10,  # at least one uppercase letter
    "has_lowercase":        5,  # at least one lowercase letter
    "has_digit":           10,  # at least one digit
    "has_special":         15,  # at least one special character
    "char_variety":        10,  # uses 3+ of the 4 character classes
    "no_common_password":  10,  # not a known common password
    "no_keyboard_pattern": 10,  # no obvious keyboard sequence
    "no_repeated_chars":    5,  # no excessive character repetition
    "entropy_bonus":       10,  # entropy >= threshold
}

assert all(v >= 0 for v in SCORE_WEIGHTS.values()), (
    "All SCORE_WEIGHTS values must be non-negative"
)
assert sum(SCORE_WEIGHTS.values()) >= 100, (
    f"SCORE_WEIGHTS sum to {sum(SCORE_WEIGHTS.values())}, must be >= 100 "
    "so that a perfect password can reach a score of 100"
)

# ---------------------------------------------------------------------------
# Length thresholds
# ---------------------------------------------------------------------------
LENGTH_MINIMUM:   int = 8
LENGTH_GOOD:      int = 12
LENGTH_EXCELLENT: int = 20
LENGTH_MAXIMUM:   int = 1_000   # guard against pathological inputs

assert LENGTH_MINIMUM < LENGTH_GOOD < LENGTH_EXCELLENT < LENGTH_MAXIMUM, (
    "Length thresholds must be strictly increasing"
)

# ---------------------------------------------------------------------------
# Entropy (bits)
# ---------------------------------------------------------------------------
ENTROPY_GOOD_THRESHOLD: float = 50.0   # qualifies for entropy bonus

# ---------------------------------------------------------------------------
# Repeated characters — flag if any char appears >= this fraction of length
# ---------------------------------------------------------------------------
REPEATED_CHAR_RATIO: float = 0.4

assert 0.0 < REPEATED_CHAR_RATIO < 1.0, (
    "REPEATED_CHAR_RATIO must be in (0, 1)"
)

# ---------------------------------------------------------------------------
# Strength band definitions  (score lower-bound -> label, colour code)
# Sorted descending so the first match wins.
# ---------------------------------------------------------------------------
STRENGTH_BANDS: list[tuple[int, str, str]] = [
    (80, "Very Strong", "bright_green"),
    (60, "Strong",      "green"),
    (40, "Medium",      "yellow"),
    (20, "Weak",        "red"),
    ( 0, "Very Weak",   "bright_red"),
]

assert STRENGTH_BANDS == sorted(STRENGTH_BANDS, key=lambda t: t[0], reverse=True), (
    "STRENGTH_BANDS must be sorted by threshold descending"
)

# ---------------------------------------------------------------------------
# Special characters recognised by the checker
# ---------------------------------------------------------------------------
SPECIAL_CHARS: str = r"""!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~"""

# ---------------------------------------------------------------------------
# Keyboard walk patterns (lower-cased; checker tests substrings of length >=
# KEYBOARD_PATTERN_MIN_LEN).  Entries must not duplicate COMMON_PASSWORDS to
# avoid hidden double-penalties.
# ---------------------------------------------------------------------------
KEYBOARD_PATTERNS: list[str] = [
    # Horizontal rows — left-to-right
    "qwerty", "qwertz", "azerty",
    "asdfgh", "zxcvbn",
    # Horizontal rows — right-to-left (reverses)
    "ytrewq",
    "hgfdsa", "nbvcxz",
    # Numeric sequences — ascending / descending
    "234567", "345678", "456789", "567890",
    "987654", "876543", "765432",
    "0987654321",
    # Alphabetical sequences
    "abcdef", "abcdefg", "abcdefgh",
    # Vertical column walks (left column, second column, third column)
    "1qaz", "2wsx", "3edc",
    # Vertical column walks — reversed
    "zaq1", "xsw2", "cde3",
]

KEYBOARD_PATTERN_MIN_LEN: int = 4

# ---------------------------------------------------------------------------
# Common passwords list (subset — extend or load from file in production).
# All entries MUST be lower-case; the checker compares pw.lower() against
# this set, so upper-case entries would never match.
# ---------------------------------------------------------------------------
COMMON_PASSWORDS: frozenset[str] = frozenset({
    "password", "password1", "password123", "123456", "123456789",
    "12345678", "12345", "1234567", "abc123",
    "monkey", "1234567890", "letmein", "trustno1", "dragon",
    "baseball", "iloveyou", "master", "sunshine", "ashley",
    "bailey", "passw0rd", "shadow", "123123", "654321",
    "superman", "qazwsx", "michael", "football", "password!",
    "welcome", "login", "admin", "root", "test",
    "hello", "charlie", "donald", "password2", "qwerty123",
    "1q2w3e4r", "mustang", "access", "joshua", "solo",
    "starwars", "master1", "hello123", "thomas", "jordan",
    "harley", "ranger", "daniel", "hunter", "andrew",
    "11111111", "111111", "000000", "pass", "passpass",
})

assert all(entry == entry.lower() for entry in COMMON_PASSWORDS), (
    "All COMMON_PASSWORDS entries must be lower-case"
)

# Detect overlap between the two lists and fail fast.  The temporary name
# is deleted immediately so it never leaks into the module namespace.
_overlap = frozenset(KEYBOARD_PATTERNS) & COMMON_PASSWORDS
assert not _overlap, (
    f"Entries in both KEYBOARD_PATTERNS and COMMON_PASSWORDS: {sorted(_overlap)}. "
    "This causes a hidden double-penalty. Remove duplicates from one list."
)
del _overlap