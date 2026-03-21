"""
constants.py — All hardcoded values, thresholds, and scoring weights live here.
Changing behaviour should mean changing this file, not hunting through logic.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Scoring weights  (must sum ≤ 100; penalties are subtracted)
# ---------------------------------------------------------------------------
SCORE_WEIGHTS: dict[str, int] = {
    "length_minimum": 10,       # meets bare minimum length
    "length_good": 10,          # meets recommended length
    "length_excellent": 5,      # extra credit for very long passwords
    "has_uppercase": 10,        # at least one uppercase letter
    "has_lowercase": 5,         # at least one lowercase letter
    "has_digit": 10,            # at least one digit
    "has_special": 15,          # at least one special character
    "char_variety": 10,         # uses 3+ of the 4 character classes
    "no_common_password": 10,   # not a known common password
    "no_keyboard_pattern": 10,  # no obvious keyboard sequence
    "no_repeated_chars": 5,     # no excessive character repetition
    "entropy_bonus": 10,        # entropy ≥ threshold
}

# ---------------------------------------------------------------------------
# Length thresholds
# ---------------------------------------------------------------------------
LENGTH_MINIMUM: int = 8
LENGTH_GOOD: int = 12
LENGTH_EXCELLENT: int = 20

# ---------------------------------------------------------------------------
# Entropy (bits)
# ---------------------------------------------------------------------------
ENTROPY_GOOD_THRESHOLD: float = 50.0   # bits — qualifies for entropy bonus

# ---------------------------------------------------------------------------
# Repeated characters — flag if any char appears ≥ this fraction of length
# ---------------------------------------------------------------------------
REPEATED_CHAR_RATIO: float = 0.4

# ---------------------------------------------------------------------------
# Strength band definitions  (score lower-bound → label, colour code)
# ---------------------------------------------------------------------------
STRENGTH_BANDS: list[tuple[int, str, str]] = [
    (80, "Very Strong", "bright_green"),
    (60, "Strong",      "green"),
    (40, "Medium",      "yellow"),
    (20, "Weak",        "red"),
    (0,  "Very Weak",   "bright_red"),
]

# ---------------------------------------------------------------------------
# Special characters recognised by the checker
# ---------------------------------------------------------------------------
SPECIAL_CHARS: str = r"""!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~"""

# ---------------------------------------------------------------------------
# Keyboard walk patterns (lower-cased; checker tests substrings of length ≥ 4)
# ---------------------------------------------------------------------------
KEYBOARD_PATTERNS: list[str] = [
    "qwerty", "qwertz", "azerty",
    "asdfgh", "zxcvbn", "qazwsx",
    "123456", "234567", "345678", "456789", "567890",
    "12345678", "123456789", "1234567890",
    "987654", "876543", "765432", "654321",
    "abcdef", "abcdefg", "abcdefgh",
    "pass", "password", "letmein", "welcome",
    "iloveyou", "admin", "login", "master",
    "0987654321",
]

KEYBOARD_PATTERN_MIN_LEN: int = 4

# ---------------------------------------------------------------------------
# Common passwords list (subset — extend or load from file in production)
# ---------------------------------------------------------------------------
COMMON_PASSWORDS: frozenset[str] = frozenset({
    "password", "password1", "password123", "123456", "123456789",
    "12345678", "12345", "1234567", "qwerty", "abc123",
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
