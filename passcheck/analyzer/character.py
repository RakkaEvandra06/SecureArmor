"""Character-class and composition criteria.

Covers presence checks (uppercase / lowercase / digit / special) plus the
two composition checks (variety across classes, uniqueness ratio) — grouped
together because they all reason about the *character makeup* of the
password, as opposed to length (length.py) or anti-patterns (patterns.py).
"""
from __future__ import annotations

from ..constants import (
    CHAR_CLASS_COUNT,
    CHAR_UNIQUENESS_MIN_RATIO,
    CHAR_VARIETY_MIN_CLASSES,
    SCORE_WEIGHTS,
    SPECIAL_CHARS_SET,
)
from ..models import CriterionResult

__all__ = [
    "criterion_has_uppercase",
    "criterion_has_lowercase",
    "criterion_has_digit",
    "criterion_has_special",
    "criterion_char_variety",
    "criterion_char_uniqueness",
]

# ---------------------------------------------------------------------------
# Module-level invariant
# ---------------------------------------------------------------------------

_EXPECTED_CHAR_CLASS_COUNT: int = 5
if CHAR_CLASS_COUNT != _EXPECTED_CHAR_CLASS_COUNT:
    raise AssertionError(
        f"constants.CHAR_CLASS_COUNT ({CHAR_CLASS_COUNT}) no longer matches the "
        f"{_EXPECTED_CHAR_CLASS_COUNT} character-class checks implemented in "
        "criterion_char_variety() below. Update one or the other."
    )

def criterion_has_uppercase(pw: str) -> CriterionResult:
    weight = SCORE_WEIGHTS["has_uppercase"]
    passed = any(c.isupper() for c in pw)
    return CriterionResult(
        name="Uppercase Letter",
        passed=passed,
        score=weight if passed else 0,
        max_score=weight,
        detail="present" if passed else "none found",
        suggestion="" if passed else "Add an uppercase letter (A-Z).",
    )

def criterion_has_lowercase(pw: str) -> CriterionResult:
    weight = SCORE_WEIGHTS["has_lowercase"]
    passed = any(c.islower() for c in pw)
    return CriterionResult(
        name="Lowercase Letter",
        passed=passed,
        score=weight if passed else 0,
        max_score=weight,
        detail="present" if passed else "none found",
        suggestion="" if passed else "Add a lowercase letter (a-z).",
    )

def criterion_has_digit(pw: str) -> CriterionResult:
    weight = SCORE_WEIGHTS["has_digit"]
    passed = any(c.isascii() and c.isdigit() for c in pw)
    return CriterionResult(
        name="Digit",
        passed=passed,
        score=weight if passed else 0,
        max_score=weight,
        detail="present" if passed else "none found",
        suggestion="" if passed else "Add a digit (0-9).",
    )

def criterion_has_special(pw: str) -> CriterionResult:
    weight = SCORE_WEIGHTS["has_special"]
    passed = any(c in SPECIAL_CHARS_SET for c in pw)
    return CriterionResult(
        name="Special Character",
        passed=passed,
        score=weight if passed else 0,
        max_score=weight,
        detail="present" if passed else "none found",
        suggestion="" if passed else "Add a special character (e.g. ! @ # $ % ^ & *).",
    )

# ------------------------------------------------------------------
# Composition criteria
# ------------------------------------------------------------------

def criterion_char_variety(pw: str) -> CriterionResult:
    weight = SCORE_WEIGHTS["char_variety"]
    classes_present = [
        any(c.isupper() for c in pw),
        any(c.islower() for c in pw),
        any(c.isascii() and c.isdigit() for c in pw),
        any(c in SPECIAL_CHARS_SET for c in pw),
        any(not c.isascii() and not c.isupper() and not c.islower() for c in pw),
    ]

    classes = sum(classes_present)
    passed  = classes >= CHAR_VARIETY_MIN_CLASSES
    return CriterionResult(
        name="Character Variety",
        passed=passed,
        score=weight if passed else 0,
        max_score=weight,
        detail=f"{classes}/{CHAR_CLASS_COUNT} character classes used",
        suggestion=(
            ""
            if passed
            else (
                f"Use at least {CHAR_VARIETY_MIN_CLASSES} different character "
                "classes (uppercase, lowercase, digits, symbols, or other "
                "Unicode characters)."
            )
        ),
    )

def criterion_char_uniqueness(graphemes: list[str], length: int) -> CriterionResult:
    weight = SCORE_WEIGHTS["char_uniqueness"]
    unique_count = len(set(graphemes))
    unique_ratio = unique_count / max(length, 1)
    passed = unique_ratio >= CHAR_UNIQUENESS_MIN_RATIO
    return CriterionResult(
        name="Character Uniqueness",
        passed=passed,
        score=weight if passed else 0,
        max_score=weight,
        detail=f"{unique_ratio:.0%} of characters are unique",
        suggestion="" if passed else "Use a wider variety of characters; avoid repeating the same ones.",
    )
