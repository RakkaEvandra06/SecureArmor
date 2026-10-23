"""Character-class and composition criteria."""
from __future__ import annotations

from ..constants import (
    CHAR_CLASS_COUNT,
    CHAR_UNIQUENESS_MIN_RATIO,
    CHAR_VARIETY_MIN_CLASSES,
    SCORE_WEIGHTS,
    SPECIAL_CHARS_SET,
)
from ..models import CriterionResult, SkipReason
from ..utils import grapheme_unique_count

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

# ---------------------------------------------------------------------------
# Individual character-class criteria
# ---------------------------------------------------------------------------

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
    # Deliberately restricted to ASCII digits (0-9).  Non-ASCII digit
    # characters such as Arabic-Indic numerals (٣) are counted under class 5
    # ("other Unicode") in criterion_char_variety, not here.
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

# ---------------------------------------------------------------------------
# Composition criteria
# ---------------------------------------------------------------------------

def criterion_char_variety(pw: str) -> CriterionResult:
    """Score based on the number of distinct character classes present."""
    weight = SCORE_WEIGHTS["char_variety"]
    classes_present = [
        any(c.isupper() for c in pw),                           # class 1: uppercase (any script)
        any(c.islower() for c in pw),                           # class 2: lowercase (any script)
        any(c.isascii() and c.isdigit() for c in pw),           # class 3: ASCII digit 0-9
        any(c in SPECIAL_CHARS_SET for c in pw),                # class 4: ASCII special char
        any(                                                    # class 5: other Unicode —
            not c.isascii()                                     #   non-ASCII chars not in
            and not c.isupper()                                 #   classes 1 or 2; includes
            and not c.islower()                                 #   non-ASCII digits, CJK,
            for c in pw                                         #   emoji, symbols, etc.
        ),
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
    if length == 0:
        return CriterionResult(
            name="Character Uniqueness",
            passed=False,
            score=0,
            max_score=weight,
            detail="skipped, password is empty",
            skipped=True,
            skip_reason=SkipReason.EMPTY_PASSWORD,
        )
    unique_count = grapheme_unique_count(graphemes)
    unique_ratio = unique_count / length
    passed = unique_ratio >= CHAR_UNIQUENESS_MIN_RATIO
    return CriterionResult(
        name="Character Uniqueness",
        passed=passed,
        score=weight if passed else 0,
        max_score=weight,
        detail=f"{unique_ratio:.0%} of characters are unique",
        suggestion="" if passed else "Use a wider variety of characters; avoid repeating the same ones.",
    )