"""Anti-pattern criteria: common passwords, keyboard walks, repeated chars.

Grouped together because all three are "penalise known-bad shapes" checks
that share the same skip-cascade logic (common password detected -> skip
the others to avoid double-penalising the same weakness).
"""
from __future__ import annotations

from collections import Counter

from ..constants import KEYBOARD_PATTERNS, REPEATED_CHAR_RATIO, SCORE_WEIGHTS
from ..models import CriterionResult, SkipReason
from ..utils import LEET_TABLE

__all__ = [
    "criterion_no_common_password",
    "criterion_no_keyboard_pattern",
    "criterion_no_repeated_chars",
]

def criterion_no_common_password(
    *, is_common: bool, can_lookup: bool, length: int,
    has_ascii_residue: bool,
) -> CriterionResult:
    weight = SCORE_WEIGHTS["no_common_password"]

    if not can_lookup:
        if length == 0:
            return CriterionResult(
                name="Not a Common Password",
                passed=False,
                score=0,
                max_score=weight,
                detail="skipped, password is empty",
                skipped=True,
                skip_reason=SkipReason.EMPTY_PASSWORD,
            )
        if has_ascii_residue:
            return CriterionResult(
                name="Not a Common Password",
                passed=False,
                score=0,
                max_score=weight,
                detail="skipped, password is too short for common-password lookup",
                skipped=True,
                skip_reason=SkipReason.TOO_SHORT_FOR_LOOKUP,
            )
        return CriterionResult(
            name="Not a Common Password",
            passed=False,
            score=0,
            max_score=weight,
            detail="skipped, password has no ASCII-equivalent form to check",
            skipped=True,
            skip_reason=SkipReason.UNICODE_ONLY_PASSWORD,
        )

    passed = not is_common
    return CriterionResult(
        name="Not a Common Password",
        passed=passed,
        score=weight if passed else 0,
        max_score=weight,
        detail="not found in common password list" if passed else "found in common password list",
        suggestion="" if passed else "Choose a password that isn't on common password lists.",
    )

def criterion_no_keyboard_pattern(
    pw: str, *, is_common: bool, can_lookup: bool, length: int,
    has_ascii_residue: bool,
) -> CriterionResult:
    weight = SCORE_WEIGHTS["no_keyboard_pattern"]

    if is_common:
        return CriterionResult(
            name="No Keyboard Pattern",
            passed=False,
            score=0,
            max_score=weight,
            detail="skipped, already penalised as a common password",
            skipped=True,
            skip_reason=SkipReason.COMMON_PASSWORD_DETECTED,
        )

    if not can_lookup:
        if length == 0:
            return CriterionResult(
                name="No Keyboard Pattern",
                passed=False,
                score=0,
                max_score=weight,
                detail="skipped, password is empty",
                skipped=True,
                skip_reason=SkipReason.EMPTY_PASSWORD,
            )
        if has_ascii_residue:
            return CriterionResult(
                name="No Keyboard Pattern",
                passed=False,
                score=0,
                max_score=weight,
                detail="skipped, password is too short for keyboard-pattern lookup",
                skipped=True,
                skip_reason=SkipReason.TOO_SHORT_FOR_LOOKUP,
            )
        return CriterionResult(
            name="No Keyboard Pattern",
            passed=False,
            score=0,
            max_score=weight,
            detail="skipped, password has no ASCII-equivalent form to check",
            skipped=True,
            skip_reason=SkipReason.UNICODE_ONLY_PASSWORD,
        )

    pw_lower     = pw.lower()
    pw_normalised = pw_lower.translate(LEET_TABLE)
    hit = next(
        (
            pattern
            for pattern in KEYBOARD_PATTERNS
            if pattern in pw_lower or pattern in pw_normalised
        ),
        None,
    )
    passed = hit is None
    return CriterionResult(
        name="No Keyboard Pattern",
        passed=passed,
        score=weight if passed else 0,
        max_score=weight,
        detail="no keyboard-walk pattern found" if passed else f"contains keyboard pattern '{hit}'",
        suggestion="" if passed else "Avoid keyboard sequences like 'qwerty' or '123456'.",
    )

def criterion_no_repeated_chars(
    graphemes: list[str], length: int, *, is_common: bool
) -> CriterionResult:
    weight = SCORE_WEIGHTS["no_repeated_chars"]

    if is_common:
        return CriterionResult(
            name="No Repeated Characters",
            passed=False,
            score=0,
            max_score=weight,
            detail="skipped, already penalised as a common password",
            skipped=True,
            skip_reason=SkipReason.COMMON_PASSWORD_DETECTED,
        )
    if length == 0:
        return CriterionResult(
            name="No Repeated Characters",
            passed=False,
            score=0,
            max_score=weight,
            detail="skipped, password is empty",
            skipped=True,
            skip_reason=SkipReason.EMPTY_PASSWORD,
        )

    counter   = Counter(graphemes)
    max_freq  = counter.most_common(1)[0][1] if counter else 0
    ratio     = max_freq / max(length, 1)   # length == len(graphemes)
    passed    = ratio < REPEATED_CHAR_RATIO
    return CriterionResult(
        name="No Repeated Characters",
        passed=passed,
        score=weight if passed else 0,
        max_score=weight,
        detail=f"most-repeated character makes up {ratio:.0%} of the password",
        suggestion="" if passed else "Avoid repeating the same character too many times.",
    )
