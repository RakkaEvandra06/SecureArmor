"""
analyzer.py — Password analysis engine.

Each criterion is implemented as a private method that returns a
CriterionResult.  The public `analyze()` method orchestrates them all and
assembles a PasswordAnalysis.  No I/O or CLI concerns belong here.
"""

from __future__ import annotations

import math
import string
from collections import Counter

from .constants import (
    COMMON_PASSWORDS,
    ENTROPY_GOOD_THRESHOLD,
    KEYBOARD_PATTERN_MIN_LEN,
    KEYBOARD_PATTERNS,
    LENGTH_EXCELLENT,
    LENGTH_GOOD,
    LENGTH_MINIMUM,
    REPEATED_CHAR_RATIO,
    SCORE_WEIGHTS,
    SPECIAL_CHARS,
    STRENGTH_BANDS,
)
from .models import CriterionResult, PasswordAnalysis


class PasswordAnalyzer:
    """
    Stateless analyzer — instantiate once and call `analyze()` repeatedly.

    Design note: each `_check_*` method is self-contained so that:
    - individual rules can be unit-tested in isolation
    - new rules can be added without touching existing ones (Open/Closed)
    """

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, password: str) -> PasswordAnalysis:
        """Run all checks and return a fully populated PasswordAnalysis."""

        criteria: list[CriterionResult] = [
            self._check_length_minimum(password),
            self._check_length_good(password),
            self._check_length_excellent(password),
            self._check_has_uppercase(password),
            self._check_has_lowercase(password),
            self._check_has_digit(password),
            self._check_has_special(password),
            self._check_char_variety(password),
            self._check_no_common_password(password),
            self._check_no_keyboard_pattern(password),
            self._check_no_repeated_chars(password),
            self._check_entropy(password),
        ]

        score = min(100, sum(c.score for c in criteria))
        label, color = self._strength_band(score)
        suggestions = [c.suggestion for c in criteria if not c.passed and c.suggestion]

        return PasswordAnalysis(
            password=password,
            score=score,
            strength_label=label,
            strength_color=color,
            criteria=criteria,
            entropy_bits=self._calculate_entropy(password),
            suggestions=suggestions,
        )

    # ------------------------------------------------------------------
    # Criterion checks — each returns a CriterionResult
    # ------------------------------------------------------------------

    def _check_length_minimum(self, pw: str) -> CriterionResult:
        passed = len(pw) >= LENGTH_MINIMUM
        w = SCORE_WEIGHTS["length_minimum"]
        return CriterionResult(
            name="Minimum length",
            passed=passed,
            score=w if passed else 0,
            max_score=w,
            detail=f"Length is {len(pw)} characters (minimum {LENGTH_MINIMUM})",
            suggestion=f"Use at least {LENGTH_MINIMUM} characters." if not passed else "",
        )

    def _check_length_good(self, pw: str) -> CriterionResult:
        passed = len(pw) >= LENGTH_GOOD
        w = SCORE_WEIGHTS["length_good"]
        return CriterionResult(
            name="Recommended length",
            passed=passed,
            score=w if passed else 0,
            max_score=w,
            detail=f"Length is {len(pw)} characters (recommended ≥ {LENGTH_GOOD})",
            suggestion=f"Aim for at least {LENGTH_GOOD} characters for better security." if not passed else "",
        )

    def _check_length_excellent(self, pw: str) -> CriterionResult:
        passed = len(pw) >= LENGTH_EXCELLENT
        w = SCORE_WEIGHTS["length_excellent"]
        return CriterionResult(
            name="Excellent length",
            passed=passed,
            score=w if passed else 0,
            max_score=w,
            detail=f"Length is {len(pw)} characters (excellent ≥ {LENGTH_EXCELLENT})",
            suggestion=f"Consider a passphrase of {LENGTH_EXCELLENT}+ characters for maximum length." if not passed else "",
        )

    def _check_has_uppercase(self, pw: str) -> CriterionResult:
        passed = any(c.isupper() for c in pw)
        w = SCORE_WEIGHTS["has_uppercase"]
        return CriterionResult(
            name="Uppercase letters",
            passed=passed,
            score=w if passed else 0,
            max_score=w,
            detail="Contains uppercase letters" if passed else "No uppercase letters found",
            suggestion="Add at least one uppercase letter (A-Z)." if not passed else "",
        )

    def _check_has_lowercase(self, pw: str) -> CriterionResult:
        passed = any(c.islower() for c in pw)
        w = SCORE_WEIGHTS["has_lowercase"]
        return CriterionResult(
            name="Lowercase letters",
            passed=passed,
            score=w if passed else 0,
            max_score=w,
            detail="Contains lowercase letters" if passed else "No lowercase letters found",
            suggestion="Add at least one lowercase letter (a-z)." if not passed else "",
        )

    def _check_has_digit(self, pw: str) -> CriterionResult:
        passed = any(c.isdigit() for c in pw)
        w = SCORE_WEIGHTS["has_digit"]
        return CriterionResult(
            name="Digits",
            passed=passed,
            score=w if passed else 0,
            max_score=w,
            detail="Contains at least one digit" if passed else "No digits found",
            suggestion="Add at least one number (0-9)." if not passed else "",
        )

    def _check_has_special(self, pw: str) -> CriterionResult:
        passed = any(c in SPECIAL_CHARS for c in pw)
        w = SCORE_WEIGHTS["has_special"]
        return CriterionResult(
            name="Special characters",
            passed=passed,
            score=w if passed else 0,
            max_score=w,
            detail="Contains special characters" if passed else "No special characters found",
            suggestion=f"Add special characters such as: {SPECIAL_CHARS[:12]}…" if not passed else "",
        )

    def _check_char_variety(self, pw: str) -> CriterionResult:
        classes = sum([
            any(c.isupper() for c in pw),
            any(c.islower() for c in pw),
            any(c.isdigit() for c in pw),
            any(c in SPECIAL_CHARS for c in pw),
        ])
        passed = classes >= 3
        w = SCORE_WEIGHTS["char_variety"]
        return CriterionResult(
            name="Character variety",
            passed=passed,
            score=w if passed else 0,
            max_score=w,
            detail=f"Uses {classes}/4 character classes",
            suggestion="Mix uppercase, lowercase, digits, and special characters." if not passed else "",
        )

    def _check_no_common_password(self, pw: str) -> CriterionResult:
        is_common = pw.lower() in COMMON_PASSWORDS
        w = SCORE_WEIGHTS["no_common_password"]
        return CriterionResult(
            name="Not a common password",
            passed=not is_common,
            score=0 if is_common else w,
            max_score=w,
            detail="Password appears in common password lists!" if is_common else "Not found in common password lists",
            suggestion="Avoid well-known passwords — they are cracked instantly." if is_common else "",
        )

    def _check_no_keyboard_pattern(self, pw: str) -> CriterionResult:
        pw_lower = pw.lower()
        found: list[str] = []
        for pattern in KEYBOARD_PATTERNS:
            if len(pattern) >= KEYBOARD_PATTERN_MIN_LEN and pattern in pw_lower:
                found.append(pattern)
        passed = len(found) == 0
        w = SCORE_WEIGHTS["no_keyboard_pattern"]
        detail = (
            f"Keyboard patterns detected: {', '.join(found)}"
            if not passed
            else "No obvious keyboard patterns detected"
        )
        return CriterionResult(
            name="No keyboard patterns",
            passed=passed,
            score=0 if not passed else w,
            max_score=w,
            detail=detail,
            suggestion="Avoid sequences like 'qwerty', '123456', 'asdfgh'." if not passed else "",
        )

    def _check_no_repeated_chars(self, pw: str) -> CriterionResult:
        if not pw:
            return CriterionResult(
                name="No excessive repetition",
                passed=False,
                score=0,
                max_score=SCORE_WEIGHTS["no_repeated_chars"],
                detail="Empty password",
            )
        counts = Counter(pw.lower())
        most_common_char, most_common_count = counts.most_common(1)[0]
        ratio = most_common_count / len(pw)
        passed = ratio < REPEATED_CHAR_RATIO
        w = SCORE_WEIGHTS["no_repeated_chars"]
        return CriterionResult(
            name="No excessive repetition",
            passed=passed,
            score=w if passed else 0,
            max_score=w,
            detail=(
                f"'{most_common_char}' appears {most_common_count}×"
                f" ({ratio:.0%} of password)"
            ),
            suggestion="Avoid repeating the same character too many times." if not passed else "",
        )

    def _check_entropy(self, pw: str) -> CriterionResult:
        bits = self._calculate_entropy(pw)
        passed = bits >= ENTROPY_GOOD_THRESHOLD
        w = SCORE_WEIGHTS["entropy_bonus"]
        return CriterionResult(
            name="Entropy",
            passed=passed,
            score=w if passed else 0,
            max_score=w,
            detail=f"Estimated entropy: {bits:.1f} bits (good ≥ {ENTROPY_GOOD_THRESHOLD:.0f} bits)",
            suggestion="Increase length and character variety to raise entropy." if not passed else "",
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _calculate_entropy(pw: str) -> float:
        """
        Shannon-style entropy estimation based on character pool size.

        Pool size is determined by which character classes are present,
        then entropy = log2(pool_size) × length.
        """
        if not pw:
            return 0.0

        pool = 0
        if any(c.islower() for c in pw):
            pool += 26
        if any(c.isupper() for c in pw):
            pool += 26
        if any(c.isdigit() for c in pw):
            pool += 10
        if any(c in SPECIAL_CHARS for c in pw):
            pool += len(SPECIAL_CHARS)
        if any(c not in string.printable for c in pw):
            pool += 32  # some non-ASCII bonus

        if pool == 0:
            return 0.0

        return math.log2(pool) * len(pw)

    @staticmethod
    def _strength_band(score: int) -> tuple[str, str]:
        for threshold, label, color in STRENGTH_BANDS:
            if score >= threshold:
                return label, color
        return "Very Weak", "bright_red"
