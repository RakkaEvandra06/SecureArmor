from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass, field
from types import MappingProxyType

from .constants import (
    COMMON_PASSWORDS,
    ENTROPY_GOOD_THRESHOLD,
    KEYBOARD_PATTERNS,
    LENGTH_EXCELLENT,
    LENGTH_GOOD,
    LENGTH_MAXIMUM,
    LENGTH_MINIMUM,
    REPEATED_CHAR_RATIO,
    SCORE_WEIGHTS,
    SHANNON_WEIGHT,
    SPECIAL_CHARS,
    STRENGTH_BANDS,
)
from .models import CriterionResult, PasswordAnalysis

@dataclass(frozen=True)
class _CharProfile:
    """Immutable character-level profile of a password."""

    length:        int
    has_upper:     bool
    has_lower:     bool
    has_digit:     bool
    has_special:   bool
    has_non_ascii: bool

    # Read-only frequency map: char → occurrence count.
    char_counts: MappingProxyType  # MappingProxyType[str, int]
    _sorted_counts: tuple[tuple[str, int], ...] = field(
        init=False, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "_sorted_counts",
            tuple(
                sorted(self.char_counts.items(), key=lambda kv: kv[1], reverse=True)
            ),
        )

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def from_password(cls, pw: str) -> _CharProfile:
        """Build a profile from *pw* in a genuine single O(n) pass."""
        has_upper     = False
        has_lower     = False
        has_digit     = False
        has_special   = False
        has_non_ascii = False
        counts: Counter[str] = Counter()

        for c in pw:
            counts[c] += 1
            if not has_upper     and c.isupper():         has_upper     = True
            if not has_lower     and c.islower():         has_lower     = True
            if not has_digit     and c.isdigit():         has_digit     = True
            if not has_special   and c in SPECIAL_CHARS:  has_special   = True
            if not has_non_ascii and ord(c) > 127:        has_non_ascii = True

        # Freeze the frequency map before handing it to the dataclass.
        # _sorted_counts is derived automatically via __post_init__.
        frozen_map = MappingProxyType(dict(counts))

        return cls(
            length        = len(pw),
            has_upper     = has_upper,
            has_lower     = has_lower,
            has_digit     = has_digit,
            has_special   = has_special,
            has_non_ascii = has_non_ascii,
            char_counts   = frozen_map,
        )

    # ------------------------------------------------------------------
    # Public accessor
    # ------------------------------------------------------------------

    def most_common(self, n: int = 1) -> tuple[tuple[str, int], ...]:
        """Return the *n* most common ``(char, count)`` pairs, descending."""
        return self._sorted_counts[:n]

class PasswordAnalyzer:
    """Stateless password strength analyser."""

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, password: str) -> PasswordAnalysis:
        """Analyse *password* and return a fully populated :class:`PasswordAnalysis`."""
        if not password:
            raise ValueError("Password must not be empty.")
        if len(password) > LENGTH_MAXIMUM:
            raise ValueError(
                f"Password length {len(password)} exceeds the maximum "
                f"allowed length of {LENGTH_MAXIMUM} characters."
            )

        profile           = _CharProfile.from_password(password)
        entropy_bits      = self._calculate_entropy(profile)
        repetition_result = self._check_no_repeated_chars(profile)
        entropy_result    = self._check_entropy(
            entropy_bits, repetition_passed=repetition_result.passed
        )

        criteria_list: list[CriterionResult] = [
            self._check_length_minimum(profile),
            self._check_length_good(profile),
            self._check_length_excellent(profile),
            self._check_has_uppercase(profile),
            self._check_has_lowercase(profile),
            self._check_has_digit(profile),
            self._check_has_special(profile),
            self._check_char_variety(profile),
            self._check_no_common_password(password),
            self._check_no_keyboard_pattern(password),
            repetition_result,
            entropy_result,
        ]

        score            = min(100, sum(c.score for c in criteria_list))
        label, color     = self._strength_band(score)
        suggestions_list = [
            c.suggestion for c in criteria_list if not c.passed and c.suggestion
        ]

        return PasswordAnalysis(
            password       = password,
            score          = score,
            strength_label = label,
            strength_color = color,
            criteria       = tuple(criteria_list),
            entropy_bits   = entropy_bits,
            suggestions    = tuple(suggestions_list),
        )

    # ------------------------------------------------------------------
    # Criterion checks — each returns a CriterionResult
    # ------------------------------------------------------------------

    def _check_length_minimum(self, profile: _CharProfile) -> CriterionResult:
        """Award points if the password meets the bare minimum length."""
        passed = profile.length >= LENGTH_MINIMUM
        w      = SCORE_WEIGHTS["length_minimum"]
        return CriterionResult(
            name       = "Minimum length",
            passed     = passed,
            score      = w if passed else 0,
            max_score  = w,
            detail     = f"Length is {profile.length} characters (minimum {LENGTH_MINIMUM})",
            suggestion = f"Use at least {LENGTH_MINIMUM} characters." if not passed else "",
        )

    def _check_length_good(self, profile: _CharProfile) -> CriterionResult:
        """Award points if the password meets the recommended length."""
        passed = profile.length >= LENGTH_GOOD
        w      = SCORE_WEIGHTS["length_good"]
        return CriterionResult(
            name       = "Recommended length",
            passed     = passed,
            score      = w if passed else 0,
            max_score  = w,
            detail     = (
                f"Length is {profile.length} characters "
                f"(recommended >= {LENGTH_GOOD})"
            ),
            suggestion = (
                f"Aim for at least {LENGTH_GOOD} characters for better security."
                if not passed else ""
            ),
        )

    def _check_length_excellent(self, profile: _CharProfile) -> CriterionResult:
        """Award bonus points for an excellent (very long) password."""
        passed = profile.length >= LENGTH_EXCELLENT
        w      = SCORE_WEIGHTS["length_excellent"]
        return CriterionResult(
            name       = "Excellent length",
            passed     = passed,
            score      = w if passed else 0,
            max_score  = w,
            detail     = (
                f"Length is {profile.length} characters "
                f"(excellent >= {LENGTH_EXCELLENT})"
            ),
            suggestion = (
                f"Consider a passphrase of {LENGTH_EXCELLENT}+ characters "
                "for maximum security."
                if not passed else ""
            ),
        )

    def _check_has_uppercase(self, profile: _CharProfile) -> CriterionResult:
        """Award points if the password contains at least one uppercase letter."""
        w = SCORE_WEIGHTS["has_uppercase"]
        return CriterionResult(
            name       = "Uppercase letters",
            passed     = profile.has_upper,
            score      = w if profile.has_upper else 0,
            max_score  = w,
            detail     = (
                "Contains uppercase letters"
                if profile.has_upper
                else "No uppercase letters found"
            ),
            suggestion = (
                "Add at least one uppercase letter (A-Z)."
                if not profile.has_upper else ""
            ),
        )

    def _check_has_lowercase(self, profile: _CharProfile) -> CriterionResult:
        """Award points if the password contains at least one lowercase letter."""
        w = SCORE_WEIGHTS["has_lowercase"]
        return CriterionResult(
            name       = "Lowercase letters",
            passed     = profile.has_lower,
            score      = w if profile.has_lower else 0,
            max_score  = w,
            detail     = (
                "Contains lowercase letters"
                if profile.has_lower
                else "No lowercase letters found"
            ),
            suggestion = (
                "Add at least one lowercase letter (a-z)."
                if not profile.has_lower else ""
            ),
        )

    def _check_has_digit(self, profile: _CharProfile) -> CriterionResult:
        """Award points if the password contains at least one digit."""
        w = SCORE_WEIGHTS["has_digit"]
        return CriterionResult(
            name       = "Digits",
            passed     = profile.has_digit,
            score      = w if profile.has_digit else 0,
            max_score  = w,
            detail     = (
                "Contains at least one digit"
                if profile.has_digit
                else "No digits found"
            ),
            suggestion = (
                "Add at least one number (0-9)."
                if not profile.has_digit else ""
            ),
        )

    def _check_has_special(self, profile: _CharProfile) -> CriterionResult:
        """Award points if the password contains at least one special character."""
        w = SCORE_WEIGHTS["has_special"]
        return CriterionResult(
            name       = "Special characters",
            passed     = profile.has_special,
            score      = w if profile.has_special else 0,
            max_score  = w,
            detail     = (
                "Contains special characters"
                if profile.has_special
                else "No special characters found"
            ),
            suggestion = (
                "Add special characters such as: ! @ # $ % ^ & *"
                if not profile.has_special else ""
            ),
        )

    def _check_char_variety(self, profile: _CharProfile) -> CriterionResult:
        """Award points if the password uses at least 3 of the 4 character classes."""
        classes = sum([
            profile.has_upper,
            profile.has_lower,
            profile.has_digit,
            profile.has_special,
        ])
        passed = classes >= 3
        w      = SCORE_WEIGHTS["char_variety"]
        return CriterionResult(
            name       = "Character variety",
            passed     = passed,
            score      = w if passed else 0,
            max_score  = w,
            detail     = f"Uses {classes}/4 character classes",
            suggestion = (
                "Mix uppercase, lowercase, digits, and special characters."
                if not passed else ""
            ),
        )

    def _check_no_common_password(self, pw: str) -> CriterionResult:
        """Deduct all points if the password (case-insensitive) is in the common list."""
        is_common = pw.lower() in COMMON_PASSWORDS
        w         = SCORE_WEIGHTS["no_common_password"]
        return CriterionResult(
            name       = "Not a common password",
            passed     = not is_common,
            score      = 0 if is_common else w,
            max_score  = w,
            detail     = (
                "Password appears in common password lists!"
                if is_common
                else "Not found in common password lists"
            ),
            suggestion = (
                "Avoid well-known passwords — they are cracked instantly."
                if is_common else ""
            ),
        )

    def _check_no_keyboard_pattern(self, pw: str) -> CriterionResult:
        """Deduct all points if the password contains a recognisable keyboard walk."""
        pw_lower = pw.lower()
        found: list[str] = [
            pattern
            for pattern in KEYBOARD_PATTERNS
            if pattern in pw_lower
        ]
        passed = not found
        w      = SCORE_WEIGHTS["no_keyboard_pattern"]
        return CriterionResult(
            name       = "No keyboard patterns",
            passed     = passed,
            score      = w if passed else 0,
            max_score  = w,
            detail     = (
                f"Keyboard patterns detected: {', '.join(found)}"
                if not passed
                else "No obvious keyboard patterns detected"
            ),
            suggestion = (
                "Avoid sequences like 'qwerty', '123456', 'asdfgh'."
                if not passed else ""
            ),
        )

    def _check_no_repeated_chars(self, profile: _CharProfile) -> CriterionResult:
        """Deduct all points if a single character dominates the password."""
        w = SCORE_WEIGHTS["no_repeated_chars"]

        most_common_char, most_common_count = profile.most_common(1)[0]
        ratio  = most_common_count / profile.length
        passed = ratio < REPEATED_CHAR_RATIO

        return CriterionResult(
            name       = "No excessive repetition",
            passed     = passed,
            score      = w if passed else 0,
            max_score  = w,
            detail     = (
                f"'{most_common_char}' appears {most_common_count}x"
                f" ({ratio:.0%} of password)"
            ),
            suggestion = (
                "Avoid repeating the same character too many times."
                if not passed else ""
            ),
        )

    def _check_entropy(
        self,
        entropy_bits: float,
        *,
        repetition_passed: bool,
    ) -> CriterionResult:
        """Award bonus points if the estimated entropy meets the threshold."""
        w = SCORE_WEIGHTS["entropy_bonus"]

        if not repetition_passed:
            return CriterionResult(
                name       = "Entropy",
                passed     = False,
                score      = 0,
                max_score  = w,
                detail     = (
                    f"Estimated entropy: {{entropy_bits:.1f}} bits "
                    "— skipped (repetition penalty already applied)"
                ),
                # No suggestion: the repetition criterion already advises the user.
                suggestion = "",
            )

        passed = entropy_bits >= ENTROPY_GOOD_THRESHOLD
        return CriterionResult(
            name       = "Entropy",
            passed     = passed,
            score      = w if passed else 0,
            max_score  = w,
            detail     = (
                f"Estimated entropy: {entropy_bits:.1f} bits "
                f"(good >= {ENTROPY_GOOD_THRESHOLD:.0f} bits)"
            ),
            suggestion = (
                "Increase length and character variety to raise entropy."
                if not passed else ""
            ),
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _calculate_entropy(profile: _CharProfile) -> float:
        """Estimate password entropy (bits) based on character pool and distribution."""
        if profile.length == 0:
            return 0.0

        # --- 1. Pool-based (upper-bound) entropy ---
        pool = 0
        if profile.has_lower:     pool += 26
        if profile.has_upper:     pool += 26
        if profile.has_digit:     pool += 10
        if profile.has_special:   pool += len(SPECIAL_CHARS)
        if profile.has_non_ascii: pool += 32  # conservative non-ASCII bonus

        if pool == 0:
            return 0.0

        pool_entropy_per_char = math.log2(pool)

        # --- 2. Shannon entropy per character (distribution-aware) ---
        total = profile.length
        shannon_per_char = -sum(
            (count / total) * math.log2(count / total)
            for count in profile.char_counts.values()
        )

        # --- 3. Weighted blend ---
        entropy_per_char = (
            (1.0 - SHANNON_WEIGHT) * pool_entropy_per_char
            + SHANNON_WEIGHT       * shannon_per_char
        )

        return max(0.0, entropy_per_char * profile.length)

    @staticmethod
    def _strength_band(score: int) -> tuple[str, str]:
        """Map a numeric *score* (0–100) to a ``(label, colour_key)`` pair."""
        for threshold, label, color in STRENGTH_BANDS:
            if score >= threshold:
                return label, color
        raise ValueError(
            f"No matching strength band found for score {score}. "
            "Ensure STRENGTH_BANDS contains an entry with threshold 0."
        )