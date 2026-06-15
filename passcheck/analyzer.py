"""Core scoring engine for PassCheck."""

from __future__ import annotations

import math
import unicodedata
from collections import Counter

from .constants import (
    CHAR_CLASS_COUNT,
    CHAR_UNIQUENESS_MIN_RATIO,
    CHAR_VARIETY_MIN_CLASSES,
    ENTROPY_GOOD_THRESHOLD,
    KEYBOARD_PATTERNS,
    LENGTH_EXCELLENT,
    LENGTH_GOOD,
    LENGTH_MAXIMUM,
    LENGTH_MINIMUM,
    NON_ASCII_POOL_SIZE,
    REPEATED_CHAR_RATIO,
    SCORE_WEIGHTS,
    SHANNON_WEIGHT,
    SPECIAL_CHARS_SET,
    STRENGTH_BANDS,
    get_common_passwords,
)
from .models import CriterionResult, PasswordAnalysis, SkipReason
from .utils import (
    _grapheme_split,
    _LEET_TABLE,
    grapheme_len,
    grapheme_unique_count,
    masked_password,
    normalise_for_lookup,
)

# ---------------------------------------------------------------------------
# Module-level invariants
# ---------------------------------------------------------------------------

_EXPECTED_CHAR_CLASS_COUNT: int = 5
assert CHAR_CLASS_COUNT == _EXPECTED_CHAR_CLASS_COUNT, (
    f"constants.CHAR_CLASS_COUNT ({CHAR_CLASS_COUNT}) no longer matches the "
    f"{_EXPECTED_CHAR_CLASS_COUNT} character-class checks implemented in "
    "PasswordAnalyzer._criterion_char_variety(). Update one or the other."
)

class PasswordAnalyzer:
    """Evaluate password strength across the weighted criteria in SCORE_WEIGHTS."""

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def analyze(self, password: str) -> PasswordAnalysis:
        """Run every criterion against *password* and return the aggregated result."""
        password = unicodedata.normalize("NFC", password)

        length = grapheme_len(password)
        if length > LENGTH_MAXIMUM:
            raise ValueError(
                f"Password exceeds the maximum analysable length of "
                f"{LENGTH_MAXIMUM} characters (got {length}). "
                "Truncate or reject the input before calling analyze()."
            )

        lookup_variants = normalise_for_lookup(password)
        can_lookup = bool(lookup_variants)
        is_common  = can_lookup and bool(lookup_variants & get_common_passwords())
        entropy = self._compute_entropy(password, length)

        criteria: tuple[CriterionResult, ...] = (
            self._criterion_length_minimum(length),
            self._criterion_length_good(length),
            self._criterion_length_excellent(length),
            self._criterion_has_uppercase(password),
            self._criterion_has_lowercase(password),
            self._criterion_has_digit(password),
            self._criterion_has_special(password),
            self._criterion_char_variety(password),
            self._criterion_char_uniqueness(password, length),
            self._criterion_no_common_password(is_common=is_common, can_lookup=can_lookup),
            self._criterion_no_keyboard_pattern(
                password, is_common=is_common, can_lookup=can_lookup
            ),
            self._criterion_no_repeated_chars(password, length, is_common=is_common),
            self._criterion_entropy(entropy),
        )

        eff_max   = sum(c.max_score for c in criteria if not c.skipped)
        raw_score = sum(c.score for c in criteria if not c.skipped)
        score     = raw_score
        label, colour = self._strength_label_and_colour(score, eff_max)

        return PasswordAnalysis(
            password_masked=masked_password(password),
            password_length=length,
            score=score,
            strength_label=label,
            strength_color=colour,
            criteria=criteria,
            entropy_bits=entropy,
            suggestions=tuple(
                c.suggestion
                for c in criteria
                if not c.passed and not c.skipped and c.suggestion
            ),
        )

    # ------------------------------------------------------------------
    # Length criteria
    # ------------------------------------------------------------------

    def _criterion_length_minimum(self, length: int) -> CriterionResult:
        weight = SCORE_WEIGHTS["length_minimum"]
        passed = length >= LENGTH_MINIMUM
        return CriterionResult(
            name="Minimum Length",
            passed=passed,
            score=weight if passed else 0,
            max_score=weight,
            detail=f"{length} chars (minimum {LENGTH_MINIMUM})",
            suggestion="" if passed else f"Use at least {LENGTH_MINIMUM} characters.",
        )

    def _criterion_length_good(self, length: int) -> CriterionResult:
        weight = SCORE_WEIGHTS["length_good"]
        passed = length >= LENGTH_GOOD
        return CriterionResult(
            name="Good Length",
            passed=passed,
            score=weight if passed else 0,
            max_score=weight,
            detail=f"{length} chars (good {LENGTH_GOOD}+)",
            suggestion="" if passed else f"Aim for {LENGTH_GOOD}+ characters for a sizeable length bonus.",
        )

    def _criterion_length_excellent(self, length: int) -> CriterionResult:
        weight = SCORE_WEIGHTS["length_excellent"]
        passed = length >= LENGTH_EXCELLENT
        return CriterionResult(
            name="Excellent Length",
            passed=passed,
            score=weight if passed else 0,
            max_score=weight,
            detail=f"{length} chars (excellent {LENGTH_EXCELLENT}+)",
            suggestion="" if passed else f"Consider {LENGTH_EXCELLENT}+ characters for maximum length credit.",
        )

    # ------------------------------------------------------------------
    # Character-class criteria
    # ------------------------------------------------------------------

    def _criterion_has_uppercase(self, pw: str) -> CriterionResult:
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

    def _criterion_has_lowercase(self, pw: str) -> CriterionResult:
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

    def _criterion_has_digit(self, pw: str) -> CriterionResult:
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

    def _criterion_has_special(self, pw: str) -> CriterionResult:
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

    def _criterion_char_variety(self, pw: str) -> CriterionResult:
        weight = SCORE_WEIGHTS["char_variety"]
        classes_present = [
            any(c.isupper() for c in pw),
            any(c.islower() for c in pw),
            any(c.isascii() and c.isdigit() for c in pw),
            any(c in SPECIAL_CHARS_SET for c in pw),
            any(not c.isascii() for c in pw),  # 5th class: non-ASCII / Unicode
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

    def _criterion_char_uniqueness(self, pw: str, length: int) -> CriterionResult:
        weight = SCORE_WEIGHTS["char_uniqueness"]
        unique_count = grapheme_unique_count(pw)
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

    # ------------------------------------------------------------------
    # Anti-pattern criteria
    # ------------------------------------------------------------------

    def _criterion_no_common_password(
        self, *, is_common: bool, can_lookup: bool
    ) -> CriterionResult:
        weight = SCORE_WEIGHTS["no_common_password"]

        if not can_lookup:
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

    def _criterion_no_keyboard_pattern(
        self, pw: str, *, is_common: bool, can_lookup: bool
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
        pw_normalised = pw_lower.translate(_LEET_TABLE)
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

    def _criterion_no_repeated_chars(
        self, pw: str, length: int, *, is_common: bool
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
                detail="no characters present",
                suggestion="Enter a non-empty password.",
            )

        graphemes = _grapheme_split(pw)
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

    # ------------------------------------------------------------------
    # Entropy criterion
    # ------------------------------------------------------------------

    def _criterion_entropy(self, entropy: float) -> CriterionResult:
        """Return the entropy criterion result for a pre-computed *entropy* value."""
        weight = SCORE_WEIGHTS["entropy"]
        passed = entropy >= ENTROPY_GOOD_THRESHOLD
        return CriterionResult(
            name="Entropy",
            passed=passed,
            score=weight if passed else 0,
            max_score=weight,
            detail=f"{entropy:.1f} bits (target {ENTROPY_GOOD_THRESHOLD:.0f}+)",
            suggestion="" if passed else "Increase length and character variety to raise entropy.",
        )

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_entropy(pw: str, length: int) -> float:
        """Return a blended Shannon / character-pool entropy estimate, in bits."""
        if length == 0:
            return 0.0

        graphemes        = _grapheme_split(pw)
        counts           = Counter(graphemes)
        total            = length                  # == len(graphemes)
        shannon_per_char = -sum(
            (n / total) * math.log2(n / total) for n in counts.values()
        )

        pool_size = 0
        if any(c.islower() for c in pw):
            pool_size += 26
        if any(c.isupper() for c in pw):
            pool_size += 26
        if any(c.isascii() and c.isdigit() for c in pw):
            pool_size += 10
        if any(c in SPECIAL_CHARS_SET for c in pw):
            pool_size += len(SPECIAL_CHARS_SET)
        if any(not c.isascii() for c in pw):
            pool_size += NON_ASCII_POOL_SIZE
        pool_size = max(pool_size, 1)

        shannon_total = shannon_per_char * length
        pool_total    = math.log2(pool_size) * length

        return SHANNON_WEIGHT * shannon_total + (1 - SHANNON_WEIGHT) * pool_total

    @staticmethod
    def _strength_label_and_colour(score: int, eff_max: int) -> tuple[str, str]:
        """Map *score* (as a percentage of *eff_max*) to a strength label and colour key."""
        pct = round(score / eff_max * 100) if eff_max > 0 else 0
        for threshold, label, colour in STRENGTH_BANDS:
            if pct >= threshold:
                return label, colour
        return STRENGTH_BANDS[-1][1], STRENGTH_BANDS[-1][2]