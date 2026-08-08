"""PasswordAnalyzer — orchestrates every criterion module into one result.

This is intentionally a thin "assembly" file: the actual scoring logic for
each criterion lives in the focused sibling modules (length.py,
character.py, patterns.py, entropy.py, strength.py). Reading this file top
to bottom tells you exactly which 13 criteria exist and where each one's
implementation lives, without wading through ~500 lines of mixed logic.
"""
from __future__ import annotations

import unicodedata

from ..constants import LENGTH_MAXIMUM, MAX_PERCENT_FOR_KNOWN_WEAK_PATTERN, get_common_passwords
from ..models import CriterionResult, PasswordAnalysis
from ..utils import ascii_residue_length, masked_password, normalise_for_lookup, split_graphemes
from .character import (
    criterion_char_uniqueness,
    criterion_char_variety,
    criterion_has_digit,
    criterion_has_lowercase,
    criterion_has_special,
    criterion_has_uppercase,
)
from .entropy import compute_entropy, criterion_entropy
from .length import criterion_length_excellent, criterion_length_good, criterion_length_minimum
from .patterns import criterion_no_common_password, criterion_no_keyboard_pattern, criterion_no_repeated_chars
from .strength import strength_label_and_colour

__all__ = ["PasswordAnalyzer"]

class PasswordAnalyzer:
    """Evaluate password strength across the weighted criteria in SCORE_WEIGHTS."""

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def analyze(self, password: str) -> PasswordAnalysis:
        """Run every criterion against *password* and return the aggregated result."""
        password = unicodedata.normalize("NFC", password)

        graphemes = split_graphemes(password)
        length = len(graphemes)
        if length > LENGTH_MAXIMUM:
            raise ValueError(
                f"Password exceeds the maximum analysable length of "
                f"{LENGTH_MAXIMUM} characters (got {length}). "
                "Truncate or reject the input before calling analyze()."
            )

        lookup_variants = normalise_for_lookup(password)
        can_lookup = bool(lookup_variants)
        is_common  = can_lookup and bool(lookup_variants & get_common_passwords())
        # Distinguishes "too short to look up" (e.g. 'cat') from "genuinely
        # has no ASCII-equivalent form" (e.g. an all-CJK/emoji password) so
        # the skip_reason reported to callers is accurate in both cases.
        has_ascii_residue = ascii_residue_length(password) > 0
        entropy = compute_entropy(password, graphemes, length)

        keyboard_result = criterion_no_keyboard_pattern(
            password, is_common=is_common, can_lookup=can_lookup, length=length,
            has_ascii_residue=has_ascii_residue,
        )

        criteria: tuple[CriterionResult, ...] = (
            criterion_length_minimum(length),
            criterion_length_good(length),
            criterion_length_excellent(length),
            criterion_has_uppercase(password),
            criterion_has_lowercase(password),
            criterion_has_digit(password),
            criterion_has_special(password),
            criterion_char_variety(password),
            criterion_char_uniqueness(graphemes, length),
            criterion_no_common_password(
                is_common=is_common, can_lookup=can_lookup, length=length,
                has_ascii_residue=has_ascii_residue,
            ),
            keyboard_result,
            criterion_no_repeated_chars(graphemes, length, is_common=is_common),
            criterion_entropy(entropy),
        )

        eff_max   = sum(c.max_score for c in criteria if not c.skipped)
        raw_score = sum(c.score for c in criteria if not c.skipped)
        score     = raw_score
        keyboard_hit = (not keyboard_result.skipped) and (not keyboard_result.passed)
        weak_pattern_detected = is_common or keyboard_hit

        cap_applied = False
        if weak_pattern_detected:
            capped = min(score, round(eff_max * MAX_PERCENT_FOR_KNOWN_WEAK_PATTERN / 100))
            if capped < score:
                cap_applied = True
            score = capped

        label, colour = strength_label_and_colour(score, eff_max)

        return PasswordAnalysis(
            password_masked=masked_password(password),
            password_length=length,
            score=score,
            strength_label=label,
            strength_color=colour,
            criteria=criteria,
            entropy_bits=entropy,
            weak_pattern_cap_applied=cap_applied,
            suggestions=tuple(
                c.suggestion
                for c in criteria
                if not c.passed and not c.skipped and c.suggestion
            ),
        )
