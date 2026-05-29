from __future__ import annotations

from collections.abc import Sequence
from typing import TypedDict

from .models import CriterionResult, PasswordAnalysis
from .utils import is_utf_terminal as _is_utf_terminal

_UTF_TERMINAL: bool = _is_utf_terminal()

class _CriterionSummary(TypedDict):
    """JSON-serialisable summary for a single criterion."""

    name:        str
    passed:      bool
    skipped:     bool
    score:       int
    max_score:   int
    detail:      str
    suggestion:  str
    skip_reason: str

class AnalysisSummary(TypedDict):
    """Full JSON-serialisable summary produced by :func:`criteria_summary`."""

    score:          int
    strength:       str
    entropy_bits:   float
    passed:         int
    total:          int
    effective_max:  int
    suggestions:    list[str]
    criteria:       list[_CriterionSummary]

# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------

def score_bar(score: int, width: int = 20) -> str:
    """Return a text progress bar representing *score* (0–100)."""
    if isinstance(width, bool) or not isinstance(width, int):
        raise TypeError(
            f"score_bar() requires a plain int width, got {type(width).__name__!r}. "
            "Pass a plain int such as score_bar(score, width=20)."
        )
    if width <= 0:
        raise ValueError(f"score_bar() requires a positive width, got {width!r}.")

    score  = max(0, min(100, score))
    filled = min(width, round(score / 100 * width))

    # FIX D-01: Use the module-level cached result instead of calling
    # _is_utf_terminal() on each invocation.
    if _UTF_TERMINAL:
        fill_char, empty_char = "█", "░"
    else:
        fill_char, empty_char = "#", "-"

    return fill_char * filled + empty_char * (width - filled)

def max_possible_score(criteria: Sequence[CriterionResult]) -> int:
    """Return the sum of ``max_score`` values for all non-skipped criteria."""
    return sum(c.max_score for c in criteria if not c.skipped)

effective_max_score = max_possible_score

def criteria_summary(analysis: PasswordAnalysis) -> AnalysisSummary:
    """Return a typed, JSON-serialisable summary dict for *analysis*."""
    return AnalysisSummary(
        score         = analysis.score,
        strength      = analysis.strength_label,
        entropy_bits  = round(analysis.entropy_bits, 2),
        passed        = analysis.passed_count,
        total         = analysis.total_criteria,
        effective_max = max_possible_score(analysis.criteria),
        suggestions   = list(analysis.suggestions),
        criteria      = [
            _CriterionSummary(
                name        = c.name,
                passed      = c.passed,
                skipped     = c.skipped,
                score       = c.score,
                max_score   = c.max_score,
                detail      = c.detail,
                suggestion  = c.suggestion,
                skip_reason = c.skip_reason,
            )
            for c in analysis.criteria
        ],
    )