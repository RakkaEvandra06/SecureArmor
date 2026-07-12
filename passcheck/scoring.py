"""Presentation-agnostic helpers derived from a :class:`~passcheck.models.PasswordAnalysis`."""

from __future__ import annotations

import warnings
from typing import TypedDict

from .models import PasswordAnalysis

__all__ = [
    "AnalysisSummary",
    "CriterionSummary",
    "criteria_summary",
    "effective_max_score",
    "score_bar",
]

# ---------------------------------------------------------------------------
# JSON summary types
# ---------------------------------------------------------------------------

class CriterionSummary(TypedDict):
    """JSON-serialisable view of a single :class:`~passcheck.models.CriterionResult`."""

    name:        str
    passed:      bool
    skipped:     bool
    score:       int
    max_score:   int
    detail:      str
    suggestion:  str
    skip_reason: str | None

class AnalysisSummary(TypedDict):
    """JSON-serialisable view of a full :class:`~passcheck.models.PasswordAnalysis`."""

    password_masked:     str
    password_length:     int
    score:               int
    effective_max_score: int
    score_percent:       int
    strength_label:      str
    strength_color:      str
    entropy_bits:        float
    passed_count:        int
    total_criteria:      int
    weak_pattern_cap_applied: bool
    suggestions:         list[str]
    criteria:            list[CriterionSummary]

# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------

def effective_max_score(analysis: PasswordAnalysis) -> int:
    """Return the sum of ``max_score`` for every non-skipped criterion in *analysis*."""
    warnings.warn(
        "scoring.effective_max_score() is deprecated and will be removed in a "
        "future release.  Use analysis.effective_max_score instead.",
        DeprecationWarning,
        stacklevel=2,
    )
    return analysis.effective_max_score

def criteria_summary(analysis: PasswordAnalysis) -> AnalysisSummary:
    """Return a JSON-serialisable summary of *analysis*."""
    return AnalysisSummary(
        password_masked=analysis.password_masked,
        password_length=analysis.password_length,
        score=analysis.score,
        effective_max_score=analysis.effective_max_score,
        score_percent=analysis.score_percent,
        strength_label=analysis.strength_label,
        strength_color=analysis.strength_color,
        entropy_bits=round(analysis.entropy_bits, 2),
        passed_count=analysis.passed_count,
        total_criteria=analysis.total_criteria,
        weak_pattern_cap_applied=analysis.weak_pattern_cap_applied,
        suggestions=list(analysis.suggestions),
        criteria=[
            CriterionSummary(
                name=c.name,
                passed=c.passed,
                skipped=c.skipped,
                score=c.score,
                max_score=c.max_score,
                detail=c.detail,
                suggestion=c.suggestion,
                skip_reason=c.skip_reason.value if c.skip_reason is not None else None,
            )
            for c in analysis.criteria
        ],
    )

def score_bar(percent: int, *, width: int = 20, utf: bool = True) -> str:
    """Return a fixed-*width*-character progress bar representing *percent* (0-100)."""
    clamped = max(0, min(percent, 100))
    filled  = round(width * clamped / 100)
    empty   = width - filled

    fill_char, empty_char = ("█", "░") if utf else ("#", "-")
    return fill_char * filled + empty_char * empty