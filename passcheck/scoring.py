"""Presentation-agnostic helpers derived from a :class:`~passcheck.models.PasswordAnalysis`."""
from __future__ import annotations

import warnings
from typing import TypedDict

from .constants import STRENGTH_BANDS as _STRENGTH_BANDS
from .models import PasswordAnalysis, SkipReason

__all__ = [
    "AnalysisSummary",
    "CriterionSummary",
    "criteria_summary",
    "effective_max_score",
    "score_bar",
    "score_to_label",
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

    password_masked:          str
    # SEC-001: ``None`` when ``redact=True``; the exact character count is
    # itself partial credential information that ``--redact`` must suppress.
    password_length:          int | None
    score:                    int
    effective_max_score:      int
    score_percent:            int
    strength_label:           str
    strength_color:           str
    entropy_bits:             float
    # SEC-003: human-readable caveat when the entropy figure is misleading
    # (e.g. the score was capped because a weak pattern was detected, meaning
    # the statistical estimate does not reflect the real attacker effort).
    # ``None`` when no caveat applies.
    entropy_note:             str | None
    passed_count:             int
    total_criteria:           int
    weak_pattern_cap_applied: bool
    unicode_checks_skipped:   bool
    suggestions:              list[str]
    criteria:                 list[CriterionSummary]

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

def criteria_summary(
    analysis: PasswordAnalysis,
    *,
    redact: bool = False,
) -> AnalysisSummary:
    """Return a JSON-serialisable summary of *analysis*.

    Parameters
    ----------
    redact:
        When ``True``, ``password_masked`` is replaced with ``'[REDACTED]'``
        and ``password_length`` is set to ``None`` (SEC-001).  Use this
        whenever output may be logged, forwarded, or stored.
    """
    masked = "[REDACTED]" if redact else analysis.password_masked

    # SEC-001: suppress exact length when redact is requested — the character
    # count is itself identifying information about the credential.
    length = None if redact else analysis.password_length

    unicode_checks_skipped = any(
        c.skip_reason == SkipReason.UNICODE_ONLY_PASSWORD
        for c in analysis.criteria
        if c.skipped
    )

    # SEC-003: when the score was capped because a weak pattern was detected,
    # the raw entropy figure is a theoretical statistical estimate that does
    # not reflect the attacker effort required for a pattern-based attack.
    # Surface a plain-language note so API consumers can relay this to users.
    entropy_note: str | None = (
        "Theoretical estimate only — score was capped due to a detected weak "
        "pattern.  Statistical entropy does not account for pattern-based or "
        "dictionary attacks; actual resistance may be significantly lower."
        if analysis.weak_pattern_cap_applied
        else None
    )

    return AnalysisSummary(
        password_masked=masked,
        password_length=length,
        score=analysis.score,
        effective_max_score=analysis.effective_max_score,
        score_percent=analysis.score_percent,
        strength_label=analysis.strength_label,
        strength_color=analysis.strength_color,
        entropy_bits=round(analysis.entropy_bits, 2),
        entropy_note=entropy_note,
        passed_count=analysis.passed_count,
        total_criteria=analysis.total_criteria,
        weak_pattern_cap_applied=analysis.weak_pattern_cap_applied,
        unicode_checks_skipped=unicode_checks_skipped,
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

def score_to_label(percent: int) -> tuple[str, str]:
    """Return ``(label, colour_key)`` for a score *percent* in ``[0, 100]``."""
    pct = max(0, min(percent, 100))
    for threshold, label, colour in _STRENGTH_BANDS:
        if pct >= threshold:
            return label, colour
    return _STRENGTH_BANDS[-1][1], _STRENGTH_BANDS[-1][2]