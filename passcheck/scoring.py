"""
scoring.py — Scoring utilities decoupled from analysis logic.

Responsible for:
  - Computing a normalised score summary from criteria results
  - Providing score-to-label mapping helpers
  - Generating the score bar used in the display layer

Keeping this separate from analyzer.py ensures the scoring model can be
swapped (e.g., weighted average vs additive) without touching either
the analysis engine or the CLI.
"""

from __future__ import annotations

from .constants import STRENGTH_BANDS
from .models import CriterionResult, PasswordAnalysis


def score_bar(score: int, width: int = 20) -> str:
    """
    Return a Unicode progress-bar string representing *score* (0–100).

    Example (score=60, width=20):  ████████████░░░░░░░░
    """
    filled = round(score / 100 * width)
    return "█" * filled + "░" * (width - filled)


def score_to_label(score: int) -> tuple[str, str]:
    """Return (label, rich_colour) for a given score."""
    for threshold, label, color in STRENGTH_BANDS:
        if score >= threshold:
            return label, color
    return "Very Weak", "bright_red"


def max_possible_score(criteria: list[CriterionResult]) -> int:
    """Sum of all max_scores — useful for displaying x/100 breakdown."""
    return sum(c.max_score for c in criteria)


def criteria_summary(analysis: PasswordAnalysis) -> dict[str, object]:
    """
    Return a plain dict summary for programmatic use / JSON export.

    Keeps the output layer agnostic of the rich console.
    """
    return {
        "score": analysis.score,
        "strength": analysis.strength_label,
        "entropy_bits": round(analysis.entropy_bits, 2),
        "passed": analysis.passed_count,
        "total": analysis.total_criteria,
        "suggestions": analysis.suggestions,
        "criteria": [
            {
                "name": c.name,
                "passed": c.passed,
                "score": c.score,
                "max_score": c.max_score,
                "detail": c.detail,
            }
            for c in analysis.criteria
        ],
    }
