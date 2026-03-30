from __future__ import annotations

import sys

from .constants import STRENGTH_BANDS
from .models import CriterionResult, PasswordAnalysis

def score_bar(score: int, width: int = 20) -> str:

    filled = round(score / 100 * width)
    encoding = getattr(sys.stdout, "encoding", "utf-8") or "utf-8"
    if encoding.lower().replace("-", "") in ("utf8", "utf16", "utf32"):
        fill_char, empty_char = "█", "░"
    else:
        fill_char, empty_char = "#", "-"
    return fill_char * filled + empty_char * (width - filled)

def score_to_label(score: int) -> tuple[str, str]:
    """Return (label, colour_key) for a given numeric score."""
    for threshold, label, color in STRENGTH_BANDS:
        if score >= threshold:
            return label, color
    return "Very Weak", "bright_red"

def max_possible_score(criteria: list[CriterionResult]) -> int:
    """Sum of all max_scores — useful for displaying x/100 breakdowns."""
    return sum(c.max_score for c in criteria)

def criteria_summary(analysis: PasswordAnalysis) -> dict[str, object]:

    return {
        "score":        analysis.score,
        "strength":     analysis.strength_label,
        "entropy_bits": round(analysis.entropy_bits, 2),
        "passed":       analysis.passed_count,
        "total":        analysis.total_criteria,
        "suggestions":  analysis.suggestions,
        "criteria": [
            {
                "name":      c.name,
                "passed":    c.passed,
                "score":     c.score,
                "max_score": c.max_score,
                "detail":    c.detail,
            }
            for c in analysis.criteria
        ],
    }