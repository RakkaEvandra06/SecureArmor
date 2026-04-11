from __future__ import annotations

import codecs
import sys

from .models import CriterionResult, PasswordAnalysis

def _is_utf_encoding(encoding: str) -> bool:
    """Return True if *encoding* resolves to a UTF variant via the codec registry.
    """
    try:
        return codecs.lookup(encoding).name in ("utf-8", "utf-8-sig", "utf-16", "utf-32")
    except LookupError:
        return False

def score_bar(score: int, width: int = 20) -> str:
    """Return a text progress bar representing *score* (0-100)."""
    filled = round(score / 100 * width)
    encoding = getattr(sys.stdout, "encoding", "utf-8") or "utf-8"
    if _is_utf_encoding(encoding):
        fill_char, empty_char = "█", "░"
    else:
        fill_char, empty_char = "#", "-"
    return fill_char * filled + empty_char * (width - filled)

def max_possible_score(criteria: list[CriterionResult]) -> int:
    """Sum of all max_scores — useful for displaying x/100 breakdowns."""
    return sum(c.max_score for c in criteria)

def criteria_summary(analysis: PasswordAnalysis) -> dict[str, object]:
    """Return a JSON-serialisable summary dict for *analysis*."""
    return {
        "score":        analysis.score,
        "strength":     analysis.strength_label,
        "entropy_bits": round(analysis.entropy_bits, 2),
        "passed":       analysis.passed_count,
        "total":        analysis.total_criteria,
        "suggestions":  list(analysis.suggestions),
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