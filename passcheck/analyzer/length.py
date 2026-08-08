"""Length-based criteria: minimum / good / excellent length thresholds."""
from __future__ import annotations

from ..constants import LENGTH_EXCELLENT, LENGTH_GOOD, LENGTH_MINIMUM, SCORE_WEIGHTS
from ..models import CriterionResult

__all__ = [
    "criterion_length_minimum",
    "criterion_length_good",
    "criterion_length_excellent",
]

def criterion_length_minimum(length: int) -> CriterionResult:
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

def criterion_length_good(length: int) -> CriterionResult:
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

def criterion_length_excellent(length: int) -> CriterionResult:
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
