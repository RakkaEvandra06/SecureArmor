"""Entropy criterion and the blended Shannon / character-pool entropy estimator."""
from __future__ import annotations

import math
from collections import Counter

from ..constants import (
    ENTROPY_GOOD_THRESHOLD,
    NON_ASCII_POOL_SIZE,
    SCORE_WEIGHTS,
    SHANNON_WEIGHT,
    SPECIAL_CHARS_SET,
)
from ..models import CriterionResult
from ..utils import repeated_block_period

__all__ = ["criterion_entropy", "compute_entropy"]

def criterion_entropy(entropy: float) -> CriterionResult:
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

def compute_entropy(pw: str, graphemes: list[str], length: int) -> float:
    """Return a blended Shannon / character-pool entropy estimate, in bits."""
    if length == 0:
        return 0.0

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

    period = repeated_block_period(graphemes)
    effective_length: float = length
    if period >= 1:
        repetitions = length / period
        effective_length = period + math.log2(repetitions)

    max_freq = max(counts.values())
    freq_effective_length = length * (1 - max_freq / length) + 1
    effective_length = min(effective_length, freq_effective_length, length)

    shannon_total = shannon_per_char * effective_length
    pool_total    = math.log2(pool_size) * effective_length

    return SHANNON_WEIGHT * shannon_total + (1 - SHANNON_WEIGHT) * pool_total
