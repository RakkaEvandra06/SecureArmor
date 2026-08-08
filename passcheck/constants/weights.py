"""Per-criterion scoring weights for PassCheck.

Isolated from the rest of constants/ because it changes for a different
reason than thresholds or pattern data: tuning *how much* each criterion
is worth, not *what* it checks.
"""
from __future__ import annotations

from types import MappingProxyType

__all__ = ["SCORE_WEIGHTS"]

SCORE_WEIGHTS: MappingProxyType[str, int] = MappingProxyType({
    "length_minimum":       9,
    "length_good":          9,
    "length_excellent":     4,
    "has_uppercase":        7,
    "has_lowercase":        7,
    "has_digit":            9,
    "has_special":         12,
    "char_variety":         9,
    "char_uniqueness":      4,
    "no_common_password":   9,
    "no_keyboard_pattern":  9,
    "no_repeated_chars":    4,
    "entropy":              8,
})

if not all(v > 0 for v in SCORE_WEIGHTS.values()):
    raise ValueError(
        "All SCORE_WEIGHTS values must be strictly positive (CriterionResult "
        "requires max_score > 0 for every criterion). To disable a criterion "
        "entirely, remove its key from SCORE_WEIGHTS and delete the "
        "corresponding _criterion_* method in analyzer.py, then rebalance "
        "the remaining weights back to a sum of 100, do not set it to 0."
    )

_weights_total = sum(SCORE_WEIGHTS.values())
if _weights_total != 100:
    raise ValueError(
        f"SCORE_WEIGHTS must sum to exactly 100 so that a perfect password "
        f"reaches a score of exactly 100. Current sum: {_weights_total}."
    )
del _weights_total

_EXPECTED_WEIGHT_KEYS: frozenset[str] = frozenset({
    "length_minimum",
    "length_good",
    "length_excellent",
    "has_uppercase",
    "has_lowercase",
    "has_digit",
    "has_special",
    "char_variety",
    "char_uniqueness",
    "no_common_password",
    "no_keyboard_pattern",
    "no_repeated_chars",
    "entropy",
})

_missing_weight_keys = _EXPECTED_WEIGHT_KEYS - frozenset(SCORE_WEIGHTS)
_extra_weight_keys   = frozenset(SCORE_WEIGHTS) - _EXPECTED_WEIGHT_KEYS
if _missing_weight_keys or _extra_weight_keys:
    raise ValueError(
        f"SCORE_WEIGHTS key mismatch. "
        f"Missing keys: {sorted(_missing_weight_keys)}. "
        f"Unexpected keys: {sorted(_extra_weight_keys)}. "
        "Ensure every criterion key in analyzer.py has a corresponding entry "
        "in SCORE_WEIGHTS and vice versa."
    )
del _missing_weight_keys, _extra_weight_keys, _EXPECTED_WEIGHT_KEYS
