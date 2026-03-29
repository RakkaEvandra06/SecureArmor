from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class CriterionResult:
    """Immutable result for a single scoring criterion."""

    name:       str   # human-readable name
    passed:     bool  # did the password satisfy this criterion?
    score:      int   # points awarded (0 if not passed)
    max_score:  int   # maximum possible points for this criterion
    detail:     str   # one-line explanation shown in the criteria table
    suggestion: str = ""  # improvement tip shown only when not passed


@dataclass(frozen=True)
class PasswordAnalysis:
    """Immutable aggregated analysis result for one password."""

    password:        str
    score:           int    # 0-100
    strength_label:  str    # e.g. "Strong"
    strength_color:  str    # colorama colour key
    criteria:        list[CriterionResult] = field(default_factory=list)
    entropy_bits:    float  = 0.0
    suggestions:     list[str] = field(default_factory=list)

    @property
    def passed_count(self) -> int:
        """Number of criteria the password satisfied."""
        return sum(1 for c in self.criteria if c.passed)

    @property
    def total_criteria(self) -> int:
        """Total number of criteria that were evaluated."""
        return len(self.criteria)