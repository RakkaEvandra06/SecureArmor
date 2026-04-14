from __future__ import annotations

from dataclasses import dataclass, field

@dataclass(frozen=True)
class CriterionResult:
    """Immutable result for a single scoring criterion."""

    name:       str
    passed:     bool
    score:      int
    max_score:  int
    detail:     str
    suggestion: str = ""

    def __post_init__(self) -> None:
        # Validate in order from simplest to most derived so that the first
        # meaningful constraint violation surfaces with a clear message.
        if self.max_score <= 0:
            raise ValueError(
                f"CriterionResult.max_score must be positive, got {self.max_score!r}."
            )
        if self.score < 0:
            raise ValueError(
                f"CriterionResult.score must be non-negative, got {self.score!r}."
            )
        if self.score > self.max_score:
            raise ValueError(
                f"CriterionResult.score ({self.score}) must not exceed "
                f"max_score ({self.max_score})."
            )
        if self.passed and self.suggestion:
            raise ValueError(
                "A passed CriterionResult must not carry a non-empty suggestion."
            )

@dataclass(frozen=True)
class PasswordAnalysis:
    """Immutable aggregated analysis result for one password."""

    password:        str
    score:           int
    strength_label:  str
    strength_color:  str

    criteria:     tuple[CriterionResult, ...] = field(default_factory=tuple)
    entropy_bits: float                        = 0.0
    suggestions:  tuple[str, ...]             = field(default_factory=tuple)

    @property
    def passed_count(self) -> int:
        """Number of criteria the password actively satisfied (not skipped)."""
        return sum(1 for c in self.criteria if c.passed)

    @property
    def total_criteria(self) -> int:
        """Total number of criteria that were evaluated."""
        return len(self.criteria)