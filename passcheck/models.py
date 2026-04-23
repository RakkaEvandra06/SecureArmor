from __future__ import annotations

from dataclasses import dataclass, field

from .constants import VALID_COLOUR_KEYS as _VALID_COLOUR_KEYS

@dataclass(frozen=True)
class CriterionResult:
    """Immutable result for a single scoring criterion."""

    name:       str
    passed:     bool
    score:      int
    max_score:  int
    detail:     str
    suggestion: str  = ""
    skipped:    bool = False

    def __post_init__(self) -> None:
        # ------------------------------------------------------------------ #
        # Validate in order from simplest to most derived so that the first  #
        # meaningful constraint violation surfaces with a clear message.     #
        # ------------------------------------------------------------------ #
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
        if self.passed and self.score == 0:
            raise ValueError(
                "A passed CriterionResult must have a positive score; "
                f"got score=0 with max_score={self.max_score}. "
                "If the criterion genuinely contributes nothing, mark it as skipped."
            )

        if not self.passed and not self.skipped and self.score != 0:
            raise ValueError(
                f"A failed (non-passed, non-skipped) CriterionResult must have "
                f"score=0, got score={self.score!r}. "
                "Use skipped=True for unevaluated criteria, or passed=True if "
                "the criterion was actually satisfied."
            )

        # ------------------------------------------------------------------ #
        # Skipped-specific invariants                                          #
        # ------------------------------------------------------------------ #
        if self.skipped:
            if self.passed:
                raise ValueError(
                    "A skipped CriterionResult cannot also be marked as passed."
                )
            if self.score != 0:
                raise ValueError(
                    f"A skipped CriterionResult must have score=0, got {self.score!r}."
                )
            if self.suggestion:
                raise ValueError(
                    "A skipped CriterionResult must not carry a non-empty suggestion "
                    "(the criterion that triggered the skip already advises the user)."
                )

@dataclass(frozen=True)
class PasswordAnalysis:
    """Immutable aggregated analysis result for one password."""

    password:        str
    score:           int
    strength_label:  str
    strength_color:  str

    criteria:     tuple[CriterionResult, ...] = field(default=())
    entropy_bits: float                        = 0.0
    suggestions:  tuple[str, ...]             = field(default=())

    def __post_init__(self) -> None:
        if not (0 <= self.score <= 100):
            raise ValueError(
                f"PasswordAnalysis.score must be in [0, 100], got {self.score!r}."
            )
        if self.strength_color not in _VALID_COLOUR_KEYS:
            raise ValueError(
                f"PasswordAnalysis.strength_color {self.strength_color!r} is not a "
                f"recognised colour key. Valid keys: {sorted(_VALID_COLOUR_KEYS)}."
            )

    @property
    def passed_count(self) -> int:
        """Number of criteria the password actively satisfied."""
        return sum(1 for c in self.criteria if c.passed)

    @property
    def total_criteria(self) -> int:
        """Number of criteria that were actually evaluated (skipped excluded)."""
        return sum(1 for c in self.criteria if not c.skipped)