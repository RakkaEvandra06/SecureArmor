from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from .constants import VALID_COLOUR_KEYS as _VALID_COLOUR_KEYS

class SkipReason(str, Enum):
    """Stable, versioned reason codes for skipped :class:`CriterionResult` entries."""

    COMMON_PASSWORD_DETECTED   = "common_password_detected"
    REPETITION_PENALTY_APPLIED = "repetition_penalty_applied"
    UNICODE_ONLY_PASSWORD      = "unicode_only_password"

@dataclass(frozen=True)
class CriterionResult:
    """Immutable result for a single scoring criterion."""

    name:        str
    passed:      bool
    score:       int
    max_score:   int
    detail:      str
    suggestion:  str                = ""
    skipped:     bool               = False
    skip_reason: SkipReason | None  = None

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError(
                "CriterionResult.name must be a non-empty, non-whitespace string."
            )
        if not self.detail.strip():
            raise ValueError(
                "CriterionResult.detail must be a non-empty, non-whitespace string."
            )
        self._validate_score_bounds()
        self._validate_passed_consistency()
        self._validate_skipped_consistency()

    # ------------------------------------------------------------------
    # Public convenience predicate
    # ------------------------------------------------------------------

    @property
    def evaluated(self) -> bool:
        """Return ``True`` when this criterion was actually run (i.e. not skipped)."""
        return not self.skipped

    # ------------------------------------------------------------------
    # Validators
    # ------------------------------------------------------------------

    def _validate_score_bounds(self) -> None:
        """Ensure ``score`` and ``max_score`` are in a valid range."""
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

    def _validate_passed_consistency(self) -> None:
        """Enforce invariants that apply to passed (non-skipped) criteria."""
        if not self.passed or self.skipped:
            return

        if self.suggestion:
            raise ValueError(
                "A passed CriterionResult must not carry a non-empty suggestion."
            )
        if self.score == 0:
            raise ValueError(
                "A passed CriterionResult must have a positive score; "
                f"got score=0 with max_score={self.max_score}. "
                "If the criterion genuinely contributes nothing, mark it as skipped."
            )

    def _validate_skipped_consistency(self) -> None:
        """Enforce invariants that apply to skipped criteria."""
        if not self.skipped:
            if self.skip_reason is not None:
                raise ValueError(
                    "CriterionResult.skip_reason must be None when skipped=False, "
                    f"got {self.skip_reason!r}. "
                    "Set skip_reason only together with skipped=True."
                )
            # Enforce the failed-criterion zero-score rule here (not skipped, not passed).
            if not self.passed and self.score != 0:
                raise ValueError(
                    f"A failed (non-passed, non-skipped) CriterionResult must have "
                    f"score=0, got score={self.score!r}. "
                    "Use skipped=True for unevaluated criteria, or passed=True if "
                    "the criterion was actually satisfied."
                )
            return

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

    password_masked: str
    password_length: int
    score:           int
    strength_label:  str
    strength_color:  str
    criteria:        tuple[CriterionResult, ...] = field(default=())
    entropy_bits:    float                        = 0.0
    suggestions:     tuple[str, ...]              = field(default=())

    def __post_init__(self) -> None:
        if self.password_length < 0:
            raise ValueError(
                f"PasswordAnalysis.password_length must be non-negative, "
                f"got {self.password_length!r}."
            )

        if self.score < 0:
            raise ValueError(
                f"PasswordAnalysis.score must be non-negative, got {self.score!r}."
            )

        if self.strength_color not in _VALID_COLOUR_KEYS:
            raise ValueError(
                f"PasswordAnalysis.strength_color {self.strength_color!r} is not a "
                f"recognised colour key. Valid keys: {sorted(_VALID_COLOUR_KEYS)}."
            )
        if self.entropy_bits < 0.0:
            raise ValueError(
                f"PasswordAnalysis.entropy_bits must be non-negative, "
                f"got {self.entropy_bits!r}."
            )
        if not self.criteria:
            raise ValueError(
                "PasswordAnalysis.criteria must contain at least one "
                "CriterionResult. An empty tuple indicates a programming "
                "error in the analyzer."
            )

        eff_max = sum(c.max_score for c in self.criteria if not c.skipped)

        if eff_max > 0 and not (0 <= self.score <= eff_max):
            raise ValueError(
                f"PasswordAnalysis.score ({self.score}) must be in "
                f"[0, effective_max_score ({eff_max})]. The analyzer must cap the "
                "raw score at the sum of non-skipped criteria's max_score "
                "values before constructing this model."
            )

        criteria_suggestions = frozenset(
            c.suggestion
            for c in self.criteria
            if not c.passed and not c.skipped and c.suggestion
        )
        unexpected_suggestions = frozenset(self.suggestions) - criteria_suggestions
        if unexpected_suggestions:
            raise ValueError(
                "PasswordAnalysis.suggestions contains entries that do not "
                "correspond to any failed (non-skipped) criterion's "
                f"suggestion: {sorted(unexpected_suggestions)!r}. Build "
                "suggestions from the `suggestion` field of failed criteria."
            )

    @property
    def effective_max_score(self) -> int:
        """Sum of ``max_score`` values for all non-skipped criteria (computed on demand)."""
        return sum(c.max_score for c in self.criteria if not c.skipped)

    @property
    def passed_count(self) -> int:
        """Number of criteria the password actively satisfied."""
        return sum(1 for c in self.criteria if c.passed)

    @property
    def total_criteria(self) -> int:
        """Number of criteria that were actually evaluated (skipped excluded)."""
        return sum(1 for c in self.criteria if not c.skipped)

    @property
    def score_percent(self) -> int:
        """Score as a percentage of the effective maximum, in ``[0, 100]``."""
        eff_max = self.effective_max_score   # call property; no cached field
        if eff_max == 0:
            return 0
        return min(round(self.score / eff_max * 100), 100)