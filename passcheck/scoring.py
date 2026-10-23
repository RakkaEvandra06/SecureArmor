"""Presentation-agnostic helpers derived from a :class:`~passcheck.models.PasswordAnalysis`."""
from __future__ import annotations

import re
import warnings
from typing import TypedDict

from .constants import STRENGTH_BANDS as _STRENGTH_BANDS
from .constants import is_external_wordlist_loaded as _is_external_wordlist_loaded
from .constants import is_wordlist_sufficient as _is_wordlist_sufficient
from .models import PasswordAnalysis, SkipReason

# ---------------------------------------------------------------------------
# Detail-string redaction patterns
# ---------------------------------------------------------------------------

# "8 chars (minimum 8)"  →  "<hidden> chars (minimum 8)"
_LENGTH_IN_DETAIL_RE: re.Pattern[str] = re.compile(r"^\d+(?= chars )")

# "65.3 bits (target 70+)"  →  "<hidden> bits (target 70+)"
# Matches the entropy detail produced by criterion_entropy().
_ENTROPY_BITS_RE: re.Pattern[str] = re.compile(r"\d+(?:\.\d+)? bits")

# "most-repeated character makes up 50% of the password"
# "75% of characters are unique"
# Any bare percentage surviving after the above replacement.
_RATIO_PERCENT_RE: re.Pattern[str] = re.compile(r"\b\d+%")

# "password is a 4-character block repeated 3×"
# Covers the structural-repeat detail produced by criterion_no_structural_repeat().
_BLOCK_PERIOD_RE: re.Pattern[str] = re.compile(
    r"a \d+-character block repeated \d+\u00d7"  # × == U+00D7
)

# "3/5 character classes used"
# Covers the variety detail produced by criterion_char_variety().
_CLASS_COUNT_RE: re.Pattern[str] = re.compile(r"\b\d+/\d+ character classes")

__all__ = [
    "AnalysisSummary",
    "CriterionSummary",
    "LENGTH_CRITERION_NAMES",
    "criteria_summary",
    "effective_max_score",
    "score_bar",
    "score_to_label",
    "scrub_detail",           # previously _scrub_detail — made public so display.py
]                             # can import it without coupling to a private symbol.

LENGTH_CRITERION_NAMES: frozenset[str] = frozenset({
    "Minimum Length",
    "Good Length",
    "Excellent Length",
})

# ---------------------------------------------------------------------------
# JSON summary types
# ---------------------------------------------------------------------------

class CriterionSummary(TypedDict):
    """JSON-serialisable view of a single :class:`~passcheck.models.CriterionResult`."""

    name:        str
    passed:      bool | None   # None in redact mode for length criteria (SEC-001)
    skipped:     bool
    score:       int  | None   # None in redact mode for length criteria (SEC-001)
    max_score:   int  | None   # None in redact mode for length criteria (SEC-001)
    detail:      str
    suggestion:  str
    skip_reason: str | None

class AnalysisSummary(TypedDict):
    """JSON-serialisable view of a full :class:`~passcheck.models.PasswordAnalysis`."""

    password_masked:          str
    password_length:          int | None
    score:                    int
    effective_max_score:      int
    score_percent:            int
    strength_label:           str
    strength_color:           str
    entropy_bits:             float
    entropy_note:             str | None
    passed_count:             int
    total_criteria:           int
    weak_pattern_cap_applied:      bool
    unicode_checks_skipped:        bool | None   # None in redact mode (SEC-002)
    short_password_checks_skipped: bool | None   # None in redact mode (SEC-002)
    wordlist_sufficient:           bool
    external_wordlist_loaded: bool
    dict_attack_advisory:     str | None
    suggestions:              list[str]
    criteria:                 list[CriterionSummary]

# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------

def effective_max_score(analysis: PasswordAnalysis) -> int:
    """Return the sum of ``max_score`` for every non-skipped criterion in *analysis*."""
    warnings.warn(
        "scoring.effective_max_score() is deprecated and will be removed in a "
        "future release.  Use analysis.effective_max_score instead.",
        DeprecationWarning,
        stacklevel=2,
    )
    return analysis.effective_max_score

def scrub_detail(detail: str, *, redact: bool) -> str:
    """Redact all numeric information from criterion detail strings."""
    if not redact:
        return detail
    detail = _LENGTH_IN_DETAIL_RE.sub("<hidden>", detail)
    detail = _ENTROPY_BITS_RE.sub("<hidden> bits", detail)
    detail = _RATIO_PERCENT_RE.sub("<hidden>%", detail)
    detail = _BLOCK_PERIOD_RE.sub("a repeating block (details hidden)", detail)
    detail = _CLASS_COUNT_RE.sub("<hidden> character classes", detail)
    return detail

def _redacted_entropy(entropy_bits: float) -> float:
    """Return *entropy_bits* rounded to the nearest 5 bits for redacted output."""
    return round(entropy_bits / 5.0) * 5.0

def criteria_summary(
    analysis: PasswordAnalysis,
    *,
    redact: bool = True,
) -> AnalysisSummary:
    """Return a JSON-serialisable summary of *analysis*."""
    masked = "[REDACTED]" if redact else analysis.password_masked

    length = None if redact else analysis.password_length

    unicode_checks_skipped: bool | None = (
        None if redact else
        any(
            c.skip_reason == SkipReason.UNICODE_ONLY_PASSWORD
            for c in analysis.criteria
            if c.skipped
        )
    )

    # Integrators can use this flag to know the common-password and keyboard
    # checks were bypassed because the ASCII residue was fewer than 4 chars,
    # not because the password contained no ASCII at all.
    short_password_checks_skipped: bool | None = (
        None if redact else
        any(
            c.skip_reason == SkipReason.TOO_SHORT_FOR_LOOKUP
            for c in analysis.criteria
            if c.skipped
        )
    )

    # two accurate fields computed from the loader's published state.
    wordlist_sufficient      = _is_wordlist_sufficient()
    external_wordlist_loaded = _is_external_wordlist_loaded()

    # entropy_note is always a non-None string: the formula is always a
    # theoretical upper-bound.  When the weak-pattern cap fired the note
    # is more explicit about the specific risk.
    if analysis.weak_pattern_cap_applied:
        entropy_note: str = (
            "Theoretical estimate only — score was capped due to a detected weak "
            "pattern.  Statistical entropy does not account for pattern-based or "
            "dictionary attacks; actual resistance may be significantly lower."
        )
    else:
        entropy_note = (
            "Theoretical upper-bound estimate based on character-pool size and "
            "repetition penalties.  Actual resistance to targeted attacks may "
            "differ; the estimate does not account for dictionary or pattern-based "
            "guessing strategies."
        )

    # When redacting, round entropy to the nearest 5-bit bucket to reduce
    # fine-grained inference about password length and composition while
    # still communicating the general strength tier.
    entropy_out: float = (
        _redacted_entropy(analysis.entropy_bits)
        if redact
        else round(analysis.entropy_bits, 2)
    )

    # redact mode since the advisory text may implicitly confirm composition
    # details (e.g. "word with substitutions").
    advisory_out: str | None = (
        None if redact else analysis.dict_attack_advisory
    )

    return AnalysisSummary(
        password_masked=masked,
        password_length=length,
        score=analysis.score,
        effective_max_score=analysis.effective_max_score,
        score_percent=analysis.score_percent,
        strength_label=analysis.strength_label,
        strength_color=analysis.strength_color,
        entropy_bits=entropy_out,
        entropy_note=entropy_note,
        passed_count=analysis.passed_count,
        total_criteria=analysis.total_criteria,
        weak_pattern_cap_applied=analysis.weak_pattern_cap_applied,
        unicode_checks_skipped=unicode_checks_skipped,
        short_password_checks_skipped=short_password_checks_skipped,
        wordlist_sufficient=wordlist_sufficient,
        external_wordlist_loaded=external_wordlist_loaded,
        dict_attack_advisory=advisory_out,
        suggestions=list(analysis.suggestions),
        criteria=[
            CriterionSummary(
                name=c.name,
                passed=(
                    None
                    if redact and c.name in LENGTH_CRITERION_NAMES
                    else c.passed
                ),
                skipped=c.skipped,
                score=(
                    None
                    if redact and c.name in LENGTH_CRITERION_NAMES
                    else c.score
                ),
                max_score=(
                    None
                    if redact and c.name in LENGTH_CRITERION_NAMES
                    else c.max_score
                ),
                detail=scrub_detail(c.detail, redact=redact),
                suggestion=c.suggestion,
                skip_reason=c.skip_reason.value if c.skip_reason is not None else None,
            )
            for c in analysis.criteria
        ],
    )

def score_bar(percent: int, *, width: int = 20, utf: bool = True) -> str:
    """Return a fixed-*width*-character progress bar representing *percent* (0-100)."""
    clamped = max(0, min(percent, 100))
    filled  = round(width * clamped / 100)
    empty   = width - filled

    fill_char, empty_char = ("█", "░") if utf else ("#", "-")
    return fill_char * filled + empty_char * empty

def score_to_label(percent: int) -> tuple[str, str]:
    """Return ``(label, colour_key)`` for a score *percent* in ``[0, 100]``."""
    pct = max(0, min(percent, 100))
    for threshold, label, colour in _STRENGTH_BANDS:
        if pct >= threshold:
            return label, colour
    return _STRENGTH_BANDS[-1][1], _STRENGTH_BANDS[-1][2]