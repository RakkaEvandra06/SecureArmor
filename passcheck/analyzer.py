from __future__ import annotations

import math
import unicodedata
from collections import Counter
from dataclasses import dataclass, field
from types import MappingProxyType

from .constants import (
    CHAR_UNIQUENESS_MIN_RATIO,
    CHAR_VARIETY_MIN_CLASSES,
    COMMON_PASSWORDS,
    ENTROPY_GOOD_THRESHOLD,
    KEYBOARD_PATTERNS,
    LENGTH_EXCELLENT,
    LENGTH_GOOD,
    LENGTH_MAXIMUM,
    LENGTH_MINIMUM,
    REPEATED_CHAR_RATIO,
    SCORE_WEIGHTS,
    SHANNON_WEIGHT,
    SPECIAL_CHARS,
    STRENGTH_BANDS,
)
from .models import CriterionResult, PasswordAnalysis
from .utils import masked_password as _masked_password

# Maximum number of distinct keyboard patterns shown in a failure detail line.
_KEYBOARD_DISPLAY_CAP: int = 3

# Appended to the entropy detail when the check is skipped.
_ENTROPY_SKIPPED_NOTE: str = "- skipped (repetition penalty already applied)"

# ---------------------------------------------------------------------------
# Leet-speak substitution table
# ---------------------------------------------------------------------------

_LEET_TABLE: dict[int, str] = str.maketrans({
    "@": "a", "4": "a",
    "3": "e",
    "1": "i",   # adm1n → admin, m@tr1x → matrix
    "!": "i",   # pass!on → passion
    "|": "i",
    "6": "g",   # 6oogle → google
    "8": "b",   # 8ball  → bball
    "0": "o",
    "5": "s", "$": "s",
    "7": "t",
})

_PUNCTUATION_CHARS: str = (
    "!@#$%^&*()-_=+[]{}|;:,.<>?/"
    "\\"   # backslash
    '"'    # double-quote
    "'`~"
)

#   '!!password!!'  →  strip  →  'password'   →  leet  →  'password'  ✓
#   'adm1n'         →  strip  →  'adm1n'      →  leet  →  'admin'     ✓
#   'p@$$w0rd'      →  strip  →  'p@$$w0rd'   →  leet  →  'password'  ✓
#   '@dmin'         →  leet (no strip first)   →  'admin'             ✓
def _normalise_for_lookup(pw: str) -> tuple[str, str, str, str]:
    """Return four lookup keys for common-password detection."""
    nfkd     = unicodedata.normalize("NFKD", pw.lower())
    ascii_pw = nfkd.encode("ascii", errors="ignore").decode("ascii")
    # Strip punctuation on the raw ASCII form first, then leet-substitute.
    stripped   = ascii_pw.strip(_PUNCTUATION_CHARS)
    normalised = stripped.translate(_LEET_TABLE)
    leet_full  = ascii_pw.translate(_LEET_TABLE)
    return ascii_pw, normalised, stripped, leet_full

# ---------------------------------------------------------------------------
# Character profile
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class _CharProfile:
    """Immutable character-level profile of a password."""

    length:          int
    has_upper:       bool
    has_lower:       bool
    has_digit:       bool
    has_special:     bool
    has_non_ascii:   bool
    has_ascii_upper: bool
    has_ascii_lower: bool
    char_counts:     MappingProxyType[str, int]

    # Pre-sorted (char, count) pairs; populated in __post_init__.
    _sorted_counts: tuple[tuple[str, int], ...] = field(
        init=False, repr=False, compare=False, default=()
    )

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "_sorted_counts",
            tuple(
                sorted(self.char_counts.items(), key=lambda kv: kv[1], reverse=True)
            ),
        )

    @classmethod
    def from_password(cls, pw: str) -> _CharProfile:
        """Build a :class:`_CharProfile` from *pw* in a single O(n) pass."""
        has_upper       = False
        has_lower       = False
        has_digit       = False
        has_special     = False
        has_non_ascii   = False
        has_ascii_upper = False
        has_ascii_lower = False
        counts: Counter[str] = Counter()

        for ch in pw:
            counts[ch] += 1
            if not has_upper       and ch.isupper():         has_upper       = True
            if not has_lower       and ch.islower():         has_lower       = True
            if not has_digit       and ch.isdigit():         has_digit       = True
            if not has_special     and ch in SPECIAL_CHARS:  has_special     = True
            if not has_non_ascii   and ord(ch) > 127:        has_non_ascii   = True
            if not has_ascii_upper and ch.isupper() and ord(ch) <= 127:
                has_ascii_upper = True
            if not has_ascii_lower and ch.islower() and ord(ch) <= 127:
                has_ascii_lower = True

        return cls(
            length          = len(pw),
            has_upper       = has_upper,
            has_lower       = has_lower,
            has_digit       = has_digit,
            has_special     = has_special,
            has_non_ascii   = has_non_ascii,
            has_ascii_upper = has_ascii_upper,
            has_ascii_lower = has_ascii_lower,
            char_counts     = MappingProxyType(dict(counts)),
        )

    def most_common(self, n: int = 1) -> tuple[tuple[str, int], ...]:
        """Return the *n* most common ``(char, count)`` pairs, descending by count."""
        return self._sorted_counts[:n]

def _non_ascii_pool_size(char_counts: MappingProxyType[str, int]) -> int:
    """Estimate the alphabet pool size contributed by non-ASCII characters."""
    max_ord = max(
        (ord(c) for c in char_counts if ord(c) > 127),
        default=0,
    )
    if max_ord == 0:
        return 0
    if max_ord < 0x0250:   # Latin-1 Supplement + Latin Extended-A/B
        return 128
    if max_ord < 0x0500:   # IPA Ext, Greek, Cyrillic, …
        return 256
    if max_ord < 0x4E00:   # Arabic, Hebrew, misc scripts
        return 512
    return 1024            # CJK Unified Ideographs and beyond

# ---------------------------------------------------------------------------
# Analyser
# ---------------------------------------------------------------------------

class PasswordAnalyzer:
    """Stateless password-strength analyser."""

    def analyze(self, password: str) -> PasswordAnalysis:
        """Analyse *password* and return a fully-populated :class:`PasswordAnalysis`."""
        if not password:
            raise ValueError("Password must not be empty.")
        if len(password) > LENGTH_MAXIMUM:
            raise ValueError(
                f"Password length {len(password)} exceeds the maximum "
                f"allowed length of {LENGTH_MAXIMUM} characters."
            )

        profile           = _CharProfile.from_password(password)
        entropy_bits      = self._calculate_entropy(profile)
        repetition_result = self._check_no_repeated_chars(profile)
        entropy_result    = self._check_entropy(
            entropy_bits,
            repetition_passed=repetition_result.passed,
            password_length=profile.length,
        )
        common_result   = self._check_no_common_password(password)
        keyboard_result = self._check_no_keyboard_pattern(
            password,
            skip=not common_result.passed,
        )

        criteria: list[CriterionResult] = [
            self._check_length_minimum(profile),
            self._check_length_good(profile),
            self._check_length_excellent(profile),
            self._check_has_uppercase(profile),
            self._check_has_lowercase(profile),
            self._check_has_digit(profile),
            self._check_has_special(profile),
            self._check_char_variety(profile),
            self._check_char_uniqueness(profile),
            common_result,
            keyboard_result,
            repetition_result,
            entropy_result,
        ]

        score        = min(100, sum(c.score for c in criteria))
        label, color = self._strength_band(score)
        suggestions  = tuple(
            c.suggestion
            for c in criteria
            if not c.skipped and not c.passed and c.suggestion
        )

        return PasswordAnalysis(
            # Store only the masked form — never the raw password.
            password_masked = _masked_password(password),
            password_length = len(password),
            score           = score,
            strength_label  = label,
            strength_color  = color,
            criteria        = tuple(criteria),
            entropy_bits    = entropy_bits,
            suggestions     = suggestions,
        )

    # ------------------------------------------------------------------
    # Shared criterion-builder helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _make_length_criterion(
        profile:    _CharProfile,
        key:        str,
        name:       str,
        threshold:  int,
        label:      str,
        suggestion: str,
    ) -> CriterionResult:
        """Build a length-based :class:`CriterionResult` from *profile*."""
        passed = profile.length >= threshold
        w      = SCORE_WEIGHTS[key]
        return CriterionResult(
            name       = name,
            passed     = passed,
            score      = w if passed else 0,
            max_score  = w,
            detail     = f"Length is {profile.length} characters ({label} {threshold})",
            suggestion = suggestion if not passed else "",
        )

    @staticmethod
    def _make_presence_criterion(
        key:            str,
        name:           str,
        present:        bool,
        detail_present: str,
        detail_absent:  str,
        suggestion:     str,
    ) -> CriterionResult:
        """Build a character-presence :class:`CriterionResult`."""
        w = SCORE_WEIGHTS[key]
        return CriterionResult(
            name       = name,
            passed     = present,
            score      = w if present else 0,
            max_score  = w,
            detail     = detail_present if present else detail_absent,
            suggestion = "" if present else suggestion,
        )

    # ------------------------------------------------------------------
    # Criterion checks — length
    # ------------------------------------------------------------------

    def _check_length_minimum(self, profile: _CharProfile) -> CriterionResult:
        return self._make_length_criterion(
            profile,
            key        = "length_minimum",
            name       = "Minimum length",
            threshold  = LENGTH_MINIMUM,
            label      = "minimum >=",
            suggestion = f"Use at least {LENGTH_MINIMUM} characters.",
        )

    def _check_length_good(self, profile: _CharProfile) -> CriterionResult:
        return self._make_length_criterion(
            profile,
            key        = "length_good",
            name       = "Recommended length",
            threshold  = LENGTH_GOOD,
            label      = "recommended >=",
            suggestion = f"Aim for at least {LENGTH_GOOD} characters for better security.",
        )

    def _check_length_excellent(self, profile: _CharProfile) -> CriterionResult:
        return self._make_length_criterion(
            profile,
            key        = "length_excellent",
            name       = "Excellent length",
            threshold  = LENGTH_EXCELLENT,
            label      = "excellent >=",
            suggestion = (
                f"Consider a passphrase of {LENGTH_EXCELLENT}+ characters "
                "for maximum security."
            ),
        )

    # ------------------------------------------------------------------
    # Criterion checks — character-class presence
    # ------------------------------------------------------------------

    def _check_has_uppercase(self, profile: _CharProfile) -> CriterionResult:
        return self._make_presence_criterion(
            key            = "has_uppercase",
            name           = "Uppercase letters",
            present        = profile.has_ascii_upper,
            detail_present = "Contains ASCII uppercase letters (A-Z)",
            detail_absent  = "No ASCII uppercase letters (A-Z) found",
            suggestion     = "Add at least one uppercase letter (A-Z).",
        )

    def _check_has_lowercase(self, profile: _CharProfile) -> CriterionResult:
        return self._make_presence_criterion(
            key            = "has_lowercase",
            name           = "Lowercase letters",
            present        = profile.has_ascii_lower,
            detail_present = "Contains ASCII lowercase letters (a-z)",
            detail_absent  = "No ASCII lowercase letters (a-z) found",
            suggestion     = "Add at least one lowercase letter (a-z).",
        )

    def _check_has_digit(self, profile: _CharProfile) -> CriterionResult:
        return self._make_presence_criterion(
            key            = "has_digit",
            name           = "Digits",
            present        = profile.has_digit,
            detail_present = "Contains at least one digit",
            detail_absent  = "No digits found",
            suggestion     = "Add at least one number (0-9).",
        )

    def _check_has_special(self, profile: _CharProfile) -> CriterionResult:
        return self._make_presence_criterion(
            key            = "has_special",
            name           = "Special characters",
            present        = profile.has_special,
            detail_present = "Contains special characters",
            detail_absent  = "No special characters found",
            suggestion     = "Add special characters such as: ! @ # $ % ^ & *",
        )

    # ------------------------------------------------------------------
    # Criterion checks — composition quality
    # ------------------------------------------------------------------

    def _check_char_variety(self, profile: _CharProfile) -> CriterionResult:
        """Award points when the password uses at least 3 of the 5 character classes."""
        class_count = sum((
            profile.has_ascii_upper,
            profile.has_ascii_lower,
            profile.has_digit,
            profile.has_special,
            profile.has_non_ascii,
        ))
        passed = class_count >= CHAR_VARIETY_MIN_CLASSES
        w      = SCORE_WEIGHTS["char_variety"]
        return CriterionResult(
            name       = "Character variety",
            passed     = passed,
            score      = w if passed else 0,
            max_score  = w,
            detail     = f"Uses {class_count}/5 character classes",
            suggestion = (
                "Mix uppercase, lowercase, digits, special characters, "
                "or non-ASCII characters."
                if not passed else ""
            ),
        )

    def _check_char_uniqueness(self, profile: _CharProfile) -> CriterionResult:
        """Award points when at least 60 % of the password's characters are distinct."""
        unique_count = len(profile.char_counts)
        ratio        = unique_count / profile.length if profile.length else 0.0
        passed       = ratio >= CHAR_UNIQUENESS_MIN_RATIO
        w            = SCORE_WEIGHTS["char_uniqueness"]
        return CriterionResult(
            name       = "Character uniqueness",
            passed     = passed,
            score      = w if passed else 0,
            max_score  = w,
            detail     = f"{unique_count} unique chars out of {profile.length} ({ratio:.0%})",
            suggestion = (
                "Avoid repetitive patterns — use a greater variety of distinct characters."
                if not passed else ""
            ),
        )

    # ------------------------------------------------------------------
    # Criterion checks — blacklist / pattern detection
    # ------------------------------------------------------------------

    def _check_no_common_password(self, pw: str) -> CriterionResult:
        """Fail if the password (or a normalised variant) appears in the common-password list."""
        ascii_lower, normalised, stripped, leet_full = _normalise_for_lookup(pw)
        is_common = (
            ascii_lower in COMMON_PASSWORDS   # verbatim:         "angel1"
            or normalised  in COMMON_PASSWORDS # strip + leet:     "adm1n"      → "admin"
            or stripped    in COMMON_PASSWORDS # edge-stripped:    "!!password!!" → "password"
            or leet_full   in COMMON_PASSWORDS # leet (no strip):  "@dmin"      → "admin"
        )
        w = SCORE_WEIGHTS["no_common_password"]
        return CriterionResult(
            name       = "Not a common password",
            passed     = not is_common,
            score      = 0 if is_common else w,
            max_score  = w,
            detail     = (
                "Password (or a common variant) appears in common password lists!"
                if is_common
                else "Not found in common password lists"
            ),
            suggestion = (
                "Avoid well-known passwords and their simple substitutions — "
                "they are cracked instantly."
                if is_common else ""
            ),
        )

    def _check_no_keyboard_pattern(
        self,
        pw: str,
        *,
        skip: bool = False,
    ) -> CriterionResult:
        """Fail if the password contains a recognisable keyboard walk."""
        w = SCORE_WEIGHTS["no_keyboard_pattern"]

        if skip:
            return CriterionResult(
                name       = "No keyboard patterns",
                passed     = False,
                skipped    = True,
                score      = 0,
                max_score  = w,
                detail     = "- skipped (common password already detected)",
                suggestion = "",
            )

        pw_lower = pw.lower()
        found    = [p for p in KEYBOARD_PATTERNS if p in pw_lower]
        passed   = not found

        display  = found[:_KEYBOARD_DISPLAY_CAP]
        extra    = len(found) - len(display)
        suffix   = f" (+{extra} more)" if extra else ""

        return CriterionResult(
            name       = "No keyboard patterns",
            passed     = passed,
            score      = w if passed else 0,
            max_score  = w,
            detail     = (
                f"Keyboard patterns detected: {', '.join(display)}{suffix}"
                if not passed
                else "No obvious keyboard patterns detected"
            ),
            suggestion = (
                "Avoid sequences like 'qwerty', '123456', 'asdfgh'."
                if not passed else ""
            ),
        )

    def _check_no_repeated_chars(self, profile: _CharProfile) -> CriterionResult:
        """Fail if a single character occupies 40 % or more of the password."""
        if profile.length == 0:
            raise RuntimeError(
                "_check_no_repeated_chars() reached with an empty profile — "
                "analyze() must reject empty passwords before any criterion runs."
            )

        w = SCORE_WEIGHTS["no_repeated_chars"]
        top_char, top_count = profile.most_common(1)[0]
        ratio  = top_count / profile.length
        passed = ratio < REPEATED_CHAR_RATIO

        return CriterionResult(
            name       = "No excessive repetition",
            passed     = passed,
            score      = w if passed else 0,
            max_score  = w,
            detail     = (
                f"Max repetition: {top_count}x ({ratio:.0%}) — within limits"
                if passed
                else (
                    f"Top character appears {top_count}x "
                    f"({ratio:.0%} of password) — exceeds limit"
                )
            ),
            suggestion = (
                "Avoid repeating the same character too many times."
                if not passed else ""
            ),
        )

    def _check_entropy(
        self,
        entropy_bits: float,
        *,
        repetition_passed: bool,
        password_length:   int,
    ) -> CriterionResult:
        """Award bonus points when estimated entropy meets the threshold."""
        w = SCORE_WEIGHTS["entropy_bonus"]

        if not repetition_passed:
            return CriterionResult(
                name       = "Entropy",
                passed     = False,
                skipped    = True,
                score      = 0,
                max_score  = w,
                detail     = f"Estimated entropy: {entropy_bits:.1f} bits {_ENTROPY_SKIPPED_NOTE}",
                suggestion = "",
            )

        # Hint users to prioritise length when it is the binding constraint.
        length_note = " — increase length first" if password_length < LENGTH_GOOD else ""
        passed      = entropy_bits >= ENTROPY_GOOD_THRESHOLD

        return CriterionResult(
            name       = "Entropy",
            passed     = passed,
            score      = w if passed else 0,
            max_score  = w,
            detail     = (
                f"Estimated entropy: {entropy_bits:.1f} bits "
                f"(good >= {ENTROPY_GOOD_THRESHOLD:.0f} bits{length_note})"
            ),
            suggestion = (
                "Increase length and character variety to raise entropy."
                if not passed else ""
            ),
        )

    # ------------------------------------------------------------------
    # Static helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _calculate_entropy(profile: _CharProfile) -> float:
        """Estimate password entropy (bits) via a pool-size / Shannon blend."""
        if profile.length == 0:
            return 0.0

        pool = 0
        if profile.has_ascii_lower: pool += 26
        if profile.has_ascii_upper: pool += 26
        if profile.has_digit:       pool += 10
        if profile.has_special:     pool += len(SPECIAL_CHARS)
        if profile.has_non_ascii:   pool += _non_ascii_pool_size(profile.char_counts)

        if pool == 0:
            return 0.0

        pool_entropy_per_char = math.log2(pool)

        total = profile.length
        shannon_per_char = -sum(
            (count / total) * math.log2(count / total)
            for count in profile.char_counts.values()
        )

        entropy_per_char = (
            (1.0 - SHANNON_WEIGHT) * pool_entropy_per_char
            + SHANNON_WEIGHT       * shannon_per_char
        )
        return max(0.0, entropy_per_char * profile.length)

    @staticmethod
    def _strength_band(score: int) -> tuple[str, str]:
        """Map a numeric *score* (0–100) to a ``(label, colour_key)`` pair."""
        for threshold, label, color in STRENGTH_BANDS:
            if score >= threshold:
                return label, color
        raise ValueError(
            f"No matching strength band found for score {score}. "
            "Ensure STRENGTH_BANDS contains an entry with threshold 0."
        )