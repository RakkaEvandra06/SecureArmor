"""Terminal rendering for password analysis results."""
from __future__ import annotations

import json
import re
import threading
from typing import TYPE_CHECKING

import colorama
from colorama import Fore, Style

from .constants import VALID_COLOUR_KEYS as _VALID_COLOUR_KEYS
from .models import PasswordAnalysis, SkipReason, compute_score_percent
from .scoring import (  # scrub_detail is now public
    LENGTH_CRITERION_NAMES,
    criteria_summary,
    score_bar,
    scrub_detail,
)
from .utils import is_utf_terminal as _is_utf_terminal

if TYPE_CHECKING:
    from .models import CriterionResult

_COLORAMA_LOCK:        threading.Lock = threading.Lock()
_COLORAMA_INITIALISED: bool           = False

def _ensure_colorama_init() -> None:
    """Initialise colorama exactly once; thread-safe via double-checked locking."""
    global _COLORAMA_INITIALISED
    if not _COLORAMA_INITIALISED:
        with _COLORAMA_LOCK:
            if not _COLORAMA_INITIALISED:
                colorama.init(autoreset=True)
                _COLORAMA_INITIALISED = True

# ---------------------------------------------------------------------------
# Layout constants
# ---------------------------------------------------------------------------

_BANNER_WIDTH:         int = 60
_SEPARATOR_WIDTH:      int = 64
_CRITERION_NAME_WIDTH: int = 26
_UTF_TERMINAL: bool = _is_utf_terminal()

# ---------------------------------------------------------------------------
# Colour map
# ---------------------------------------------------------------------------

_COLOUR_MAP: dict[str, str] = {
    "bright_green": Fore.LIGHTGREEN_EX,
    "green":        Fore.GREEN,
    "yellow":       Fore.YELLOW,
    "red":          Fore.RED,
    "bright_red":   Fore.LIGHTRED_EX,
}

_missing_keys = sorted(_VALID_COLOUR_KEYS - frozenset(_COLOUR_MAP))
if _missing_keys:
    raise ValueError(
        f"_COLOUR_MAP is missing ANSI entries for colour key(s) declared in "
        f"VALID_COLOUR_KEYS: {_missing_keys}. "
        "Add the missing keys to _COLOUR_MAP or update VALID_COLOUR_KEYS "
        "in constants.py."
    )
del _missing_keys

# ---------------------------------------------------------------------------
# ANSI helpers
# ---------------------------------------------------------------------------

_ANSI_ESC: re.Pattern[str] = re.compile(r"\x1b\[[0-9;]*m")

def _coloured(text: str, colour_key: str) -> str:
    """Wrap *text* in the ANSI escape codes for *colour_key*."""
    code = _COLOUR_MAP.get(colour_key)
    if code is None:
        raise ValueError(
            f"Unknown colour key {colour_key!r}. "
            f"Valid keys: {sorted(_COLOUR_MAP)}."
        )
    return f"{code}{text}{Style.RESET_ALL}"

def _bold(text: str) -> str:
    """Wrap *text* in the ANSI bold escape code."""
    return f"{Style.BRIGHT}{text}{Style.RESET_ALL}"

def _dim(text: str) -> str:
    """Wrap *text* in the ANSI dim escape code."""
    return f"{Style.DIM}{text}{Style.RESET_ALL}"

def _visible_len(s: str) -> int:
    """Return the printable character count of *s*, ignoring ANSI codes."""
    return len(_ANSI_ESC.sub("", s))

def _ljust_ansi(s: str, width: int) -> str:
    """Left-justify *s* to *width* visible characters, preserving ANSI codes."""
    return s + " " * max(width - _visible_len(s), 0)

def _rjust_ansi(s: str, width: int) -> str:
    """Right-justify *s* to *width* visible characters, preserving ANSI codes."""
    return " " * max(width - _visible_len(s), 0) + s

# ---------------------------------------------------------------------------
# Skip-detection helpers
# ---------------------------------------------------------------------------

def _has_unicode_only_skip(analysis: PasswordAnalysis) -> bool:
    """Return ``True`` when any criterion was skipped due to a Unicode-only password."""
    return any(
        c.skip_reason == SkipReason.UNICODE_ONLY_PASSWORD
        for c in analysis.criteria
        if c.skipped
    )

# ---------------------------------------------------------------------------
# Public rendering functions
# ---------------------------------------------------------------------------

def print_analysis(analysis: PasswordAnalysis, *, redact: bool = True) -> None:
    """Render a full human-readable analysis block to stdout."""
    _ensure_colorama_init()
    _print_header(analysis, redact=redact)
    _print_score_panel(analysis, redact=redact)
    _print_criteria_table(analysis, redact=redact)
    if analysis.suggestions:
        _print_suggestions(analysis)
    if not redact and analysis.dict_attack_advisory:
        _print_dict_attack_advisory(analysis.dict_attack_advisory)
    if _has_unicode_only_skip(analysis):
        _print_unicode_advisory()

def print_analysis_json(analysis: PasswordAnalysis, *, redact: bool = True) -> None:
    """Render *analysis* as a compact JSON line (NDJSON-compatible) to stdout."""
    print(json.dumps(criteria_summary(analysis, redact=redact)))

def print_banner() -> None:
    """Print the PassCheck welcome banner to stdout."""
    _ensure_colorama_init()
    if _UTF_TERMINAL:
        tl, tr, bl, br, h, v = "╔", "╗", "╚", "╝", "═", "║"
    else:
        tl, tr, bl, br, h, v = "+", "+", "+", "+", "-", "|"

    print()
    print(_coloured(tl + h * _BANNER_WIDTH + tr, "bright_green"))
    print(
        _coloured(v, "bright_green")
        + _bold("  PassCheck — Password Strength Analyser  ".center(_BANNER_WIDTH))
        + _coloured(v, "bright_green")
    )
    print(_coloured(bl + h * _BANNER_WIDTH + br, "bright_green"))
    print(_dim("  Type a password to analyse it, or press Ctrl-D / Ctrl-C to quit.\n"))

def print_separator() -> None:
    """Print a horizontal rule between analysis blocks."""
    _ensure_colorama_init()
    char = "─" if _UTF_TERMINAL else "-"
    print(_dim(char * _SEPARATOR_WIDTH))

# ---------------------------------------------------------------------------
# Private rendering helpers
# ---------------------------------------------------------------------------

def _print_header(analysis: PasswordAnalysis, *, redact: bool = False) -> None:
    """Print the password header line."""
    display_pw  = "[REDACTED]" if redact else analysis.password_masked
    length_part = "" if redact else f"  {_dim(f'({analysis.password_length} chars)')}"
    print(f"\n  {_bold('Password:')} {_dim(display_pw)}{length_part}")

def _print_score_panel(analysis: PasswordAnalysis, *, redact: bool = False) -> None:
    """Print the score bar, strength label, entropy, and criteria counts."""
    color   = analysis.strength_color
    score   = analysis.score
    eff_max = analysis.effective_max_score
    denom   = str(eff_max)
    bar_pct = compute_score_percent(score, eff_max)
    bar     = score_bar(bar_pct, width=24, utf=_UTF_TERMINAL)

    print()
    if analysis.weak_pattern_cap_applied:
        print(
            _coloured(
                "  ⚠ Score capped: this password matches a known common/weak "
                "pattern, so its score is capped regardless of other criteria "
                "passed below.",
                "red",
            )
        )
    print(
        f"  {_coloured(bar, color)}"
        f"  {_bold(_coloured(f'{score:>3}/{denom}', color))}"
        f"  {_bold(_coloured(f'[{analysis.strength_label}]', color))}"
    )
    entropy_note = (
        " (theoretical; pattern cap applied — see suggestions)"
        if analysis.weak_pattern_cap_applied
        else ""
    )
    # Round to the nearest 5-bit bucket in redact mode to prevent the
    # exact entropy value from acting as a password-length oracle.
    if redact:
        entropy_display = round(analysis.entropy_bits / 5.0) * 5.0
        entropy_str = f"{entropy_display:.0f} bits (≈5-bit precision)"
    else:
        entropy_str = f"{analysis.entropy_bits:.1f} bits"
    print(
        _dim(
            f"  Entropy: {entropy_str}{entropy_note}"
            f"   Criteria: {analysis.passed_count}/{analysis.total_criteria} passed"
        )
    )
    print()

def _print_criteria_table(analysis: PasswordAnalysis, *, redact: bool = False) -> None:
    """Render the per-criterion results table."""
    rule_char = "─" if _UTF_TERMINAL else "-"

    col          = _CRITERION_NAME_WIDTH
    header_name  = _ljust_ansi(_bold("Criterion"), col)
    header_score = _rjust_ansi(_bold("Score"), 8)

    print(f"  {'':2}  {header_name}  {header_score}  {_dim('Detail')}")
    print(_dim("  " + rule_char * (_SEPARATOR_WIDTH - 2)))

    for criterion in analysis.criteria:
        # SEC-001: pass redact so length-criteria show a neutral icon instead of
        # ✔/✘, preventing the three-bit length-bracket oracle in terminal output.
        icon, score_cell = _format_criterion_status(criterion, redact=redact)
        name_col  = _ljust_ansi(criterion.name[:col], col)
        score_col = _rjust_ansi(score_cell, 8)
        detail    = scrub_detail(criterion.detail, redact=redact)
        print(f"  {icon}   {name_col}  {score_col}  {_dim(detail)}")

    print()

def _format_criterion_status(
    criterion: "CriterionResult",
    *,
    redact: bool = False,
) -> tuple[str, str]:
    """Return ``(icon, score_cell)`` strings for a single criterion row.

    When *redact* is ``True`` the three length criteria are rendered with a
    neutral "–" icon and no score cell so their pass/fail status cannot be
    used as a 4-bracket password-length oracle (SEC-001).
    """
    if criterion.skipped:
        return _coloured("⊘" if _UTF_TERMINAL else "~", "yellow"), _dim("   —   ")
    # SEC-001: suppress pass/fail icon for length criteria in redact mode.
    if redact and criterion.name in LENGTH_CRITERION_NAMES:
        return _dim("–" if _UTF_TERMINAL else "-"), _dim("   —   ")
    if criterion.passed:
        return _coloured("✔" if _UTF_TERMINAL else "+", "green"), _coloured(f"+{criterion.score}", "green")
    return _coloured("✘" if _UTF_TERMINAL else "x", "red"), _dim(f"+{criterion.score}/{criterion.max_score}")

def _print_suggestions(analysis: PasswordAnalysis) -> None:
    """Print the numbered suggestion list."""
    print(f"  {_coloured(_bold('Suggestions'), 'yellow')}")
    for i, tip in enumerate(analysis.suggestions, start=1):
        print(f"   {_coloured(str(i) + '.', 'yellow')} {tip}")

def _print_dict_attack_advisory(advisory: str) -> None:
    """Print the dictionary-attack advisory when the entropy estimate is marginal."""
    icon = "⚠" if _UTF_TERMINAL else "!"
    print(
        _coloured(
            f"  {icon} Dictionary-attack advisory: {advisory}",
            "yellow",
        )
    )
    print()

def _print_unicode_advisory() -> None:
    """Print an advisory when common-password / keyboard checks were skipped."""
    icon = "⚠" if _UTF_TERMINAL else "!"
    print(
        _coloured(
            f"  {icon} Unicode-only password detected: common-password and\n"
            "    keyboard-walk checks were skipped (no ASCII residue to match\n"
            "    against known weak-pattern lists).  Verify independently that\n"
            "    this password does not follow a predictable or widely-used\n"
            "    pattern (e.g. a popular emoji sequence or common CJK phrase).",
            "yellow",
        )
    )
    print()