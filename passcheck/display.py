from __future__ import annotations

import json
import re

import colorama
from colorama import Fore, Style

colorama.init(autoreset=True)

from .models import PasswordAnalysis
from .scoring import criteria_summary, score_bar

# ---------------------------------------------------------------------------
# Layout constants
# ---------------------------------------------------------------------------

_BANNER_WIDTH:    int = 60
_SEPARATOR_WIDTH: int = 64
_CRITERION_NAME_WIDTH: int = 26

# ---------------------------------------------------------------------------
# Internal colour map
# ---------------------------------------------------------------------------

_COLOUR_MAP: dict[str, str] = {
    "bright_green": Fore.LIGHTGREEN_EX,
    "green":        Fore.GREEN,
    "yellow":       Fore.YELLOW,
    "red":          Fore.RED,
    "bright_red":   Fore.LIGHTRED_EX,
}

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
    """Wrap *text* in the ANSI bright/bold escape code."""
    return f"{Style.BRIGHT}{text}{Style.RESET_ALL}"

def _dim(text: str) -> str:
    """Wrap *text* in the ANSI dim escape code."""
    return f"{Style.DIM}{text}{Style.RESET_ALL}"

# Matches any ANSI CSI escape sequence (colours, bold, dim, reset, …).
_ANSI_ESC: re.Pattern[str] = re.compile(r"\x1b\[[0-9;]*m")

def _visible_len(s: str) -> int:
    """Return the *printable* character count of *s*, ignoring ANSI codes."""
    return len(_ANSI_ESC.sub("", s))

def _ljust_ansi(s: str, width: int) -> str:
    """Left-justify *s* to *width* **visible** characters, preserving ANSI codes."""
    pad = width - _visible_len(s)
    return s + " " * max(pad, 0)

def _rjust_ansi(s: str, width: int) -> str:
    """Right-justify *s* to *width* **visible** characters, preserving ANSI codes."""
    pad = width - _visible_len(s)
    return " " * max(pad, 0) + s

# ---------------------------------------------------------------------------
# Public rendering functions
# ---------------------------------------------------------------------------

def print_analysis(analysis: PasswordAnalysis, *, show_password: bool = False) -> None:
    """Render a full human-readable analysis block to stdout."""
    _print_header(analysis, show_password=show_password)
    _print_score_panel(analysis)
    _print_criteria_table(analysis)
    if analysis.suggestions:
        _print_suggestions(analysis)
    print()

def print_analysis_json(analysis: PasswordAnalysis) -> None:
    """Render *analysis* as indented JSON to stdout."""
    print(json.dumps(criteria_summary(analysis), indent=2))

def print_banner() -> None:
    """Print the PassCheck welcome banner to stdout."""
    print()
    print(_coloured("╔" + "═" * _BANNER_WIDTH + "╗", "bright_green"))
    print(
        _coloured("║", "bright_green")
        + _bold("  PassCheck — Password Strength Analyser  ".center(_BANNER_WIDTH))
        + _coloured("║", "bright_green")
    )
    print(_coloured("╚" + "═" * _BANNER_WIDTH + "╝", "bright_green"))
    print(_dim("  Type a password to analyse it, or 'quit'/'exit' to leave.\n"))

def print_separator() -> None:
    """Print a horizontal rule between analysis blocks."""
    print(_dim("─" * _SEPARATOR_WIDTH))

# ---------------------------------------------------------------------------
# Private rendering helpers
# ---------------------------------------------------------------------------

def _masked(password: str) -> str:
    """Return a display-safe masked version of *password*."""
    length = len(password)
    if length <= 2:
        return "*" * length
    return password[0] + "*" * (length - 2) + password[-1]

def _print_header(analysis: PasswordAnalysis, *, show_password: bool) -> None:
    display = analysis.password if show_password else _masked(analysis.password)
    print(
        f"\n  {_bold('Password:')} {_dim(display)}"
        f"  {_dim(f'({len(analysis.password)} chars)')}"
    )

def _print_score_panel(analysis: PasswordAnalysis) -> None:
    color = analysis.strength_color
    score = analysis.score
    bar   = score_bar(score, width=24)
    print()
    print(
        f"  {_coloured(bar, color)}"
        f"  {_bold(_coloured(f'{score:>3}/100', color))}"
        f"  {_bold(_coloured(f'[{analysis.strength_label}]', color))}"
    )
    print(
        _dim(
            f"  Entropy: {analysis.entropy_bits:.1f} bits"
            f"   Criteria: {analysis.passed_count}/{analysis.total_criteria} passed"
        )
    )
    print()

def _print_criteria_table(analysis: PasswordAnalysis) -> None:
    col = _CRITERION_NAME_WIDTH
    header_criterion = _ljust_ansi(_bold("Criterion"), col)
    header_score     = _rjust_ansi(_bold("Score"), 8)
    print(f"  {'':2}  {header_criterion}  {header_score}  {_dim('Detail')}")
    print(_dim("  " + "─" * (_SEPARATOR_WIDTH - 2)))

    for c in analysis.criteria:
        icon       = _coloured("✔", "green") if c.passed else _coloured("✘", "red")
        score_cell = _coloured(f"+{c.score}", "green") if c.passed else _dim(f"+0/{c.max_score}")
        name_col   = _ljust_ansi(c.name[:col], col)
        score_col  = _rjust_ansi(score_cell, 8)
        print(f"  {icon}   {name_col}  {score_col}  {_dim(c.detail)}")

    print()

def _print_suggestions(analysis: PasswordAnalysis) -> None:
    print(f"  {_coloured(_bold('Suggestions'), 'yellow')}")
    for i, tip in enumerate(analysis.suggestions, start=1):
        print(f"   {_coloured(str(i) + '.', 'yellow')} {tip}")