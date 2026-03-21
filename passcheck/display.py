"""
display.py — Terminal rendering using colorama (no rich dependency).

Keeps all I/O concerns isolated from analysis and scoring logic.
"""

from __future__ import annotations

import json
import sys

import colorama
from colorama import Fore, Style

colorama.init(autoreset=True)

from .models import PasswordAnalysis
from .scoring import criteria_summary, score_bar

# ---------------------------------------------------------------------------
# Colour helpers
# ---------------------------------------------------------------------------

_COLOUR_MAP: dict[str, str] = {
    "bright_green": Fore.LIGHTGREEN_EX,
    "green":        Fore.GREEN,
    "yellow":       Fore.YELLOW,
    "red":          Fore.RED,
    "bright_red":   Fore.LIGHTRED_EX,
}


def _coloured(text: str, colour_key: str) -> str:
    return f"{_COLOUR_MAP.get(colour_key, '')}{text}{Style.RESET_ALL}"


def _bold(text: str) -> str:
    return f"{Style.BRIGHT}{text}{Style.RESET_ALL}"


def _dim(text: str) -> str:
    return f"{Style.DIM}{text}{Style.RESET_ALL}"


# ---------------------------------------------------------------------------
# Public rendering functions
# ---------------------------------------------------------------------------


def print_analysis(analysis: PasswordAnalysis, show_password: bool = False) -> None:
    _print_header(analysis, show_password)
    _print_score_panel(analysis)
    _print_criteria_table(analysis)
    if analysis.suggestions:
        _print_suggestions(analysis)
    print()


def print_analysis_json(analysis: PasswordAnalysis) -> None:
    data = criteria_summary(analysis)
    print(json.dumps(data, indent=2))


def print_banner() -> None:
    width = 60
    print()
    print(_coloured("╔" + "═" * width + "╗", "bright_green"))
    print(_coloured("║", "bright_green") + _bold("  PassCheck — Password Strength Analyser  ".center(width)) + _coloured("║", "bright_green"))
    print(_coloured("╚" + "═" * width + "╝", "bright_green"))
    print(_dim("  Type a password to analyse it, or 'quit'/'exit' to leave.\n"))


def print_separator() -> None:
    print(_dim("─" * 64))


# ---------------------------------------------------------------------------
# Private rendering helpers
# ---------------------------------------------------------------------------


def _print_header(analysis: PasswordAnalysis, show_password: bool) -> None:
    pw = analysis.password
    if show_password:
        masked = pw
    elif len(pw) <= 2:
        masked = "*" * len(pw)
    else:
        masked = pw[0] + "*" * (len(pw) - 2) + pw[-1]
    print(f"\n  {_bold('Password:')} {_dim(masked)}  {_dim(f'({len(pw)} chars)')}")


def _print_score_panel(analysis: PasswordAnalysis) -> None:
    color = analysis.strength_color
    score = analysis.score
    label = analysis.strength_label
    bar = score_bar(score, width=24)
    print()
    print(f"  {_coloured(bar, color)}  {_bold(_coloured(f'{score:>3}/100', color))}  {_bold(_coloured(f'[{label}]', color))}")
    print(_dim(f"  Entropy: {analysis.entropy_bits:.1f} bits   Criteria: {analysis.passed_count}/{analysis.total_criteria} passed"))
    print()


def _print_criteria_table(analysis: PasswordAnalysis) -> None:
    print(f"  {'':2}  {_bold('Criterion'):<26}  {_bold('Score'):>8}  {_dim('Detail')}")
    print(_dim("  " + "─" * 62))
    for c in analysis.criteria:
        icon = _coloured("✔", "green") if c.passed else _coloured("✘", "red")
        score_cell = _coloured(f"+{c.score}", "green") if c.passed else _dim(f"+0/{c.max_score}")
        name_col = c.name[:26].ljust(26)
        print(f"  {icon}   {name_col}  {score_cell}  {_dim(c.detail)}")
    print()


def _print_suggestions(analysis: PasswordAnalysis) -> None:
    print(f"  {_coloured(_bold('Suggestions'), 'yellow')}")
    for i, tip in enumerate(analysis.suggestions, 1):
        print(f"   {_coloured(str(i) + '.', 'yellow')} {tip}")
