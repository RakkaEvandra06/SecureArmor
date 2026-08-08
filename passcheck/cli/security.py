"""Security gate for the insecure --password flag.

Click callback + warning message that requires an explicit environment
opt-in before --password (which leaks via shell history and the OS
process list) can be used at all.
"""
from __future__ import annotations

import os

import click

from .exit_codes import ExitCode

__all__ = [
    "DEFAULT_INTERACTIVE_RATE_LIMIT_MS",
    "INSECURE_FLAG_ENV_GATE",
    "insecure_password_callback",
]

DEFAULT_INTERACTIVE_RATE_LIMIT_MS: float = 50.0

INSECURE_FLAG_ENV_GATE: str = "PASSCHECK_ALLOW_INSECURE_FLAG"

INSECURE_FLAG_WARNING: str = (
    "WARNING: The --password flag is inherently insecure.\n"
    "  • Your shell records the value in its history file.\n"
    "  • Every major OS exposes process command-line arguments before any\n"
    "    Python code runs — they are visible to other users and monitoring\n"
    "    tools (Task Manager, Activity Monitor, ps, /proc/<pid>/cmdline …).\n"
    "Use --password-env <VAR> for safer scripting, or run 'passcheck' with\n"
    "no flags for the secure interactive prompt.\n"
)

def _warn_insecure_flag() -> None:
    """Emit a warning to stderr whenever ``--password`` is used directly."""
    click.echo(INSECURE_FLAG_WARNING, err=True)

def insecure_password_callback(
    ctx:   click.Context,
    param: click.Parameter,
    value: str | None,
) -> str | None:
    """Click ``is_eager`` callback that gates ``--password`` behind an env opt-in."""
    if value is None:
        return value

    _warn_insecure_flag()

    if os.environ.get(INSECURE_FLAG_ENV_GATE) != "1":
        click.echo(
            "Error: The --password flag is disabled by default for security reasons.\n"
            "Use --password-env <VAR> for safer scripting, or\n"
            "run 'passcheck' with no flags for the secure interactive prompt.\n"
            "To acknowledge the risk and enable this flag, set:\n"
            f"      {INSECURE_FLAG_ENV_GATE}=1",
            err=True,
        )
        raise SystemExit(ExitCode.ERROR)

    return value
