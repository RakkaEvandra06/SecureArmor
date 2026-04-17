from __future__ import annotations

import getpass
import json
import sys
from collections.abc import Iterator
from enum import IntEnum

import click

from .analyzer import PasswordAnalyzer
from .display import (
    print_analysis,
    print_analysis_json,
    print_banner,
    print_separator,
)
from .models import PasswordAnalysis
from .scoring import criteria_summary

# Module-level analyzer — stateless, so sharing one instance is safe.
_analyzer = PasswordAnalyzer()

# ---------------------------------------------------------------------------
# Exit codes
# ---------------------------------------------------------------------------

class _ExitCode(IntEnum):
    OK    = 0
    ERROR = 1

# ---------------------------------------------------------------------------
# CLI root
# ---------------------------------------------------------------------------

@click.group(
    invoke_without_command=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)
@click.pass_context
def cli(ctx: click.Context) -> None:
    """PassCheck — Password Strength Analyser."""
    if ctx.invoked_subcommand is None:
        ctx.invoke(check)

# ---------------------------------------------------------------------------
# Sub-commands
# ---------------------------------------------------------------------------

@cli.command()
@click.option(
    "-p", "--password",
    default=None,
    help="Password to analyse. Warning: visible in shell history.",
)
@click.option(
    "--show-password",
    is_flag=True,
    default=False,
    help="Show the password (partially masked) in output.",
)
@click.option(
    "--json", "output_json",
    is_flag=True,
    default=False,
    help="Output results as JSON.",
)
def check(password: str | None, show_password: bool, output_json: bool) -> None:
    """Analyse a single password."""
    if password is not None:
        _warn_insecure_flag()
        _run_analysis(password, show_password=show_password, output_json=output_json)
    elif not sys.stdin.isatty():
        click.echo(
            "Error: stdin is not a TTY. Did you mean to use 'passcheck batch'?\n"
            "Usage examples:\n"
            "  echo 'mypassword' | passcheck batch\n"
            "  cat passwords.txt  | passcheck batch",
            err=True,
        )
        raise SystemExit(_ExitCode.ERROR)
    else:
        _interactive_loop(show_password=show_password, output_json=output_json)

@cli.command()
@click.option(
    "--show-password",
    is_flag=True,
    default=False,
    help="Show the password (partially masked) in output.",
)
@click.option(
    "--json", "output_json",
    is_flag=True,
    default=False,
    help="Output results as JSON.",
)
def batch(show_password: bool, output_json: bool) -> None:
    """Analyse multiple passwords from stdin (one per line)."""
    if sys.stdin.isatty():
        click.echo(
            "Error: 'batch' reads passwords from stdin but no piped input was detected.\n"
            "Usage example:  echo 'mypassword' | passcheck batch\n"
            "             :  cat passwords.txt | passcheck batch",
            err=True,
        )
        raise SystemExit(_ExitCode.ERROR)

    if output_json:
        _batch_json()
    else:
        _batch_text(show_password=show_password)

# ---------------------------------------------------------------------------
# Batch mode helpers
# ---------------------------------------------------------------------------

def _batch_json() -> None:
    """Stream one JSON object per line (NDJSON) to stdout."""
    found_any = False

    for pw in _stdin_passwords():
        found_any = True
        result = criteria_summary(_analyze(pw))
        # json.dumps never produces a newline inside a single-object dump, so
        # the '\n' terminator is the only record separator needed.
        print(json.dumps(result))

    if not found_any:
        click.echo("Error: No passwords received on stdin.", err=True)
        raise SystemExit(_ExitCode.ERROR)

def _batch_text(*, show_password: bool) -> None:
    """Stream human-readable analysis blocks to stdout, one per password."""
    found_any = False
    first     = True

    for pw in _stdin_passwords():
        found_any = True
        # Print a separator *before* every entry except the first, so no
        # trailing separator is emitted after the last password.
        if not first:
            print_separator()
        _run_analysis(pw, show_password=show_password, output_json=False)
        first = False

    if not found_any:
        click.echo("Error: No passwords received on stdin.", err=True)
        raise SystemExit(_ExitCode.ERROR)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _stdin_passwords() -> Iterator[str]:
    """Yield non-blank passwords from stdin one line at a time."""
    for raw_line in sys.stdin.buffer:
        try:
            line = raw_line.decode("utf-8")
        except UnicodeDecodeError:
            click.echo(
                "Warning: skipped a line that could not be decoded as UTF-8.",
                err=True,
            )
            continue
        pw = line.rstrip("\r\n")
        if pw:
            yield pw

def _analyze(password: str) -> PasswordAnalysis:
    """Run the analyser and return the result, or exit with an error message."""
    try:
        return _analyzer.analyze(password)
    except ValueError as exc:
        click.echo(f"Error: {exc}", err=True)
        raise SystemExit(_ExitCode.ERROR) from exc

def _run_analysis(password: str, *, show_password: bool, output_json: bool) -> None:
    """Analyse *password* and dispatch to the appropriate renderer."""
    analysis = _analyze(password)

    if output_json:
        print_analysis_json(analysis)
    else:
        print_analysis(analysis, show_password=show_password)

def _interactive_loop(*, show_password: bool, output_json: bool) -> None:
    """Run the interactive prompt loop until the user quits."""
    if not output_json:
        print_banner()

    while True:
        try:
            prompt = "" if output_json else "  Enter password: "
            pw = getpass.getpass(prompt)
        except (KeyboardInterrupt, EOFError):
            if not output_json:
                print("\n  Goodbye!\n")
            raise SystemExit(_ExitCode.OK)

        if pw.lower() in {"quit", "exit", "q"}:
            if output_json:
                # Emit a structured sentinel so JSON consumers can detect a
                # clean exit rather than treating the EOF as an error.
                print(json.dumps({"event": "exit"}))
            else:
                print("\n  Goodbye!\n")
            break

        if not pw:
            if output_json:
                print(json.dumps({"event": "empty_input"}))
            else:
                print("  Please enter a non-empty password.\n")
            continue

        _run_analysis(pw, show_password=show_password, output_json=output_json)

        if not output_json:
            print_separator()

def _warn_insecure_flag() -> None:
    """Emit a one-time warning to stderr when --password is used directly."""
    click.echo(
        "Warning: Passing a password via --password may expose it in your "
        "shell history. Consider using the interactive prompt instead.\n",
        err=True,
    )

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    cli()