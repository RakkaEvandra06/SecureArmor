from __future__ import annotations

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

# Module-level analyser — stateless, so a single shared instance is safe.
_analyzer = PasswordAnalyzer()

# ---------------------------------------------------------------------------
# Exit codes
# ---------------------------------------------------------------------------

class _ExitCode(IntEnum):
    OK    = 0
    ERROR = 1

# ---------------------------------------------------------------------------
# Security helpers
# ---------------------------------------------------------------------------

def _warn_insecure_flag() -> None:
    """Emit a warning to stderr whenever ``--password`` is used directly."""
    click.echo(
        "Warning: Passing a password via --password exposes it in your shell "
        "history AND in the process list (visible to all users via 'ps aux' or "
        "'/proc/<pid>/cmdline'). Use the interactive prompt instead for secure "
        "input.\n",
        err=True,
    )

def _scrub_argv_password() -> None:
    """Overwrite the password value in ``sys.argv`` with ``***``."""
    argv = sys.argv
    for i, arg in enumerate(argv):
        if arg in ("--password", "-p") and i + 1 < len(argv):
            argv[i + 1] = "***"
            return
        if arg.startswith("--password="):
            argv[i] = "--password=***"
            return

# ---------------------------------------------------------------------------
# JSON output helper
# ---------------------------------------------------------------------------

def _emit_json(obj: dict[str, object]) -> None:
    """Write *obj* as a single compact JSON line (NDJSON-compatible)."""
    print(json.dumps(obj))

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
    help=(
        "Password to analyse. "
        "WARNING: exposes the password in your shell history AND in the process "
        "list (visible to all users via 'ps aux'). "
        "Use the interactive prompt for secure input."
    ),
)
@click.option(
    "--json", "output_json",
    is_flag=True,
    default=False,
    help="Output results as JSON.",
)
def check(password: str | None, output_json: bool) -> None:
    """Analyse a single password."""
    if password is not None:
        _warn_insecure_flag()
        # Scrub sys.argv as early as possible to close the process-list window.
        _scrub_argv_password()
        _run_analysis(password, output_json=output_json)
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
        _interactive_loop(output_json=output_json)

@cli.command()
@click.option(
    "--json", "output_json",
    is_flag=True,
    default=False,
    help="Output results as JSON.",
)
def batch(output_json: bool) -> None:
    """Analyse multiple passwords from stdin (one per line)."""
    if sys.stdin.isatty():
        click.echo(
            "Error: 'batch' reads passwords from stdin but no piped input was detected.\n"
            "Usage example:  echo 'mypassword' | passcheck batch\n"
            "             :  cat passwords.txt | passcheck batch",
            err=True,
        )
        raise SystemExit(_ExitCode.ERROR)

    _run_batch(output_json=output_json)

# ---------------------------------------------------------------------------
# Batch helper
# ---------------------------------------------------------------------------

def _run_batch(*, output_json: bool) -> None:
    """Stream analysis results for all passwords arriving on stdin."""
    found_any = False
    first     = True

    try:
        for pw in _stdin_passwords(output_json=output_json):
            found_any = True
            if not output_json and not first:
                print_separator()
            _run_analysis(pw, output_json=output_json)
            first = False
    except KeyboardInterrupt:
        click.echo("\nInterrupted.", err=True)
        raise SystemExit(_ExitCode.OK)

    if not found_any:
        click.echo("Error: No passwords received on stdin.", err=True)
        raise SystemExit(_ExitCode.ERROR)

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _stdin_passwords(*, output_json: bool = False) -> Iterator[str]:
    """Yield non-blank passwords from stdin, one per line."""
    for raw_line in sys.stdin.buffer:
        try:
            line = raw_line.decode("utf-8")
        except UnicodeDecodeError:
            if output_json:
                _emit_json({
                    "event":  "decode_error",
                    "detail": "A line could not be decoded as UTF-8 and was skipped.",
                })
            else:
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

def _run_analysis(password: str, *, output_json: bool) -> None:
    """Analyse *password* and dispatch to the appropriate renderer."""
    analysis = _analyze(password)
    if output_json:
        print_analysis_json(analysis)
    else:
        print_analysis(analysis)
        print()  # trailing blank line is owned here, not inside print_analysis

def _interactive_loop(*, output_json: bool) -> None:
    """Run the interactive prompt loop until the user quits."""
    import getpass

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

        if not pw:
            if output_json:
                _emit_json({"event": "empty_input"})
            else:
                print("  Please enter a non-empty password.\n")
            continue

        _run_analysis(pw, output_json=output_json)

        if not output_json:
            print_separator()

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """Entry point registered in ``pyproject.toml``."""
    cli()