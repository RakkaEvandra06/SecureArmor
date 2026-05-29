from __future__ import annotations

import getpass
import json
import sys
import time
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
from .constants import LENGTH_MAXIMUM
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

_DEFAULT_INTERACTIVE_RATE_LIMIT_MS: float = 50.0

_INSECURE_FLAG_WARNING: str = (
    "WARNING: The --password flag is inherently insecure.\n"
    "  • Your shell records the value in its history file.\n"
    "  • The OS writes the full command line to /proc/<pid>/cmdline before\n"
    "    any Python code runs in-process scrubbing cannot undo this.\n"
    "  • Other users can read it via 'ps aux' during process execution.\n"
    "Use the interactive prompt (run 'passcheck' with no flags) for secure input.\n"
)

def _warn_insecure_flag() -> None:
    """Emit a warning to stderr whenever ``--password`` is used directly."""
    click.echo(_INSECURE_FLAG_WARNING, err=True)

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
        if not sys.stdin.isatty():
            ctx.invoke(batch)
        else:
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
@click.option(
    "--rate-limit", "rate_limit_ms",
    type=float,
    default=_DEFAULT_INTERACTIVE_RATE_LIMIT_MS,
    show_default=True,
    help=(
        "Milliseconds to wait between analyses in interactive mode "
        f"(default: {_DEFAULT_INTERACTIVE_RATE_LIMIT_MS:.0f} ms). "
        "Set to 0 to disable throttling."
    ),
)
def check(
    password:      str | None,
    output_json:   bool,
    rate_limit_ms: float,
) -> None:
    """Analyse a single password."""
    if password is not None:
        _warn_insecure_flag()
        _run_analysis(password, output_json=output_json)
    elif not sys.stdin.isatty():
        click.echo(
            "Error: stdin is not a TTY. Did you mean to use 'passcheck batch'?\n"
            "Usage examples:\n"
            "  echo 'mypassword'  | passcheck batch\n"
            "  cat passwords.txt  | passcheck batch",
            err=True,
        )
        raise SystemExit(_ExitCode.ERROR)
    else:
        _interactive_loop(
            output_json=output_json,
            rate_limit_s=rate_limit_ms / 1000.0,
        )

@cli.command()
@click.option(
    "--json", "output_json",
    is_flag=True,
    default=False,
    help="Output results as JSON.",
)
@click.option(
    "--rate-limit", "rate_limit_ms",
    type=float,
    default=0.0,
    show_default=True,
    help=(
        "Minimum milliseconds to wait between analyses in batch mode "
        "(default: 0 = unlimited). "
        "Example: --rate-limit=100 limits throughput to 10 analyses/second."
    ),
)
def batch(output_json: bool, rate_limit_ms: float) -> None:
    """Analyse multiple passwords from stdin (one per line)."""
    if sys.stdin.isatty():
        click.echo(
            "Error: 'batch' reads passwords from stdin but no piped input was detected.\n"
            "Usage example:  echo 'mypassword' | passcheck batch\n"
            "             :  cat passwords.txt | passcheck batch",
            err=True,
        )
        raise SystemExit(_ExitCode.ERROR)

    _run_batch(output_json=output_json, rate_limit_s=rate_limit_ms / 1000.0)

# ---------------------------------------------------------------------------
# Batch helper
# ---------------------------------------------------------------------------

def _warn_invalid_password(
    pw: str,
    *,
    output_json: bool,
    exc: SystemExit | None = None,
) -> None:
    """Emit a per-line warning for passwords that could not be analysed."""
    reason: str = ""
    if exc is not None and isinstance(exc.__cause__, ValueError) and exc.__cause__.args:
        reason = str(exc.__cause__.args[0])
    if not reason:
        reason = (
            f"Password of length {len(pw)} could not be analysed and was skipped."
        )
    if output_json:
        _emit_json({
            "event":  "skipped_invalid",
            "length": len(pw),
            "limit":  LENGTH_MAXIMUM,
            "detail": reason,
        })
    else:
        click.echo(f"Warning: skipped password {reason}", err=True)


def _run_batch(*, output_json: bool, rate_limit_s: float = 0.0) -> None:
    """Stream analysis results for all passwords arriving on stdin."""
    found_any = False
    need_sep  = False
    try:
        for pw in _stdin_passwords(output_json=output_json):
            found_any = True
            if not output_json and need_sep:
                print_separator()
            need_sep = True
            try:
                _run_analysis(pw, output_json=output_json)
            except SystemExit as exc:
                _warn_invalid_password(pw, output_json=output_json, exc=exc)
            if rate_limit_s > 0:
                time.sleep(rate_limit_s)
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
    """Run the analyser and return the result; propagate ValueError to the caller."""
    return _analyzer.analyze(password)

def _run_analysis(password: str, *, output_json: bool) -> None:
    """Analyse *password* and dispatch to the appropriate renderer."""
    try:
        analysis = _analyze(password)
    except ValueError as exc:
        if output_json:
            _emit_json({"event": "error", "detail": str(exc)})
        else:
            click.echo(f"Error: {exc}", err=True)
        raise SystemExit(_ExitCode.ERROR) from exc
    if output_json:
        print_analysis_json(analysis)
    else:
        print_analysis(analysis)
        print()  # trailing blank line is owned here, not inside print_analysis

def _interactive_loop(
    *,
    output_json:  bool,
    rate_limit_s: float = _DEFAULT_INTERACTIVE_RATE_LIMIT_MS / 1000.0,
) -> None:
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

        if not pw:
            if output_json:
                _emit_json({"event": "empty_input"})
            else:
                print("  Please enter a non-empty password.\n")
            continue

        if rate_limit_s > 0:
            time.sleep(rate_limit_s)

        _run_analysis(pw, output_json=output_json)

        if not output_json:
            print_separator()

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """Entry point registered in ``pyproject.toml``."""
    cli()