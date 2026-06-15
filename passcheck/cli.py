from __future__ import annotations

import getpass
import json
import os
import sys
import threading
import time
import unicodedata
from collections.abc import Iterator
from enum import IntEnum

import click

from .analyzer import PasswordAnalyzer
from . import __version__
from .display import (
    print_analysis,
    print_analysis_json,
    print_banner,
    print_separator,
)
from .constants import LENGTH_MAXIMUM
from .models import PasswordAnalysis
from .utils import grapheme_len as _grapheme_len

# ---------------------------------------------------------------------------
# Shared analyser singleton
# ---------------------------------------------------------------------------

_analyzer:      PasswordAnalyzer | None = None
_analyzer_lock: threading.Lock = threading.Lock()

def _get_analyzer() -> PasswordAnalyzer:
    """Return the shared PasswordAnalyzer instance, constructing it lazily."""
    global _analyzer
    if _analyzer is None:
        with _analyzer_lock:
            if _analyzer is None:   # second check inside the lock
                _analyzer = PasswordAnalyzer()
    return _analyzer

def _set_analyzer(analyzer: PasswordAnalyzer) -> None:
    """Override the shared analyser instance (test suite only)."""
    if os.environ.get("PASSCHECK_TEST_MODE") != "1":
        raise RuntimeError(
            "_set_analyzer() is reserved for the test suite. "
            "Set the PASSCHECK_TEST_MODE=1 environment variable to enable it."
        )
    global _analyzer
    with _analyzer_lock:
        _analyzer = analyzer

# ---------------------------------------------------------------------------
# Exit codes
# ---------------------------------------------------------------------------

class _ExitCode(IntEnum):
    OK          = 0
    ERROR       = 1
    PARTIAL     = 2
    INTERRUPTED = 130  # POSIX convention: 128 + SIGINT(2)

# ---------------------------------------------------------------------------
# Internal exception for analysis failures  (DESIGN-06)
# ---------------------------------------------------------------------------

class _AnalysisError(Exception):
    """Raised by :func:`_run_analysis` when the analyser returns a ValueError."""

    def __init__(self, detail: str) -> None:
        self.detail = detail
        super().__init__(detail)

# ---------------------------------------------------------------------------
# Security helpers
# ---------------------------------------------------------------------------

_DEFAULT_INTERACTIVE_RATE_LIMIT_MS: float = 50.0

_INSECURE_FLAG_ENV_GATE: str = "PASSCHECK_ALLOW_INSECURE_FLAG"

_INSECURE_FLAG_WARNING: str = (
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
    click.echo(_INSECURE_FLAG_WARNING, err=True)

def _insecure_password_callback(
    ctx:   click.Context,
    param: click.Parameter,
    value: str | None,
) -> str | None:
    """Click ``is_eager`` callback that gates ``--password`` behind an env opt-in."""
    if value is None:
        return value

    _warn_insecure_flag()

    if os.environ.get(_INSECURE_FLAG_ENV_GATE) != "1":
        raise click.UsageError(
            "The --password flag is disabled by default for security reasons.\n"
            "Use --password-env <VAR> for safer scripting, or\n"
            "run 'passcheck' with no flags for the secure interactive prompt.\n"
            f"To acknowledge the risk and enable this flag, set:\n"
            f"      {_INSECURE_FLAG_ENV_GATE}=1"
        )

    return value

# ---------------------------------------------------------------------------
# JSON output helper
# ---------------------------------------------------------------------------

def _emit_json(obj: dict[str, object]) -> None:
    """Write *obj* as a single compact JSON line (NDJSON-compatible)."""
    print(json.dumps(obj))

# ---------------------------------------------------------------------------
# Shared NFC + length pre-check helper
# ---------------------------------------------------------------------------

class PasswordTooLongError(ValueError):
    """Raised by :func:`_nfc_and_check_length` when a password is too long to analyse."""

    def __init__(self, length: int) -> None:
        self.length = length
        super().__init__(
            f"Error: password exceeds the maximum analysable length "
            f"of {LENGTH_MAXIMUM} characters."
        )

def _nfc_and_check_length(pw: str) -> str:
    """Normalise *pw* to NFC, raising :class:`PasswordTooLongError` if too long."""
    pw = unicodedata.normalize("NFC", pw)
    length = _grapheme_len(pw)
    if length > LENGTH_MAXIMUM:
        raise PasswordTooLongError(length)
    return pw

def _report_length_error(exc: PasswordTooLongError, *, output_json: bool) -> None:
    """Report a :class:`PasswordTooLongError` using the standard error-event shape."""
    if output_json:
        _emit_json({"event": "error", "detail": str(exc)})
    else:
        click.echo(str(exc), err=True)

# ---------------------------------------------------------------------------
# CLI root
# ---------------------------------------------------------------------------

@click.group(
    invoke_without_command=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)
@click.version_option(__version__, "-V", "--version", prog_name="passcheck")
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
    is_eager=True,
    callback=_insecure_password_callback,
    expose_value=True,
    help=(
        "Password to analyse. "
        "INSECURE: exposes the password in your shell history AND in the OS process "
        "list (visible to all users via 'ps aux' before any Python code runs). "
        f"Requires {_INSECURE_FLAG_ENV_GATE}=1 to be set in the environment. "
        "Prefer --password-env for scripting, or omit both flags for the secure "
        "interactive prompt."
    ),
)
@click.option(
    "--password-env",
    "password_env",
    default=None,
    help=(
        "Name of an environment variable that holds the password to analyse. "
        "Safer than --password: environment variables are not visible in the OS "
        "process list. "
        "Example: PASSCHECK_PW=secret passcheck check --password-env PASSCHECK_PW"
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
        "Milliseconds to wait before each analysis (interactive and single-password modes). "
        f"(default: {_DEFAULT_INTERACTIVE_RATE_LIMIT_MS:.0f} ms). "
        "Set to 0 to disable throttling. "
        "For batch mode, use the 'batch' sub-command's own --rate-limit option."
    ),
)
def check(
    password:      str | None,
    password_env:  str | None,
    output_json:   bool,
    rate_limit_ms: float,
) -> None:
    """Analyse a single password."""
    if password is not None and password_env is not None:
        click.echo(
            "Error: --password and --password-env are mutually exclusive. "
            "Use --password-env <VAR> for safer scripting.",
            err=True,
        )
        raise SystemExit(_ExitCode.ERROR)

    # ── --password-env path ──────────────────────────────────────────────────
    if password_env is not None:
        pw = os.environ.get(password_env)
        if pw is None:
            click.echo(
                f"Error: environment variable {password_env!r} is not set.",
                err=True,
            )
            raise SystemExit(_ExitCode.ERROR)
        if pw == "":
            click.echo(
                f"Error: environment variable {password_env!r} is set but empty. "
                "Please assign a non-empty password value.",
                err=True,
            )
            raise SystemExit(_ExitCode.ERROR)
        try:
            pw = _nfc_and_check_length(pw)
        except PasswordTooLongError as exc:
            _report_length_error(exc, output_json=output_json)
            raise SystemExit(_ExitCode.ERROR) from exc
        if rate_limit_ms > 0:
            time.sleep(rate_limit_ms / 1000.0)
        try:
            _run_analysis(pw, output_json=output_json)
        except _AnalysisError as exc:
            if output_json:
                _emit_json({"event": "error", "detail": exc.detail})
            else:
                click.echo(f"Error: {exc.detail}", err=True)
            raise SystemExit(_ExitCode.ERROR)
        return

    # ── --password path ──────────────────────────────────────────────────────
    if password is not None:
        try:
            password = _nfc_and_check_length(password)
        except PasswordTooLongError as exc:
            _report_length_error(exc, output_json=output_json)
            raise SystemExit(_ExitCode.ERROR) from exc
        if rate_limit_ms > 0:
            time.sleep(rate_limit_ms / 1000.0)
        # DESIGN-06: same pattern as --password-env path above.
        try:
            _run_analysis(password, output_json=output_json)
        except _AnalysisError as exc:
            if output_json:
                _emit_json({"event": "error", "detail": exc.detail})
            else:
                click.echo(f"Error: {exc.detail}", err=True)
            raise SystemExit(_ExitCode.ERROR)

    # ── non-interactive stdin guard ──────────────────────────────────────────
    elif not sys.stdin.isatty():
        click.echo(
            "Error: 'passcheck check' requires interactive input.\n"
            "\n"
            "For piped or file-based input, use the 'batch' sub-command:\n"
            "  echo 'mypassword'  | passcheck batch\n"
            "  cat passwords.txt  | passcheck batch\n"
            "  passcheck batch    < passwords.txt\n"
            "\n"
            "Alternatively, run 'passcheck' with no sub-command, it\n"
            "auto-selects batch mode when stdin is not a terminal.",
            err=True,
        )
        raise SystemExit(_ExitCode.ERROR)

    # ── interactive fallback ─────────────────────────────────────────────────
    else:
        _interactive_loop(
            output_json=output_json,
            rate_limit_s=rate_limit_ms / 1000.0,
        )

@cli.command()
@click.pass_context
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
def batch(ctx: click.Context, output_json: bool, rate_limit_ms: float) -> None:
    """Analyse multiple passwords from stdin (one per line)."""
    if sys.stdin.isatty():
        click.echo(
            "Error: 'batch' reads passwords from stdin but no piped input was detected.\n"
            "Usage example:  echo 'mypassword' | passcheck batch\n"
            "             :  cat passwords.txt | passcheck batch",
            err=True,
        )
        raise SystemExit(_ExitCode.ERROR)

    _explicitly_invoked = (
        ctx.parent is not None
        and ctx.parent.invoked_subcommand == "batch"
    )
    if rate_limit_ms == 0.0 and not output_json and _explicitly_invoked:
        click.echo(
            "Note: rate limiting is disabled. "
            "Use --rate-limit N to throttle batch analysis (e.g. --rate-limit 100 "
            "for a maximum of 10 analyses/second).",
            err=True,
        )

    _run_batch(output_json=output_json, rate_limit_s=rate_limit_ms / 1000.0)

# ---------------------------------------------------------------------------
# Batch helper
# ---------------------------------------------------------------------------

def _warn_invalid_password(
    pw: str,
    *,
    output_json: bool,
    reason: str,
    line_num: int = 0,
) -> None:
    """Emit a per-line warning for a password that was skipped in batch mode."""
    glen = _grapheme_len(pw)
    if output_json:
        _emit_json({
            "event":  "skipped_invalid",
            "line":   line_num,
            "length": glen,
            "limit":  LENGTH_MAXIMUM,
            "detail": reason,
        })
    else:
        loc = f"line {line_num}: " if line_num else ""
        click.echo(f"Warning: {loc}{reason}", err=True)

def _run_batch(*, output_json: bool, rate_limit_s: float = 0.0) -> None:
    """Stream analysis results for all passwords arriving on stdin."""
    found_any     = False
    need_sep      = False
    line_num      = 0
    failure_count = 0

    try:
        for pw in _stdin_passwords(output_json=output_json):
            line_num  += 1
            found_any  = True
            if not output_json and need_sep:
                print_separator()
            need_sep = True
            try:
                pw = _nfc_and_check_length(pw)
            except PasswordTooLongError as exc:
                _warn_invalid_password(
                    pw, output_json=output_json, reason=str(exc), line_num=line_num,
                )
                failure_count += 1
                continue

            if rate_limit_s > 0:
                time.sleep(rate_limit_s)
            try:
                _run_analysis(pw, output_json=output_json)
            except _AnalysisError as exc:
                reason = exc.detail or (
                    f"Password of length {_grapheme_len(pw)} could not be "
                    "analysed and was skipped."
                )
                _warn_invalid_password(
                    pw, output_json=output_json, reason=reason, line_num=line_num,
                )
                failure_count += 1

    except KeyboardInterrupt:
        click.echo("\nInterrupted.", err=True)
        raise SystemExit(_ExitCode.INTERRUPTED)

    if not found_any:
        click.echo("Error: No passwords received on stdin.", err=True)
        raise SystemExit(_ExitCode.ERROR)

    if failure_count > 0:
        raise SystemExit(_ExitCode.PARTIAL)

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
    return _get_analyzer().analyze(password)

def _run_analysis(password: str, *, output_json: bool) -> None:
    """Analyse *password* and dispatch to the appropriate renderer."""
    try:
        analysis = _analyze(password)
    except ValueError as exc:
        raise _AnalysisError(str(exc)) from exc
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

        try:
            pw = _nfc_and_check_length(pw)
        except PasswordTooLongError as exc:
            _report_length_error(exc, output_json=output_json)
            if not output_json:
                print()
            continue

        if rate_limit_s > 0:
            time.sleep(rate_limit_s)

        try:
            _run_analysis(pw, output_json=output_json)
        except _AnalysisError as exc:
            if output_json:
                _emit_json({"event": "error", "detail": exc.detail})
            else:
                click.echo(f"  Error: {exc.detail}\n", err=True)
            continue

        if not output_json:
            print_separator()

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """Entry point registered in ``pyproject.toml``."""
    cli()