"""The `passcheck check` command — analyse a single password."""
from __future__ import annotations

import os
import sys
import time

import click

from .app import cli
from .errors import AnalysisError, PasswordTooLongError
from .exit_codes import ExitCode
from .helpers import emit_json, nfc_and_check_length, report_length_error, run_analysis
from .interactive import interactive_loop
from .security import (
    DEFAULT_INTERACTIVE_RATE_LIMIT_MS,
    INSECURE_FLAG_ENV_GATE,
    insecure_password_callback,
)

__all__ = ["check"]

@cli.command()
@click.option(
    "-p", "--password",
    default=None,
    is_eager=True,
    callback=insecure_password_callback,
    expose_value=True,
    help=(
        "Password to analyse. "
        "INSECURE: exposes the password in your shell history AND in the OS process "
        "list (visible to all users via 'ps aux' before any Python code runs). "
        f"Requires {INSECURE_FLAG_ENV_GATE}=1 to be set in the environment. "
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
        "Safer than --password: the value is not in the OS process argument vector. "
        "Note: the variable value is still visible in /proc/<pid>/environ on Linux "
        "(readable by the process owner and root). "
        "Avoid inline assignment (VAR=secret passcheck ...) — most shells record "
        "that form in history. "
        "For highest security, use the interactive prompt (no flags)."
    ),
)
@click.option(
    "--json", "output_json",
    is_flag=True,
    default=False,
    help="Output results as JSON.",
)
@click.option(
    "--redact",
    "redact_password",
    is_flag=True,
    default=False,
    help=(
        "Replace the password's masked form with '[REDACTED]' in all output. "
        "Recommended whenever output may be logged, forwarded, or stored: "
        "even the masked form (first character, last character, exact length) "
        "constitutes a partial credential disclosure that persists in logs. "
        "(SA-M04)"
    ),
)
@click.option(
    "--rate-limit", "rate_limit_ms",
    type=float,
    default=DEFAULT_INTERACTIVE_RATE_LIMIT_MS,
    show_default=True,
    help=(
        "Milliseconds to wait before each analysis (interactive and single-password modes). "
        f"(default: {DEFAULT_INTERACTIVE_RATE_LIMIT_MS:.0f} ms). "
        "Set to 0 to disable throttling. "
        "For batch mode, use the 'batch' sub-command's own --rate-limit option."
    ),
)
def check(
    password:        str | None,
    password_env:    str | None,
    output_json:     bool,
    redact_password: bool,
    rate_limit_ms:   float,
) -> None:
    """Analyse a single password."""
    if password is not None and password_env is not None:
        click.echo(
            "Error: --password and --password-env are mutually exclusive. "
            "Use --password-env <VAR> for safer scripting.",
            err=True,
        )
        raise SystemExit(ExitCode.ERROR)

    # ── --password-env path ──────────────────────────────────────────────────
    if password_env is not None:
        pw = os.environ.get(password_env)
        if pw is None:
            click.echo(
                f"Error: environment variable {password_env!r} is not set.",
                err=True,
            )
            raise SystemExit(ExitCode.ERROR)
        if pw == "":
            click.echo(
                f"Error: environment variable {password_env!r} is set but empty. "
                "Please assign a non-empty password value.",
                err=True,
            )
            raise SystemExit(ExitCode.ERROR)
        try:
            pw = nfc_and_check_length(pw)
        except PasswordTooLongError as exc:
            report_length_error(exc, output_json=output_json)
            raise SystemExit(ExitCode.ERROR) from exc
        if rate_limit_ms > 0:
            time.sleep(rate_limit_ms / 1000.0)
        try:
            run_analysis(pw, output_json=output_json, redact=redact_password)
        except AnalysisError as exc:
            if output_json:
                emit_json({"event": "error", "detail": exc.detail})
            else:
                click.echo(f"Error: {exc.detail}", err=True)
            raise SystemExit(ExitCode.ERROR)
        return

    # ── --password path ──────────────────────────────────────────────────────
    if password is not None:
        if password == "":
            click.echo(
                "Error: --password was given an empty value. "
                "Please provide a non-empty password.",
                err=True,
            )
            raise SystemExit(ExitCode.ERROR)
        try:
            password = nfc_and_check_length(password)
        except PasswordTooLongError as exc:
            report_length_error(exc, output_json=output_json)
            raise SystemExit(ExitCode.ERROR) from exc
        if rate_limit_ms > 0:
            time.sleep(rate_limit_ms / 1000.0)
        try:
            run_analysis(password, output_json=output_json, redact=redact_password)
        except AnalysisError as exc:
            if output_json:
                emit_json({"event": "error", "detail": exc.detail})
            else:
                click.echo(f"Error: {exc.detail}", err=True)
            raise SystemExit(ExitCode.ERROR)

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
        raise SystemExit(ExitCode.ERROR)

    # ── interactive fallback ─────────────────────────────────────────────────
    else:
        interactive_loop(
            output_json=output_json,
            rate_limit_s=rate_limit_ms / 1000.0,
            redact=redact_password,
        )