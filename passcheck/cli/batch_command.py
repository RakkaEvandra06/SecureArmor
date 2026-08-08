"""The `passcheck batch` command — analyse many passwords from stdin."""
from __future__ import annotations

import sys
import time
from collections.abc import Iterator

import click

from ..constants import LENGTH_MAXIMUM
from ..display import print_separator
from ..utils import grapheme_len as _grapheme_len
from .app import cli
from .errors import AnalysisError, PasswordTooLongError
from .exit_codes import ExitCode
from .helpers import emit_json, nfc_and_check_length, run_analysis

__all__ = ["batch"]

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
        raise SystemExit(ExitCode.ERROR)

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
    glen = _grapheme_len(pw) if pw else None
    if output_json:
        payload: dict[str, object] = {
            "event":  "skipped_invalid",
            "line":   line_num,
            "detail": reason,
        }
        if glen is not None:
            payload["length"] = glen
            payload["limit"]  = LENGTH_MAXIMUM
        emit_json(payload)
    else:
        loc = f"line {line_num}: " if line_num else ""
        click.echo(f"Warning: {loc}{reason}", err=True)

def _run_batch(*, output_json: bool, rate_limit_s: float = 0.0) -> None:
    """Stream analysis results for all passwords arriving on stdin."""
    found_any     = False
    need_sep      = False
    failure_count = 0

    try:
        for line_num, pw, skip_reason in _stdin_passwords(output_json=output_json):
            found_any = True

            if pw is None:
                # The line never produced a candidate password (oversized or
                # undecodable) — still counts as a failure for exit-code
                # purposes, and is reported against its real file line number.
                _warn_invalid_password(
                    "", output_json=output_json, reason=skip_reason, line_num=line_num,
                )
                failure_count += 1
                continue

            if not output_json and need_sep:
                print_separator()
            need_sep = True
            try:
                pw = nfc_and_check_length(pw)
            except PasswordTooLongError as exc:
                _warn_invalid_password(
                    pw, output_json=output_json, reason=str(exc), line_num=line_num,
                )
                failure_count += 1
                continue

            if rate_limit_s > 0:
                time.sleep(rate_limit_s)
            try:
                run_analysis(pw, output_json=output_json)
            except AnalysisError as exc:
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
        raise SystemExit(ExitCode.INTERRUPTED)

    if not found_any:
        click.echo("Error: No passwords received on stdin.", err=True)
        raise SystemExit(ExitCode.ERROR)

    if failure_count > 0:
        raise SystemExit(ExitCode.PARTIAL)

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_MAX_LINE_BYTES: int = 8192

def _stdin_passwords(
    *, output_json: bool = False,
) -> Iterator[tuple[int, str | None, str | None]]:
    """Yield ``(line_num, password, skip_reason)`` tuples from stdin, one per raw line."""
    buf = sys.stdin.buffer
    line_num = 0
    while True:
        raw_line = buf.readline(_MAX_LINE_BYTES + 1)
        if not raw_line:
            return  # EOF
        line_num += 1

        if len(raw_line) > _MAX_LINE_BYTES and not raw_line.endswith(b"\n"):
            # Oversized: drain and discard the remainder of this line so its
            # tail isn't mistaken for a separate password on the next read.
            while True:
                rest = buf.readline(_MAX_LINE_BYTES)
                if not rest or rest.endswith(b"\n"):
                    break
            yield (
                line_num,
                None,
                f"line exceeded the {_MAX_LINE_BYTES}-byte read limit and was skipped",
            )
            continue

        try:
            line = raw_line.decode("utf-8")
        except UnicodeDecodeError:
            yield (line_num, None, "line could not be decoded as UTF-8 and was skipped")
            continue

        pw = line.rstrip("\r\n")
        if pw:
            yield (line_num, pw, None)
        # blank lines: fall through silently; line_num has already advanced.
