"""Interactive prompt loop used when passcheck is run with no piped
input and no --password / --password-env flag."""
from __future__ import annotations

import getpass
import time

import click

from ..display import print_banner, print_separator
from .errors import AnalysisError, PasswordTooLongError
from .exit_codes import ExitCode
from .helpers import emit_json, nfc_and_check_length, report_length_error, run_analysis
from .security import DEFAULT_INTERACTIVE_RATE_LIMIT_MS

__all__ = ["interactive_loop"]

def interactive_loop(
    *,
    output_json:  bool,
    rate_limit_s: float = DEFAULT_INTERACTIVE_RATE_LIMIT_MS / 1000.0,
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
            raise SystemExit(ExitCode.OK)

        if not pw:
            if output_json:
                emit_json({"event": "empty_input"})
            else:
                print("  Please enter a non-empty password.\n")
            continue

        try:
            pw = nfc_and_check_length(pw)
        except PasswordTooLongError as exc:
            report_length_error(exc, output_json=output_json)
            if not output_json:
                print()
            continue

        if rate_limit_s > 0:
            time.sleep(rate_limit_s)

        try:
            run_analysis(pw, output_json=output_json)
        except AnalysisError as exc:
            if output_json:
                emit_json({"event": "error", "detail": exc.detail})
            else:
                click.echo(f"  Error: {exc.detail}\n", err=True)
            continue

        if not output_json:
            print_separator()
