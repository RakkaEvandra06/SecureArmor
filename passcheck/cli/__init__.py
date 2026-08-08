"""Click-based CLI for PassCheck.

This used to be a single 565-line ``cli.py``. It is now a package split by
*responsibility* (Single Responsibility Principle):

    app.py                 — root Click group + main() entry point
    exit_codes.py            — ExitCode enum
    errors.py                  — AnalysisError, PasswordTooLongError
    security.py                  — the --password insecure-flag gate
    analyzer_singleton.py          — shared PasswordAnalyzer instance
    helpers.py                       — JSON output, NFC/length check, run-one-analysis
    check_command.py                   — `passcheck check`
    batch_command.py                     — `passcheck batch`
    interactive.py                         — the interactive prompt loop

Every file stays well under the ~400-line point where AI coding agents lose
indexing accuracy.

Import order matters here: importing check_command / batch_command has the
side effect of registering those commands onto the ``cli`` group defined in
app.py (via their ``@cli.command()`` decorators), so app must be imported
first.

This module also re-exports the *original* (pre-refactor) names — including
the underscore-prefixed "private" ones — so any existing code or tests doing
``from passcheck.cli import _run_batch`` (etc.) keep working unchanged. New
code should prefer the un-prefixed names (``run_batch``-style helpers live
on their owning submodule).
"""
from __future__ import annotations

from .analyzer_singleton import get_analyzer as _get_analyzer  # noqa: F401  (intentional backward-compat re-export)
from .analyzer_singleton import set_analyzer as _set_analyzer  # noqa: F401  (intentional backward-compat re-export)
from .app import cli, main  # noqa: F401  (intentional backward-compat re-export)
from .batch_command import _MAX_LINE_BYTES, _run_batch, _stdin_passwords, _warn_invalid_password  # noqa: F401  (intentional backward-compat re-export)
from .batch_command import batch  # noqa: F401  (intentional backward-compat re-export)
from .check_command import check  # noqa: F401  (intentional backward-compat re-export)
from .errors import AnalysisError as _AnalysisError  # noqa: F401  (intentional backward-compat re-export)
from .errors import PasswordTooLongError  # noqa: F401  (intentional backward-compat re-export)
from .exit_codes import ExitCode as _ExitCode  # noqa: F401  (intentional backward-compat re-export)
from .helpers import analyze as _analyze  # noqa: F401  (intentional backward-compat re-export)
from .helpers import emit_json as _emit_json  # noqa: F401  (intentional backward-compat re-export)
from .helpers import nfc_and_check_length as _nfc_and_check_length  # noqa: F401  (intentional backward-compat re-export)
from .helpers import report_length_error as _report_length_error  # noqa: F401  (intentional backward-compat re-export)
from .helpers import run_analysis as _run_analysis  # noqa: F401  (intentional backward-compat re-export)
from .interactive import interactive_loop as _interactive_loop  # noqa: F401  (intentional backward-compat re-export)
from .security import DEFAULT_INTERACTIVE_RATE_LIMIT_MS as _DEFAULT_INTERACTIVE_RATE_LIMIT_MS  # noqa: F401  (intentional backward-compat re-export)
from .security import INSECURE_FLAG_ENV_GATE as _INSECURE_FLAG_ENV_GATE  # noqa: F401  (intentional backward-compat re-export)
from .security import insecure_password_callback as _insecure_password_callback  # noqa: F401  (intentional backward-compat re-export)

__all__ = ["cli", "main", "check", "batch"]
