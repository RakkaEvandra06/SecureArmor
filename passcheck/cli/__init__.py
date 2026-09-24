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

Import order matters here: importing check_command / batch_command has the
side effect of registering those commands onto the ``cli`` group defined in
app.py (via their ``@cli.command()`` decorators), so app must be imported
first.

Backward-compatibility re-exports
----------------------------------
This module re-exports the original (pre-refactor) names — including certain
underscore-prefixed "private" ones — so any existing code doing
``from passcheck.cli import _run_batch`` keeps working unchanged.  These
private re-exports are deprecated and will be removed in a future major
version; new code should import directly from the owning sub-module.

Security changes (SA-L02, SA-D03):
    ``_set_analyzer`` is NOT re-exported because ``set_analyzer()`` has been
    removed from ``analyzer_singleton.py``.  Any code relying on
    ``from passcheck.cli import _set_analyzer`` will receive an ImportError,
    which is intentional: the function carried a production-visible
    environment-variable gate (PASSCHECK_TEST_MODE) that constituted a
    security risk.  Test code should use ``unittest.mock.patch`` instead:

        from unittest.mock import patch
        with patch("passcheck.cli.analyzer_singleton._analyzer", my_analyzer):
            ...
"""
from __future__ import annotations

from .analyzer_singleton import get_analyzer as _get_analyzer          # noqa: F401
# NOTE: _set_analyzer is intentionally NOT re-exported — SA-L02.
from .app import cli, main                                             # noqa: F401
from .batch_command import (                                           # noqa: F401
    _MAX_LINE_BYTES,
    _run_batch,
    _stdin_passwords,
    _warn_invalid_password,
    batch,
)
from .check_command import check                                       # noqa: F401
from .errors import AnalysisError as _AnalysisError                    # noqa: F401
from .errors import PasswordTooLongError                               # noqa: F401
from .exit_codes import ExitCode as _ExitCode                          # noqa: F401
from .helpers import analyze as _analyze                               # noqa: F401
from .helpers import emit_json as _emit_json                           # noqa: F401
from .helpers import nfc_and_check_length as _nfc_and_check_length     # noqa: F401
from .helpers import report_length_error as _report_length_error       # noqa: F401
from .helpers import run_analysis as _run_analysis                     # noqa: F401
from .interactive import interactive_loop as _interactive_loop         # noqa: F401
from .security import (                                                # noqa: F401
    DEFAULT_INTERACTIVE_RATE_LIMIT_MS as _DEFAULT_INTERACTIVE_RATE_LIMIT_MS,
    INSECURE_FLAG_ENV_GATE as _INSECURE_FLAG_ENV_GATE,
    insecure_password_callback as _insecure_password_callback,
)

__all__ = ["cli", "main", "check", "batch"]