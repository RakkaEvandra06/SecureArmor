"""Small shared helpers used by every CLI command: JSON output, NFC
normalisation + length checking, and the run-one-analysis pipeline."""
from __future__ import annotations

import json
import unicodedata

import click

from ..constants import LENGTH_MAXIMUM
from ..display import print_analysis, print_analysis_json
from ..models import PasswordAnalysis
from ..utils import grapheme_len as _grapheme_len
from .analyzer_singleton import get_analyzer
from .errors import AnalysisError, PasswordTooLongError

__all__ = [
    "emit_json",
    "nfc_and_check_length",
    "report_length_error",
    "analyze",
    "run_analysis",
]

def emit_json(obj: dict[str, object]) -> None:
    """Write *obj* as a single compact JSON line (NDJSON-compatible)."""
    print(json.dumps(obj))

def nfc_and_check_length(pw: str) -> str:
    """Normalise *pw* to NFC, raising :class:`PasswordTooLongError` if too long."""
    pw = unicodedata.normalize("NFC", pw)
    length = _grapheme_len(pw)
    if length > LENGTH_MAXIMUM:
        raise PasswordTooLongError(length)
    return pw

def report_length_error(exc: PasswordTooLongError, *, output_json: bool) -> None:
    """Report a :class:`PasswordTooLongError` using the standard error-event shape."""
    if output_json:
        emit_json({"event": "error", "detail": str(exc)})
    else:
        click.echo(str(exc), err=True)

def analyze(password: str) -> PasswordAnalysis:
    """Run the analyser and return the result; propagate ValueError to the caller."""
    return get_analyzer().analyze(password)

def run_analysis(password: str, *, output_json: bool) -> None:
    """Analyse *password* and dispatch to the appropriate renderer."""
    try:
        analysis = analyze(password)
    except ValueError as exc:
        raise AnalysisError(str(exc)) from exc
    if output_json:
        print_analysis_json(analysis)
    else:
        print_analysis(analysis)
        print()  # trailing blank line is owned here, not inside print_analysis
