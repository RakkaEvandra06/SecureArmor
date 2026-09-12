"""Loading, caching, and validating the common-password list."""
from __future__ import annotations

import logging  as _logging
import os       as _os
import pathlib  as _pathlib
import random   as _random
import sys      as _sys
import threading as _threading

from ..utils import normalise_for_lookup as _normalise_for_lookup
from .common_passwords_data import RAW_BUILTIN_COMMON_PASSWORDS as _RAW_BUILTIN_COMMON_PASSWORDS
from .keyboard_patterns import KEYBOARD_PATTERNS

__all__ = ["get_common_passwords"]

_logger = _logging.getLogger(__name__)

def _expand_builtin_passwords(raw: frozenset[str]) -> frozenset[str]:
    """Expand each raw entry into all normalised lookup variants."""
    expanded: set[str] = set()
    for entry in raw:
        expanded.update(v for v in _normalise_for_lookup(entry) if v)
    return frozenset(expanded)

_BUILTIN_COMMON_PASSWORDS: frozenset[str] = _expand_builtin_passwords(
    _RAW_BUILTIN_COMMON_PASSWORDS
)

_MAX_COMMON_PASSWORDS_FILE_BYTES: int = 50 * 1024 * 1024  # 50 MB
_MIN_EXPECTED_COMMON_PASSWORDS: int = 5_000

# ---------------------------------------------------------------------------
# SA-M01: visible stderr warning for missing wordlist
# ---------------------------------------------------------------------------

def _warn_missing_wordlist(data_path: _pathlib.Path) -> None:
    """Write a visible, actionable notice to stderr when the word list is absent."""
    if _os.environ.get("PASSCHECK_SUPPRESS_WORDLIST_WARNING") == "1":
        return

    lines = [
        "",
        "[passcheck] WARNING: The common-password word list was not found:",
        f"  {data_path}",
        f"  Falling back to the built-in list ({len(_BUILTIN_COMMON_PASSWORDS)} entries).",
        "  Common-password detection coverage is SEVERELY LIMITED.",
        "  An attacker using a dictionary of 10,000 common passwords would have",
        "  roughly 14× more coverage than this tool currently provides.",
        "",
        "  To restore full coverage, place a word list at the path above.",
        "  Recommended source (public domain):",
        "    https://github.com/danielmiessler/SecLists",
        "    SecLists/Passwords/Common-Credentials/10-million-password-list-top-10000.txt",
        "",
        "  To suppress this message: set PASSCHECK_SUPPRESS_WORDLIST_WARNING=1",
        "",
    ]
    _sys.stderr.write("\n".join(lines) + "\n")
    _sys.stderr.flush()

# ---------------------------------------------------------------------------
# Password file loader
# ---------------------------------------------------------------------------

def _load_common_passwords() -> frozenset[str]:
    """Load common passwords from an external file, falling back to the built-in set."""
    data_path = _pathlib.Path(__file__).parent.parent / "data" / "common_passwords.txt"

    if not data_path.exists():
        _logger.warning(
            "Common passwords data file not found at %s. "
            "Using the built-in fallback list (%d variant entries). "
            "For proper coverage, ship data/common_passwords.txt with at least "
            "the SecLists top-10 000 password list "
            "(https://github.com/danielmiessler/SecLists).",
            data_path,
            len(_BUILTIN_COMMON_PASSWORDS),
        )
        _warn_missing_wordlist(data_path)
        return _BUILTIN_COMMON_PASSWORDS

    entries_set: set[str] = set()
    raw_count   = 0

    try:
        total_bytes = 0
        with data_path.open("rb") as fh:
            for raw_line_bytes in fh:
                total_bytes += len(raw_line_bytes)
                if total_bytes > _MAX_COMMON_PASSWORDS_FILE_BYTES:
                    _logger.warning(
                        "Common passwords file at %s exceeded the safety cap "
                        "(~%d MB) after reading ~%d bytes. "
                        "Using the %d entries loaded so far, merged with the "
                        "built-in list.  Split the file or raise "
                        "_MAX_COMMON_PASSWORDS_FILE_BYTES if intentional.",
                        data_path,
                        _MAX_COMMON_PASSWORDS_FILE_BYTES // (1024 * 1024),
                        total_bytes,
                        len(entries_set),
                    )
                    break

                try:
                    raw_line = raw_line_bytes.decode("utf-8")
                except UnicodeDecodeError:
                    _logger.debug(
                        "Skipped a line in %s that could not be decoded as UTF-8.",
                        data_path,
                    )
                    continue

                raw_entry = raw_line.strip()
                if not raw_entry:
                    continue
                raw_count += 1

                entries_set.update(_normalise_for_lookup(raw_entry))

    except (OSError, ValueError) as exc:
        _logger.warning(
            "Could not read common passwords from %s (%s). "
            "Falling back to the built-in list (%d variant entries).",
            data_path, exc, len(_BUILTIN_COMMON_PASSWORDS),
        )
        return _BUILTIN_COMMON_PASSWORDS

    loaded = frozenset(entries_set)
    result = loaded | _BUILTIN_COMMON_PASSWORDS

    _logger.debug(
        "Loaded %d raw entries from %s; expanded to %d file variants; "
        "%d built-in variant entries; %d total after merge.",
        raw_count, data_path, len(loaded),
        len(_BUILTIN_COMMON_PASSWORDS), len(result),
    )
    return result

def _debug_log_pattern_overlaps(
    loaded: frozenset[str],
    *,
    sample_size: int = 500,
    seed:        int = 42,
) -> None:
    """Log keyboard-pattern / common-password overlaps using a deterministic sample."""
    _rng    = _random.Random(seed)
    sample  = _rng.sample(sorted(loaded), min(sample_size, len(loaded)))
    overlaps = [
        (pattern, entry)
        for pattern in KEYBOARD_PATTERNS
        for entry in sample
        if pattern in entry and pattern != entry
    ]
    if overlaps:
        preview    = overlaps[:10]
        extra      = len(overlaps) - len(preview)
        extra_note = f"\n  ...and {extra} more" if extra else ""
        _logger.debug(
            "KEYBOARD_PATTERNS substrings found inside COMMON_PASSWORDS sample "
            "(double penalty handled by skip logic):\n%s%s",
            "\n".join(
                f"  pattern {p!r} found inside common password {e!r}"
                for p, e in preview
            ),
            extra_note,
        )

# ---------------------------------------------------------------------------
# Lock-always singleton (replaces double-checked locking)
# ---------------------------------------------------------------------------

_COMMON_PASSWORDS_CACHE: frozenset[str] | None = None
_COMMON_PASSWORDS_LOCK:  _threading.Lock       = _threading.Lock()

def get_common_passwords() -> frozenset[str]:
    """Return the merged common-password frozenset, loading it on first call."""
    global _COMMON_PASSWORDS_CACHE

    with _COMMON_PASSWORDS_LOCK:
        if _COMMON_PASSWORDS_CACHE is not None:
            return _COMMON_PASSWORDS_CACHE

        try:
            loaded = _load_common_passwords()

            # Validate: all normalised entries must be lower-case.
            _mixed_case = [e for e in loaded if e != e.lower()]
            if _mixed_case:
                _sorted_bad = sorted(_mixed_case)
                _suffix     = "..." if len(_sorted_bad) > 10 else ""
                raise ValueError(
                    f"All COMMON_PASSWORDS entries must be lower-case. "
                    f"Offending entries: {_sorted_bad[:10]}{_suffix}"
                )

            if len(loaded) < _MIN_EXPECTED_COMMON_PASSWORDS:
                _logger.warning(
                    "Common passwords set has only %d entries (expected at "
                    "least %d). Common-password detection coverage may be "
                    "severely degraded. Ensure data/common_passwords.txt "
                    "contains at least the SecLists top-10,000 list.",
                    len(loaded), _MIN_EXPECTED_COMMON_PASSWORDS,
                )

            _overlap = frozenset(KEYBOARD_PATTERNS) & loaded
            if _overlap:
                _logger.debug(
                    "Entries appear in both KEYBOARD_PATTERNS and COMMON_PASSWORDS "
                    "(double penalty prevented by skip logic): %s",
                    sorted(_overlap),
                )

            if _logger.isEnabledFor(_logging.DEBUG):
                _debug_log_pattern_overlaps(loaded)

            _COMMON_PASSWORDS_CACHE = loaded

        except MemoryError:
            _logger.error(
                "Out-of-memory error while loading the common passwords list. "
                "The host may be resource-exhausted. Re-raising."
            )
            raise

        except (OSError, ValueError, UnicodeDecodeError) as exc:
            _logger.warning(
                "Unexpected error while loading or validating the common passwords "
                "list (%s: %s). Falling back to the built-in list (%d variant "
                "entries). The tool will continue to function with reduced coverage.",
                type(exc).__name__,
                exc,
                len(_BUILTIN_COMMON_PASSWORDS),
            )
            _COMMON_PASSWORDS_CACHE = _BUILTIN_COMMON_PASSWORDS

        return _COMMON_PASSWORDS_CACHE