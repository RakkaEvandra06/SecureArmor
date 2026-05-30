from __future__ import annotations

import codecs
import sys
import unicodedata

# ---------------------------------------------------------------------------
# Terminal helpers
# ---------------------------------------------------------------------------

# Complete set of codec canonical names that indicate a UTF-capable stream.
_UTF_CODEC_NAMES: frozenset[str] = frozenset({
    "utf-8",
    "utf-8-sig",
    "utf-16",
    "utf-16-le",
    "utf-16-be",
    "utf-32",
    "utf-32-le",
    "utf-32-be",
})

def is_utf_terminal() -> bool:
    """Return ``True`` when stdout appears to accept UTF-8 output."""
    encoding = getattr(sys.stdout, "encoding", "utf-8") or "utf-8"
    try:
        return codecs.lookup(encoding).name in _UTF_CODEC_NAMES
    except LookupError:
        return True  # safe default: prefer Unicode and let the terminal decide

# ---------------------------------------------------------------------------
# Password masking
# ---------------------------------------------------------------------------

_MASK_FULL_BELOW: int = 6
_MASK_SINGLE_EDGE_BELOW: int = 8

def masked_password(password: str) -> str:
    """Return a display-safe masked version of *password*."""
    length = len(password)
    if length < _MASK_FULL_BELOW:
        # Fully mask very short passwords — revealing any character would expose
        # too large a fraction (e.g. 2/4 = 50 %) for an already-weak password.
        return "*" * length
    if length < _MASK_SINGLE_EDGE_BELOW:
        # Show only the first character; the remainder is masked.
        return password[0] + "*" * (length - 1)
    # Standard display: first and last characters visible.
    return password[0] + "*" * (length - 2) + password[-1]

_LEET_TABLE: dict[int, str] = str.maketrans({
    "@": "a", "4": "a",
    "3": "e",
    "1": "i",   # adm1n  → admin
    "!": "i",   # pass!on → passion
    "|": "i",
    "6": "g",   # 6ame   → game
    "9": "g",   # an9el  → angel
    "8": "b",   # 8ball  → bball
    "0": "o",
    "5": "s", "$": "s",
    "2": "s",   # pa22word → password
    "7": "t",
    "+": "t",   # s+rong → strong
    "(": "c",   # (hocolate → chocolate
})

_PUNCTUATION_CHARS: str = """!"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"""

# ---------------------------------------------------------------------------
# Lookup normalisation
# ---------------------------------------------------------------------------

def normalise_for_lookup(pw: str) -> tuple[str, str, str, str, str]:
    """Return five distinct lookup keys for common-password detection."""
    nfkd     = unicodedata.normalize("NFKD", pw.lower())
    ascii_pw = nfkd.encode("ascii", errors="ignore").decode("ascii")

    stripped            = ascii_pw.strip(_PUNCTUATION_CHARS)
    leet_full           = ascii_pw.translate(_LEET_TABLE)
    stripped_normalised = stripped.translate(_LEET_TABLE)
    reversed_leet       = leet_full[::-1]

    return ascii_pw, stripped, leet_full, stripped_normalised, reversed_leet