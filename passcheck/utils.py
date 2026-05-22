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
    "1": "i",   # adm1n → admin
    "!": "i",   # pass!on → passion
    "|": "i",
    "6": "b",   # visually resembles b, not g (e.g. "6all" → "ball")
    "9": "g",   # 9 visually resembles g (e.g. "9ame" → "game")
    "8": "b",   # 8ball → bball
    "0": "o",
    "5": "s", "$": "s",
    "7": "t",
})

_PUNCTUATION_CHARS: str = r"""!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~"""

# ---------------------------------------------------------------------------
# Lookup normalisation
# ---------------------------------------------------------------------------

def normalise_for_lookup(pw: str) -> tuple[str, str, str, str]:
    """Return four lookup keys for common-password detection."""
    nfkd     = unicodedata.normalize("NFKD", pw.lower())
    ascii_pw = nfkd.encode("ascii", errors="ignore").decode("ascii")
    # Strip punctuation on the raw ASCII form first, then leet-substitute.
    stripped   = ascii_pw.strip(_PUNCTUATION_CHARS)
    normalised = stripped.translate(_LEET_TABLE)
    leet_full  = ascii_pw.translate(_LEET_TABLE)
    return ascii_pw, normalised, stripped, leet_full