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

_MASK_FULL_BELOW:        int = 6
_MASK_SINGLE_EDGE_BELOW: int = 8

try:
    import grapheme as _grapheme  # type: ignore[import]

    def _grapheme_split(s: str) -> list[str]:
        """Split *s* into user-perceived grapheme clusters (Unicode-aware)."""
        return list(_grapheme.graphemes(s))

except ImportError:
    def _grapheme_split(s: str) -> list[str]:  # type: ignore[misc]
        """Fallback: split by Unicode code points."""
        return list(s)

def grapheme_len(s: str) -> int:
    """Return the number of user-perceived grapheme clusters in *s*."""
    return len(_grapheme_split(s))

def grapheme_unique_count(s: str) -> int:
    """Return the number of *distinct* user-perceived grapheme clusters in *s*."""
    return len(set(_grapheme_split(s)))

def masked_password(password: str) -> str:
    """Return a display-safe masked version of *password*."""
    chars  = _grapheme_split(password)
    length = len(chars)
    if length < _MASK_FULL_BELOW:
        # Fully mask very short passwords — revealing any character would expose
        # too large a fraction (e.g. 2/4 = 50 %) for an already-weak password.
        return "*" * length
    if length < _MASK_SINGLE_EDGE_BELOW:
        # Show only the first character; the remainder is masked.
        return chars[0] + "*" * (length - 1)
    # Standard display: first and last characters visible.
    return chars[0] + "*" * (length - 2) + chars[-1]

# ---------------------------------------------------------------------------
# Leet-speak normalisation
# ---------------------------------------------------------------------------

_leet_source: dict[str, str] = {
    "@": "a", "4": "a",
    "3": "e", "\N{EURO SIGN}": "e",        # 3 → e, € → e
    "1": "i",                              # adm1n    → admin
    "!": "i",                              # pass!on  → passion
    "|": "l",                              # adm|n    → admln  (matches admin)
    "6": "g",                              # 6ame     → game
    "9": "g",                              # an9el    → angel
    "8": "b",                              # 8ball    → bball
    "0": "o",
    "5": "s", "$": "s",
    "7": "t",
    "+": "t",                              # s+rong   → strong
    "(": "c",                              # (hocolate → chocolate
    "2": "z",                              # cra2y    → crazy
}

_LEET_TABLE: dict[int, int] = str.maketrans(_leet_source)

_PUNCTUATION_CHARS: str = """!"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"""
_MIN_ASCII_RESIDUE_LEN: int = 4

# ---------------------------------------------------------------------------
# Lookup normalisation
# ---------------------------------------------------------------------------

def normalise_for_lookup(pw: str) -> frozenset[str]:
    """Return a set of distinct normalised lookup keys for common-password detection."""
    nfkd     = unicodedata.normalize("NFKD", pw.casefold())
    ascii_pw = nfkd.encode("ascii", errors="ignore").decode("ascii")

    if len(ascii_pw) < _MIN_ASCII_RESIDUE_LEN:
        return frozenset()

    whitespace_stripped     = ascii_pw.strip()
    stripped                = whitespace_stripped.strip(_PUNCTUATION_CHARS)
    leet_full               = ascii_pw.translate(_LEET_TABLE)
    whitespace_leet         = whitespace_stripped.translate(_LEET_TABLE)
    stripped_normalised     = stripped.translate(_LEET_TABLE)
    reversed_leet           = leet_full[::-1]

    return frozenset(filter(None, {
        ascii_pw,
        whitespace_stripped,
        stripped,
        leet_full,
        whitespace_leet,
        stripped_normalised,
        reversed_leet,
    }))