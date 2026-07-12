from __future__ import annotations

import codecs
import logging as _logging
import re
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
    import grapheme as _grapheme

    def split_graphemes(s: str) -> list[str]:
        """Split *s* into user-perceived grapheme clusters (Unicode-aware)."""
        return list(_grapheme.graphemes(s))

except ImportError:
    _grapheme_fallback_warned = False

    def split_graphemes(s: str) -> list[str]:
        """Fallback: split by Unicode code points."""
        global _grapheme_fallback_warned
        if not _grapheme_fallback_warned:
            _logging.getLogger(__name__).warning(
                "Optional 'grapheme' package not installed; falling back to "
                "code-point splitting. Multi-codepoint Unicode characters "
                "(emoji, combining marks) may be miscounted as a result. "
                "For full correctness, install with: pip install securearmor[unicode]"
            )
            _grapheme_fallback_warned = True
        return list(s)

def grapheme_len(s: str) -> int:
    """Return the number of user-perceived grapheme clusters in *s*."""
    return len(split_graphemes(s))

def grapheme_unique_count(s: str) -> int:
    """Return the number of *distinct* user-perceived grapheme clusters in *s*."""
    return len(set(split_graphemes(s)))

# ---------------------------------------------------------------------------
# Structural repetition detection
# ---------------------------------------------------------------------------

def repeated_block_period(seq: str | list[str]) -> int:
    """Return the period of the shortest exact repeating block in *seq*."""
    n = len(seq)
    for p in range(1, n // 2 + 1):
        if n % p == 0 and seq == seq[:p] * (n // p):
            return p
    return 0

def masked_password(password: str) -> str:
    """Return a display-safe masked version of *password*."""
    chars  = split_graphemes(password)
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

LEET_TABLE: dict[int, int] = str.maketrans(
    "".join(_leet_source.keys()), "".join(_leet_source.values())
)

_PUNCTUATION_CHARS: str = """!"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"""
_MIN_ASCII_RESIDUE_LEN: int = 4

_EDGE_DECORATION_RE: re.Pattern[str] = re.compile(
    rf"^[{re.escape(_PUNCTUATION_CHARS)}0-9]+|[{re.escape(_PUNCTUATION_CHARS)}0-9]+$"
)

# ---------------------------------------------------------------------------
# Lookup normalisation
# ---------------------------------------------------------------------------

def ascii_residue_length(pw: str) -> int:
    """Return the length of *pw* after NFKD+casefold ASCII-residue extraction."""
    nfkd = unicodedata.normalize("NFKD", pw.casefold())
    return len(nfkd.encode("ascii", errors="ignore").decode("ascii"))

def normalise_for_lookup(pw: str) -> frozenset[str]:
    """Return a set of distinct normalised lookup keys for common-password detection."""
    nfkd     = unicodedata.normalize("NFKD", pw.casefold())
    ascii_pw = nfkd.encode("ascii", errors="ignore").decode("ascii")

    if len(ascii_pw) < _MIN_ASCII_RESIDUE_LEN:
        return frozenset()

    whitespace_stripped     = ascii_pw.strip()
    stripped                = whitespace_stripped.strip(_PUNCTUATION_CHARS)
    edge_stripped           = _EDGE_DECORATION_RE.sub("", whitespace_stripped)
    leet_full               = ascii_pw.translate(LEET_TABLE)
    whitespace_leet         = whitespace_stripped.translate(LEET_TABLE)
    stripped_normalised     = stripped.translate(LEET_TABLE)
    edge_stripped_leet      = edge_stripped.translate(LEET_TABLE)
    reversed_leet           = leet_full[::-1]

    return frozenset(filter(None, {
        ascii_pw,
        whitespace_stripped,
        stripped,
        edge_stripped,
        leet_full,
        whitespace_leet,
        stripped_normalised,
        edge_stripped_leet,
        reversed_leet,
    }))