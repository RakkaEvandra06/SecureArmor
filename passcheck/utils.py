from __future__ import annotations

import codecs
import sys

# ---------------------------------------------------------------------------
# Complete set of codec *canonical* names that indicate a UTF-capable stream.
# codecs.lookup(enc).name always returns the canonical name, so aliases like
# "UTF8" or "utf8" resolve correctly before comparison.
# ---------------------------------------------------------------------------
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
    enc = getattr(sys.stdout, "encoding", "utf-8") or "utf-8"
    try:
        return codecs.lookup(enc).name in _UTF_CODEC_NAMES
    except LookupError:
        return True   # safe default: prefer Unicode, let the terminal decide