"""Entropy criterion and the blended Shannon / character-pool entropy estimator."""
from __future__ import annotations

import math
from collections import Counter

from ..constants import (
    ENTROPY_GOOD_THRESHOLD,
    SCORE_WEIGHTS,
    SHANNON_WEIGHT,
    SPECIAL_CHARS_SET,
)
from ..models import CriterionResult
from ..utils import repeated_block_period

__all__ = ["criterion_entropy", "compute_entropy"]

_UNICODE_BLOCK_POOLS: tuple[tuple[int, int, int], ...] = (
    # Latin supplements
    (0x0080, 0x00FF,    96),   # Latin-1 Supplement
    (0x0100, 0x017F,   128),   # Latin Extended-A
    (0x0180, 0x024F,   208),   # Latin Extended-B
    (0x0250, 0x02AF,    96),   # IPA Extensions
    # European scripts
    (0x0370, 0x03FF,   135),   # Greek and Coptic
    (0x0400, 0x04FF,   256),   # Cyrillic
    (0x0500, 0x052F,    48),   # Cyrillic Supplement
    (0x0590, 0x05FF,    87),   # Hebrew
    (0x0600, 0x06FF,   200),   # Arabic (conservative; many control chars)
    # South / Southeast Asian scripts
    (0x0900, 0x097F,   128),   # Devanagari
    (0x0980, 0x09FF,    96),   # Bengali
    (0x0A00, 0x0A7F,    80),   # Gurmukhi
    (0x0A80, 0x0AFF,    91),   # Gujarati
    (0x0B00, 0x0B7F,    91),   # Oriya
    (0x0B80, 0x0BFF,    72),   # Tamil
    (0x0C00, 0x0C7F,    96),   # Telugu
    (0x0C80, 0x0CFF,    87),   # Kannada
    (0x0D00, 0x0D7F,   118),   # Malayalam
    (0x0E00, 0x0E7F,    87),   # Thai
    (0x0E80, 0x0EFF,    67),   # Lao
    (0x0F00, 0x0FFF,   211),   # Tibetan
    (0x1000, 0x109F,   100),   # Myanmar
    (0x10A0, 0x10FF,    87),   # Georgian
    # CJK and East Asian
    (0x3000, 0x303F,    64),   # CJK Symbols and Punctuation
    (0x3040, 0x309F,    96),   # Hiragana  ← 46 phonetic + 50 variants ≈ 96
    (0x30A0, 0x30FF,    96),   # Katakana
    (0x3100, 0x312F,    43),   # Bopomofo
    (0x3130, 0x318F,    94),   # Hangul Compatibility Jamo
    (0x3400, 0x4DBF,  6592),   # CJK Unified Ideographs Extension A
    (0x4E00, 0x9FFF, 20902),   # CJK Unified Ideographs (core)
    (0xA960, 0xA97F,    29),   # Hangul Jamo Extended-A
    (0xAC00, 0xD7A3, 11172),   # Hangul Syllables
    (0xF900, 0xFAFF,   512),   # CJK Compatibility Ideographs
    # Symbols and miscellaneous
    (0x2000, 0x206F,    64),   # General Punctuation
    (0x2100, 0x214F,    80),   # Letterlike Symbols
    (0x2200, 0x22FF,   256),   # Mathematical Operators
    (0x2600, 0x26FF,   256),   # Miscellaneous Symbols
    (0x2700, 0x27BF,   192),   # Dingbats
    # Mathematical
    (0x1D400, 0x1D7FF, 996),   # Mathematical Alphanumeric Symbols
    # Emoji (critically important: real emoji pools are small)
    (0x1F300, 0x1F5FF, 200),   # Miscellaneous Symbols and Pictographs
    (0x1F600, 0x1F64F,  80),   # Emoticons — ~80 distinct face/gesture emoji
    (0x1F680, 0x1F6FF, 128),   # Transport and Map Symbols
    (0x1F700, 0x1F77F, 116),   # Alchemical Symbols
    (0x1F900, 0x1F9FF, 256),   # Supplemental Symbols and Pictographs
    (0x1FA00, 0x1FA6F, 112),   # Chess Symbols, Medical Symbols
    (0x1FA70, 0x1FAFF, 144),   # Symbols and Pictographs Extended-A
)

# Conservative fallback pool for code points not matched by any block entry.
# 128 is chosen because most unrecognised blocks are relatively small scripts
# or technical symbol sets; 128 avoids overestimating their attacker-visible size.
_UNICODE_BLOCK_POOL_FALLBACK: int = 128

def _unicode_pool_size(pw: str) -> int:
    """Return an estimate of the non-ASCII character pool for *pw*."""
    non_ascii_chars = {c for c in pw if not c.isascii()}
    if not non_ascii_chars:
        return 0

    seen_block_keys: set[str] = set()
    total_pool = 0

    for ch in non_ascii_chars:
        cp = ord(ch)
        found = False
        for start, end, pool_count in _UNICODE_BLOCK_POOLS:
            if start <= cp <= end:
                # Key by block start so the same block is counted only once.
                block_key = f"{start:05X}"
                if block_key not in seen_block_keys:
                    total_pool += pool_count
                    seen_block_keys.add(block_key)
                found = True
                break
        if not found:
            # Unrecognised block: group by the high byte of the code point to
            # avoid counting every distinct unrecognised character separately.
            block_key = f"unk_{cp >> 8:04X}"
            if block_key not in seen_block_keys:
                total_pool += _UNICODE_BLOCK_POOL_FALLBACK
                seen_block_keys.add(block_key)

    return total_pool

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def criterion_entropy(entropy: float) -> CriterionResult:
    """Return the entropy criterion result for a pre-computed *entropy* value."""
    weight = SCORE_WEIGHTS["entropy"]
    passed = entropy >= ENTROPY_GOOD_THRESHOLD
    return CriterionResult(
        name="Entropy",
        passed=passed,
        score=weight if passed else 0,
        max_score=weight,
        detail=f"{entropy:.1f} bits (target {ENTROPY_GOOD_THRESHOLD:.0f}+)",
        suggestion="" if passed else "Increase length and character variety to raise entropy.",
    )


def compute_entropy(pw: str, graphemes: list[str], length: int) -> float:
    """Return a blended Shannon / character-pool entropy estimate, in bits."""
    if length == 0:
        return 0.0

    counts           = Counter(graphemes)
    total            = length                  # == len(graphemes)
    shannon_per_char = -sum(
        (n / total) * math.log2(n / total) for n in counts.values()
    )

    pool_size = 0
    if any(c.islower() for c in pw):
        pool_size += 26
    if any(c.isupper() for c in pw):
        pool_size += 26
    if any(c.isascii() and c.isdigit() for c in pw):
        pool_size += 10
    if any(c in SPECIAL_CHARS_SET for c in pw):
        pool_size += len(SPECIAL_CHARS_SET)
    pool_size += _unicode_pool_size(pw)
    pool_size = max(pool_size, 1)

    period = repeated_block_period(graphemes)
    effective_length: float = length
    if period >= 1:
        repetitions = length / period
        effective_length = period + math.log2(repetitions)

    max_freq = max(counts.values())
    freq_effective_length = length * (1 - max_freq / length) + 1
    effective_length = min(effective_length, freq_effective_length, length)

    shannon_total = shannon_per_char * effective_length
    pool_total    = math.log2(pool_size) * effective_length

    return SHANNON_WEIGHT * shannon_total + (1 - SHANNON_WEIGHT) * pool_total