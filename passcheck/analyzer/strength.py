"""Maps a numeric score to its strength label and display colour."""
from __future__ import annotations

from ..constants import STRENGTH_BANDS
from ..models import compute_score_percent

__all__ = ["strength_label_and_colour"]

def strength_label_and_colour(score: int, eff_max: int) -> tuple[str, str]:
    """Map *score* (as a percentage of *eff_max*) to a strength label and colour key."""
    pct = compute_score_percent(score, eff_max)
    for threshold, label, colour in STRENGTH_BANDS:
        if pct >= threshold:
            return label, colour
    return STRENGTH_BANDS[-1][1], STRENGTH_BANDS[-1][2]