"""Core scoring engine for PassCheck.

This used to be a single 498-line ``analyzer.py``. It is now a package
split by *criterion category* (Single Responsibility Principle), with one
focused file per concern:

    core.py        — PasswordAnalyzer.analyze() orchestrator (thin assembly)
    length.py        — minimum / good / excellent length criteria
    character.py        — character-class presence + variety + uniqueness
    patterns.py             — common-password / keyboard-walk / repetition checks
    entropy.py                — entropy criterion + the entropy estimator
    strength.py                  — score -> (label, colour) mapping

Every file stays well under the ~400-line point where AI coding agents lose
indexing accuracy, and each one answers a single, easily-grep-able question.
"""
from __future__ import annotations

from .core import PasswordAnalyzer

__all__ = ["PasswordAnalyzer"]
