"""Backward-compatible shim.

The real ``python -m passcheck`` entry point now lives in ``__main__.py``
(Python's ``-m`` flag requires that exact filename — ``main.py`` was never
actually reachable that way). This module is kept only so that any external
code still doing ``from passcheck.main import main`` continues to work.
"""
from .__main__ import main

__all__ = ["main"]