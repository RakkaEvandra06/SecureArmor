"""Entry point for ``python -m passcheck``.

This file MUST be named ``__main__.py`` — Python's ``-m`` flag looks for
exactly this filename inside a package and nothing else. ``main.py`` is kept
alongside it purely as a backward-compatible import shim (see main.py).
"""
from .cli import main

if __name__ == "__main__":
    main()