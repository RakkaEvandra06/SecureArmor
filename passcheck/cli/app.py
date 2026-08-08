"""The CLI root group and process entry point.

`check_command.py` and `batch_command.py` both import ``cli`` from this
module to register themselves via ``@cli.command()``. To avoid a circular
import the other direction, this module imports them lazily (inside the
function body) instead of at module load time — by the time `cli()` is
actually invoked, the whole `passcheck.cli` package has already finished
importing and both commands are registered.
"""
from __future__ import annotations

import sys

import click

from .. import __version__

__all__ = ["cli", "main"]

# ---------------------------------------------------------------------------
# CLI root
# ---------------------------------------------------------------------------

@click.group(
    invoke_without_command=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)
@click.version_option(__version__, "-V", "--version", prog_name="passcheck")
@click.pass_context
def cli(ctx: click.Context) -> None:
    """PassCheck — Password Strength Analyser."""
    if ctx.invoked_subcommand is None:
        from .batch_command import batch
        from .check_command import check

        if not sys.stdin.isatty():
            ctx.invoke(batch)
        else:
            ctx.invoke(check)

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """Entry point registered in ``pyproject.toml``."""
    cli()
