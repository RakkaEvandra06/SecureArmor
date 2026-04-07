from __future__ import annotations

import getpass
import sys

import click

from .analyzer import PasswordAnalyzer
from .display import (
    print_analysis,
    print_analysis_json,
    print_banner,
    print_separator,
)

# Module-level analyzer — stateless, so sharing one instance is safe.
_analyzer = PasswordAnalyzer()

# Exit codes
_EXIT_OK    = 0
_EXIT_ERROR = 1

# ---------------------------------------------------------------------------
# CLI root
# ---------------------------------------------------------------------------

@click.group(
    invoke_without_command=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)
@click.pass_context
def cli(ctx: click.Context) -> None:
    """PassCheck — Password Strength Analyser."""
    if ctx.invoked_subcommand is None:
        ctx.invoke(check)

# ---------------------------------------------------------------------------
# Sub-commands
# ---------------------------------------------------------------------------

@cli.command()
@click.option(
    "-p", "--password",
    default=None,
    help="Password to analyse. Warning: visible in shell history.",
)
@click.option(
    "--show-password",
    is_flag=True,
    default=False,
    help="Show the password (partially masked) in output.",
)
@click.option(
    "--json", "output_json",
    is_flag=True,
    default=False,
    help="Output results as JSON.",
)
def check(password: str | None, show_password: bool, output_json: bool) -> None:
    """Analyse a single password."""
    if password is not None:
        _warn_insecure_flag()
        _run_analysis(password, show_password=show_password, output_json=output_json)
    else:
        _interactive_loop(show_password=show_password, output_json=output_json)

@cli.command()
@click.option(
    "--show-password",
    is_flag=True,
    default=False,
    help="Show the password (partially masked) in output.",
)
@click.option(
    "--json", "output_json",
    is_flag=True,
    default=False,
    help="Output results as JSON.",
)
def batch(show_password: bool, output_json: bool) -> None:
    """Analyse multiple passwords from stdin (one per line)."""
    passwords = [line.rstrip("\n") for line in sys.stdin if line.strip()]
    if not passwords:
        click.echo("Error: No passwords received on stdin.", err=True)
        raise SystemExit(_EXIT_ERROR)

    for i, pw in enumerate(passwords):
        _run_analysis(pw, show_password=show_password, output_json=output_json)
        if not output_json and i < len(passwords) - 1:
            print_separator()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run_analysis(password: str, *, show_password: bool, output_json: bool) -> None:
    """Analyse *password* and dispatch to the appropriate renderer."""
    try:
        analysis = _analyzer.analyze(password)
    except ValueError as exc:
        click.echo(f"Error: {exc}", err=True)
        raise SystemExit(_EXIT_ERROR) from exc

    if output_json:
        print_analysis_json(analysis)
    else:
        print_analysis(analysis, show_password=show_password)

def _interactive_loop(*, show_password: bool, output_json: bool) -> None:
    """Run the interactive prompt loop until the user quits."""
    if not output_json:
        print_banner()

    while True:
        try:
            prompt = "" if output_json else "  Enter password: "
            pw = getpass.getpass(prompt)
        except (KeyboardInterrupt, EOFError):
            if not output_json:
                print("\n  Goodbye!\n")
            raise SystemExit(_EXIT_OK)

        if pw.lower() in {"quit", "exit", "q"}:
            if not output_json:
                print("\n  Goodbye!\n")
            break

        if not pw:
            if not output_json:
                print("  Please enter a non-empty password.\n")
            continue

        _run_analysis(pw, show_password=show_password, output_json=output_json)

        if not output_json:
            print_separator()
            print()

def _warn_insecure_flag() -> None:
    """Print a warning to stderr when a password is passed via --password."""
    click.echo(
        "Warning: Passing a password via --password may expose it in your "
        "shell history. Consider using the interactive prompt instead.\n",
        err=True,
    )

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    cli()