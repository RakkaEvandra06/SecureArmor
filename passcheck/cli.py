"""
cli.py — Command-line interface for PassCheck.
Uses only click + stdlib (no rich dependency).
"""

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

_analyzer = PasswordAnalyzer()


@click.group(invoke_without_command=True, context_settings={"help_option_names": ["-h", "--help"]})
@click.pass_context
def cli(ctx: click.Context) -> None:
    """
    PassCheck — Password Strength Analyser

    \b
    EXAMPLES
      passcheck check                      # interactive hidden-input prompt
      passcheck check -p "MyP@ssw0rd"      # single password (warns: insecure)
      passcheck check -p "secret" --json   # JSON output
      passcheck check --show-password      # reveal masked password in output
      passcheck batch                      # read passwords from stdin

    Run `passcheck COMMAND --help` for details on each sub-command.
    """
    if ctx.invoked_subcommand is None:
        ctx.invoke(check)


@cli.command()
@click.option("-p", "--password", default=None,
              help="Password to analyse. Warning: visible in shell history.")
@click.option("--show-password", is_flag=True, default=False,
              help="Show the password (partially masked) in output.")
@click.option("--json", "output_json", is_flag=True, default=False,
              help="Output results as JSON.")
@click.option("--interactive", "-i", is_flag=True, default=False,
              help="Stay in a loop and analyse multiple passwords.")
def check(password: str | None, show_password: bool, output_json: bool, interactive: bool) -> None:
    """Analyse one or more passwords and report their strength."""
    if password is not None and not interactive:
        _warn_insecure_flag()
        _run_analysis(password, show_password=show_password, output_json=output_json)
        return
    _interactive_loop(show_password=show_password, output_json=output_json)


@cli.command()
@click.option("--show-password", is_flag=True, default=False,
              help="Show the password (partially masked) in output.")
@click.option("--json", "output_json", is_flag=True, default=False,
              help="Output results as JSON.")
def batch(show_password: bool, output_json: bool) -> None:
    """
    Read passwords from stdin (one per line) and analyse each one.

    \b
    EXAMPLE
      cat passwords.txt | passcheck batch
      echo "MyP@ss!" | passcheck batch --json
    """
    passwords = [line.rstrip("\n") for line in sys.stdin if line.strip()]
    if not passwords:
        print("Error: No passwords received on stdin.", file=sys.stderr)
        raise SystemExit(1)
    for pw in passwords:
        _run_analysis(pw, show_password=show_password, output_json=output_json)
        if not output_json:
            print_separator()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run_analysis(password: str, *, show_password: bool, output_json: bool) -> None:
    analysis = _analyzer.analyze(password)
    if output_json:
        print_analysis_json(analysis)
    else:
        print_analysis(analysis, show_password=show_password)


def _interactive_loop(*, show_password: bool, output_json: bool) -> None:
    if not output_json:
        print_banner()

    while True:
        try:
            if output_json:
                pw = input()
            else:
                pw = getpass.getpass("  Enter password: ")
        except (KeyboardInterrupt, EOFError):
            if not output_json:
                print("\n  Goodbye!\n")
            raise SystemExit(0)

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
    print(
        "⚠  Warning: Passing a password via --password may expose it in your "
        "shell history. Consider using the interactive prompt instead.\n",
        file=sys.stderr,
    )


def main() -> None:
    cli()
