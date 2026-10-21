"""Command-line interface for CloudJack.

Stage 3 stub: only exposes ``--version`` so we can verify that the package
installs and runs. The ``scan``/``diff``/``render`` subcommands are introduced
in Stage 7.
"""

from typing import Annotated

import typer

from cloudjack import __version__


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"cloudjack {__version__}")
        raise typer.Exit()


app = typer.Typer(
    name="cloudjack",
    help="Offline AWS IAM attack-path simulator (synthetic data only).",
    add_completion=False,
    no_args_is_help=True,
)


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            callback=_version_callback,
            is_eager=True,
            help="Show the CloudJack version and exit.",
        ),
    ] = False,
) -> None:
    """CloudJack command group."""
    # The callback handles --version; this body runs only for real subcommands.


if __name__ == "__main__":
    app()
