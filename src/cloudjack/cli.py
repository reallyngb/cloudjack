"""Command-line interface for CloudJack."""

from typing import Annotated
import typer
from rich.console import Console
from rich.table import Table

from cloudjack import __version__
from cloudjack.loader import load_account, CloudJackLoadError
from cloudjack.graph import build_graph
from cloudjack.paths import find_paths

app = typer.Typer(
    name="cloudjack",
    help="Offline AWS IAM attack-path simulator (synthetic data only).",
    add_completion=False,
    no_args_is_help=True,
)
console = Console()


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"cloudjack {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option("--version", callback=_version_callback, is_eager=True, help="Show version."),
    ] = False,
) -> None:
    """CloudJack command group."""


@app.command()
def find_path(
    file: Annotated[str, typer.Option("--file", "-f", help="Path to scenario JSON")],
    start: Annotated[str, typer.Option("--start", "-s", help="Starting identity ARN")],
    target: Annotated[str, typer.Option("--target", "-t", help="Target resource ARN")],
) -> None:
    """Find an attack path from a start identity to a target resource."""
    try:
        account = load_account(file)
    except CloudJackLoadError as e:
        console.print(f"[red]Error loading file:[/red] {e}")
        raise typer.Exit(code=1)

    graph = build_graph(account)
    paths = find_paths(graph, start, target)

    if not paths:
        console.print(f"[yellow]No path found from {start} to {target}.[/yellow]")
        raise typer.Exit(code=0)

    console.print(f"\n[bold green]Found {len(paths)} attack path(s)![/bold green]\n")

    for idx, path in enumerate(paths, 1):
        console.print(f"[bold cyan]Path {idx}:[/bold cyan]")
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Step")
        table.add_column("Source")
        table.add_column("Action")
        table.add_column("Target")
        table.add_column("Evidence")

        for i, step in enumerate(path.steps, 1):
            table.add_row(
                str(i),
                step.source.split(":")[-1],
                step.action,
                step.target.split(":")[-1],
                step.evidence
            )
        console.print(table)
        console.print(f"Confidence: [bold]{path.confidence}[/bold]\n")
