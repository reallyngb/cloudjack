"""Command-line interface for CloudJack."""

from pathlib import Path
import json
from typing import Annotated
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from cloudjack import __version__
from cloudjack.loader import load_account, CloudJackLoadError
from cloudjack.graph import build_graph
from cloudjack.paths import find_paths
from cloudjack.risk import score_path
from cloudjack.remediate import generate_remediated_account
from cloudjack.report import generate_json_report, generate_html_report

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
def scan(
    file: Annotated[str, typer.Option("--file", "-f", help="Path to scenario JSON")],
    start: Annotated[str, typer.Option("--start", "-s", help="Starting identity ARN")],
    target: Annotated[str, typer.Option("--target", "-t", help="Target resource ARN")],
    remediate: Annotated[bool, typer.Option("--remediate", "-r", help="Generate a remediated JSON file")] = False,
    report: Annotated[bool, typer.Option("--report", help="Generate JSON and HTML reports")] = False,
) -> None:
    """Scan for attack paths, score risk, and optionally generate remediations/reports."""
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
        path.risk = score_path(path, account)
        
        console.print(f"[bold cyan]Path {idx} (Risk: {path.risk.total}/100)[/bold cyan]")
        console.print(f"[dim]{path.risk.explanation}[/dim]\n")
        
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

    if remediate:
        rem_account = generate_remediated_account(account, paths[0])
        out_path = Path(file).with_name(Path(file).stem + "_remediated.json")
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(rem_account.model_dump(), f, indent=2)
        console.print(Panel(f"Remediation written to [bold]{out_path}[/bold]\nRun the scan again against this file to verify the path is closed.", title="Remediation", border_style="green"))

    if report:
        # Generate JSON report
        json_path = "findings.json"
        generate_json_report(paths, json_path)
        
        # Generate HTML report
        html_path = "report.html"
        generate_html_report(account, graph, paths, html_path)
        
        console.print(Panel(f"Reports generated:\n  - [bold]{json_path}[/bold]\n  - [bold]{html_path}[/bold]\nOpen the HTML file in your browser to view the interactive report.", title="Reporting", border_style="blue"))
