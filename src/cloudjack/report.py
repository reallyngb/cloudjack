"""Generate JSON and HTML reports from analysis results."""

import json
from pathlib import Path
from jinja2 import Template
from cloudjack.models import Account, AttackPath
from cloudjack.web.render import render_graph
import networkx as nx


def _read_text_with_fallback(path: Path) -> str:
    """Read a text file, trying several common encodings in order.

    This exists because Windows editors and PowerShell ``Set-Content`` may
    produce UTF-16 or UTF-8-with-BOM files, both of which can trip up a naive
    ``read_text(encoding='utf-8')`` call. Trying UTF-8 first, then UTF-8-with-
    BOM, then UTF-16 covers all realistic cases without surprising the user.
    """
    for encoding in ("utf-8", "utf-8-sig", "utf-16"):
        try:
            return path.read_text(encoding=encoding)
        except UnicodeDecodeError:
            continue
    raise UnicodeDecodeError(
        "unknown", b"", 0, 1, f"Could not decode {path} in any supported encoding"
    )


def generate_json_report(paths: list[AttackPath], output_path: str) -> None:
    """Write a structured JSON report of all findings."""
    data = {
        "tool": "CloudJack",
        "version": "0.1.0",
        "findings": [path.model_dump() for path in paths]
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def generate_html_report(
    account: Account,
    graph: nx.DiGraph,
    paths: list[AttackPath],
    output_path: str
) -> None:
    """Write an interactive HTML report."""
    template_path = Path(__file__).parent / "web" / "template.html"
    template = Template(_read_text_with_fallback(template_path))

    # Render the pyvis graph to a temporary HTML file
    temp_graph_path = "temp_graph.html"
    render_graph(graph, paths, temp_graph_path)

    # Extract the graph body from pyvis output
    graph_raw = _read_text_with_fallback(Path(temp_graph_path))
    start = graph_raw.find('<div id="mynetwork"')
    end = graph_raw.find('</script>', start) + len('</script>')
    graph_html = graph_raw[start:end] if start >= 0 and end > start else ""

    path = paths[0] if paths else None

    html_content = template.render(
        start_identity=path.start_identity if path else "None found",
        target_resource=path.target_resource if path else "None found",
        confidence=path.confidence if path else "N/A",
        risk=path.risk if path else None,
        steps=path.steps if path else [],
        graph_html=graph_html
    )

    # Write HTML as UTF-8 explicitly so repeated runs stay consistent
    Path(output_path).write_text(html_content, encoding="utf-8")

    # Cleanup
    Path(temp_graph_path).unlink(missing_ok=True)
