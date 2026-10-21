"""Generate JSON and HTML reports from analysis results."""

import json
from pathlib import Path
from jinja2 import Template
import networkx as nx

from cloudjack.models import Account, AttackPath
from cloudjack.web.render import render_graph


def _read_text_with_fallback(path: Path) -> str:
    """Read a text file, trying several common encodings in order."""
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
        "findings": [path.model_dump() for path in paths],
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def generate_html_report(
    account: Account,
    graph: nx.DiGraph,
    paths: list[AttackPath],
    output_path: str,
) -> None:
    """Write an interactive HTML report."""
    template_path = Path(__file__).parent / "web" / "template.html"
    template = Template(_read_text_with_fallback(template_path))

    output_dir = Path(output_path).parent
    output_dir.mkdir(parents=True, exist_ok=True)
    temp_graph_path = output_dir / "_graph_temp.html"
    render_graph(graph, paths, str(temp_graph_path))

    graph_html = _read_text_with_fallback(temp_graph_path)

    path = paths[0] if paths else None

    html_content = template.render(
        start_identity=path.start_identity if path else "None found",
        target_resource=path.target_resource if path else "None found",
        confidence=path.confidence if path else "N/A",
        risk=path.risk if path else None,
        steps=path.steps if path else [],
        graph_html=graph_html,
    )

    # Defensive check: never write JSON to an HTML report path
    if not html_content.lstrip().startswith("<!DOCTYPE html>"):
        raise RuntimeError(
            f"generate_html_report produced non-HTML output. "
            f"First 100 chars: {html_content[:100]!r}"
        )

    Path(output_path).write_text(html_content, encoding="utf-8")
    temp_graph_path.unlink(missing_ok=True)
