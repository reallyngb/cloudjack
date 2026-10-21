from pathlib import Path

from cloudjack.loader import load_account
from cloudjack.graph import build_graph
from cloudjack.paths import find_paths
from cloudjack.risk import score_path
from cloudjack.report import generate_html_report, generate_json_report

DATA_DIR = Path(__file__).parent.parent.parent / "data" / "scenarios"


def test_html_report_is_valid_utf8(tmp_path):
    account = load_account(DATA_DIR / "simple_escalation.json")
    graph = build_graph(account)
    start = "arn:aws:iam::123456789012:user/admin"
    target = "arn:aws:s3:::prod-data"
    paths = find_paths(graph, start, target)
    for p in paths:
        p.risk = score_path(p, account)

    out = tmp_path / "report.html"
    generate_html_report(account, graph, paths, str(out))

    # Must decode as UTF-8 without error
    content = out.read_text(encoding="utf-8")
    assert "CloudJack Attack Path Report" in content
    assert "arn:aws:s3:::prod-data" in content


def test_json_report_structure(tmp_path):
    account = load_account(DATA_DIR / "simple_escalation.json")
    graph = build_graph(account)
    start = "arn:aws:iam::123456789012:user/admin"
    target = "arn:aws:s3:::prod-data"
    paths = find_paths(graph, start, target)

    out = tmp_path / "findings.json"
    generate_json_report(paths, str(out))

    import json
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["tool"] == "CloudJack"
    assert len(data["findings"]) == 1
    assert data["findings"][0]["target_resource"] == "arn:aws:s3:::prod-data"
