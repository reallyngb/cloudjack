"""Integration tests for the JSON and HTML report generators."""

from pathlib import Path
import json

from cloudjack.loader import load_account
from cloudjack.graph import build_graph
from cloudjack.paths import find_paths
from cloudjack.risk import score_path
from cloudjack.report import generate_html_report, generate_json_report

DATA_DIR = Path(__file__).parent.parent.parent / "data" / "scenarios"


def test_html_report_is_valid_utf8_and_contains_marker(tmp_path):
    """The HTML report must be valid UTF-8 and contain the expected marker string."""
    account = load_account(DATA_DIR / "multi_hop_escalation.json")
    graph = build_graph(account)
    start = "arn:aws:iam::123456789012:user/intern"
    target = "arn:aws:s3:::prod-data"
    paths = find_paths(graph, start, target)
    assert len(paths) == 1, "Test setup error: expected exactly 1 path"
    for p in paths:
        p.risk = score_path(p, account)

    out = tmp_path / "report.html"
    generate_html_report(account, graph, paths, str(out))

    content = out.read_text(encoding="utf-8")

    # The report must be HTML, not JSON
    assert content.lstrip().startswith("<!DOCTYPE html>"), (
        f"report.html did not start with <!DOCTYPE html>; "
        f"first 100 chars were: {content[:100]!r}"
    )
    assert "CloudJack Attack Path Report" in content
    assert "arn:aws:s3:::prod-data" in content
    # The attack path should be summarised in the evidence table
    assert "sts:AssumeRole" in content


def test_json_report_structure(tmp_path):
    """The JSON report must be a well-formed envelope with the findings inside."""
    account = load_account(DATA_DIR / "multi_hop_escalation.json")
    graph = build_graph(account)
    start = "arn:aws:iam::123456789012:user/intern"
    target = "arn:aws:s3:::prod-data"
    paths = find_paths(graph, start, target)
    for p in paths:
        p.risk = score_path(p, account)

    out = tmp_path / "findings.json"
    generate_json_report(paths, str(out))

    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["tool"] == "CloudJack"
    assert len(data["findings"]) == 1
    assert data["findings"][0]["target_resource"] == "arn:aws:s3:::prod-data"


def test_source_scenario_file_is_not_mutated(tmp_path):
    """Running the analysis pipeline must not modify the on-disk scenario JSON.

    This is a regression guard: the remediation engine used to mutate the
    original account in place, which would silently change what later tests
    (and later CLI runs) saw when they reloaded the same file.
    """
    scenario = DATA_DIR / "simple_escalation.json"
    before = scenario.read_bytes()

    account = load_account(scenario)
    graph = build_graph(account)
    paths = find_paths(
        graph,
        "arn:aws:iam::123456789012:user/admin",
        "arn:aws:s3:::prod-data",
    )
    for p in paths:
        p.risk = score_path(p, account)

    # Exercise the full report pipeline that historically mutated account state
    generate_html_report(account, graph, paths, str(tmp_path / "report.html"))
    generate_json_report(paths, str(tmp_path / "findings.json"))

    after = scenario.read_bytes()
    assert before == after, (
        "The on-disk scenario file was modified by the analysis pipeline. "
        "Investigate remediation.py / graph.py for in-place mutation of "
        "the loaded Account object."
    )
