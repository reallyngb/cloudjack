from pathlib import Path
from cloudjack.loader import load_account
from cloudjack.graph import build_graph
from cloudjack.paths import find_paths
from cloudjack.remediate import generate_remediated_account

DATA_DIR = Path(__file__).parent.parent.parent / "data" / "scenarios"


def test_remediation_closes_path():
    account = load_account(DATA_DIR / "simple_escalation.json")
    
    # 1. Verify path exists initially
    graph = build_graph(account)
    target = "arn:aws:s3:::prod-data"
    start = "arn:aws:iam::123456789012:user/admin"
    paths = find_paths(graph, start, target)
    assert len(paths) == 1
    
    # 2. Remediate
    remediated_account = generate_remediated_account(account, paths[0])
    
    # 3. Verify path is closed
    new_graph = build_graph(remediated_account)
    new_paths = find_paths(new_graph, start, target)
    assert len(new_paths) == 0
