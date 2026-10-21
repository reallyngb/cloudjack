from pathlib import Path

from cloudjack.loader import load_account
from cloudjack.graph import build_graph
from cloudjack.paths import find_paths
from cloudjack.risk import score_path
from cloudjack.remediate import generate_remediated_account

DATA_DIR = Path(__file__).parent.parent.parent / "data" / "scenarios"


def test_multi_hop_escalation():
    """Verify that the engine can find a 2-step path: intern -> role -> resource."""
    account = load_account(DATA_DIR / "multi_hop_escalation.json")
    graph = build_graph(account)

    start = "arn:aws:iam::123456789012:user/intern"
    target = "arn:aws:s3:::prod-data"

    paths = find_paths(graph, start, target)
    
    # We expect exactly one path
    assert len(paths) == 1
    path = paths[0]

    # We expect 2 steps: AssumeRole, then direct access
    assert len(path.steps) == 2
    assert path.steps[0].action == "sts:AssumeRole"
    assert path.steps[0].source == start
    assert path.steps[0].target == "arn:aws:iam::123456789012:role/ec2-admin-role"
    
    assert path.steps[1].action == "access"
    assert path.steps[1].source == "arn:aws:iam::123456789012:role/ec2-admin-role"
    assert path.steps[1].target == target


def test_multi_hop_risk_scoring():
    """Verify risk scoring for a 2-step path."""
    account = load_account(DATA_DIR / "multi_hop_escalation.json")
    graph = build_graph(account)
    
    start = "arn:aws:iam::123456789012:user/intern"
    target = "arn:aws:s3:::prod-data"
    path = find_paths(graph, start, target)[0]
    
    # Score it
    risk = score_path(path, account)
    
    # Target sensitivity: 10 -> 50 points (max)
    assert risk.target_sensitivity == 50
    
    # Action severity: max(access=10, sts:AssumeRole=20) -> 20
    assert risk.action_severity == 20
    
    # Path length: 2 steps -> 15
    assert risk.path_length_penalty == 15
    
    # Total: 50 + 20 + 15 = 85
    assert risk.total == 85


def test_multi_hop_remediation():
    """Verify remediation removes the AssumeRole permission, breaking the path."""
    account = load_account(DATA_DIR / "multi_hop_escalation.json")
    graph = build_graph(account)
    
    start = "arn:aws:iam::123456789012:user/intern"
    target = "arn:aws:s3:::prod-data"
    path = find_paths(graph, start, target)[0]
    
    # Generate remediated account
    rem_account = generate_remediated_account(account, path)
    
    # Rebuild graph and find paths
    new_graph = build_graph(rem_account)
    new_paths = find_paths(new_graph, start, target)
    
    # The path should be closed
    assert len(new_paths) == 0
