import networkx as nx
from pathlib import Path
from cloudjack.loader import load_account
from cloudjack.graph import build_graph
from cloudjack.paths import find_paths

DATA_DIR = Path(__file__).parent.parent.parent / "data" / "scenarios"


def test_cycle_does_not_hang():
    """If role A trusts role B and B trusts A, pathfinding must still terminate."""
    account = load_account(DATA_DIR / "multi_hop_escalation.json")
    graph = build_graph(account)
    
    # Manually create a cycle: dev-ops-alice -> ec2-admin-role -> dev-ops-alice
    graph.add_edge("arn:aws:iam::123456789012:role/ec2-admin-role", "arn:aws:iam::123456789012:user/dev-ops-alice", action="test")
    
    # NetworkX will raise a NetworkXNoPath or find a simple path. It must not raise RecursionError.
    paths = find_paths(graph, "arn:aws:iam::123456789012:user/intern", "arn:aws:s3:::prod-data")
    assert len(paths) == 1


def test_unreachable_target():
    """If the target cannot be reached, return an empty list cleanly."""
    account = load_account(DATA_DIR / "multi_hop_escalation.json")
    graph = build_graph(account)
    
    # data-scientist-bob has no path to prod-data
    paths = find_paths(graph, "arn:aws:iam::123456789012:user/data-scientist-bob", "arn:aws:s3:::prod-data")
    assert len(paths) == 0


def test_missing_start_or_target():
    account = load_account(DATA_DIR / "multi_hop_escalation.json")
    graph = build_graph(account)
    
    # Non-existent start
    assert len(find_paths(graph, "arn:aws:iam::123:user/ghost", "arn:aws:s3:::prod-data")) == 0
    # Non-existent target
    assert len(find_paths(graph, "arn:aws:iam::123456789012:user/intern", "arn:aws:s3:::ghost")) == 0
