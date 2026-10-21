from pathlib import Path
from cloudjack.loader import load_account
from cloudjack.graph import build_graph

DATA_DIR = Path(__file__).parent.parent.parent / "data" / "scenarios"


def test_multi_hop_graph_edges_are_exact():
    """
    Prove the graph engine generates exactly the edges defined in the JSON.
    If this test fails, a node or edge is missing or wrong.
    """
    account = load_account(DATA_DIR / "multi_hop_escalation.json")
    graph = build_graph(account)

    # The exact edges we expect based on the JSON policies and trust relations
    expected_edges = [
        # intern assumes ec2-admin-role
        ("arn:aws:iam::123456789012:user/intern", "arn:aws:iam::123456789012:role/ec2-admin-role", "sts:AssumeRole"),
        
        # ec2-admin-role accesses prod-data
        ("arn:aws:iam::123456789012:role/ec2-admin-role", "arn:aws:s3:::prod-data", "access"),
        
        # dev-ops-alice accesses dev-backups
        ("arn:aws:iam::123456789012:user/dev-ops-alice", "arn:aws:s3:::dev-backups", "access"),
        
        # data-scientist-bob accesses public-data
        ("arn:aws:iam::123456789012:user/data-scientist-bob", "arn:aws:s3:::public-data", "access"),
        
        # lambda-exec-role accesses cloudwatch-logs
        ("arn:aws:iam::123456789012:role/lambda-exec-role", "arn:aws:logs:::log-group", "access"),
    ]

    # Ensure every expected edge exists with the correct action
    for source, target, action in expected_edges:
        assert graph.has_edge(source, target), f"Missing edge: {source} -> {target}"
        edge_data = graph.get_edge_data(source, target)
        assert edge_data["action"] == action, f"Wrong action for {source} -> {target}: expected {action}, got {edge_data['action']}"

    # Ensure there are no *unexpected* edges (e.g., bob should NOT reach prod-data)
    assert not graph.has_edge("arn:aws:iam::123456789012:user/data-scientist-bob", "arn:aws:s3:::prod-data")
    assert not graph.has_edge("arn:aws:iam::123456789012:user/dev-ops-alice", "arn:aws:s3:::prod-data")
    assert not graph.has_edge("arn:aws:iam::123456789012:user/intern", "arn:aws:s3:::prod-data")
