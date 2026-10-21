"""Discover attack paths in the IAM graph."""

import networkx as nx
from cloudjack.models import AttackPath, AttackStep


def find_paths(G: nx.DiGraph, start_arn: str, target_arn: str) -> list[AttackPath]:
    """Find all simple paths from start_arn to target_arn."""
    if start_arn not in G or target_arn not in G:
        return []

    # For MVP, we just find the shortest path. 
    # Later versions can use nx.all_simple_paths to find all possible routes.
    try:
        node_path = nx.shortest_path(G, source=start_arn, target=target_arn)
    except nx.NetworkXNoPath:
        return []

    steps = []
    for i in range(len(node_path) - 1):
        source = node_path[i]
        target = node_path[i + 1]
        edge_data = G.get_edge_data(source, target)
        
        steps.append(AttackStep(
            source=source,
            action=edge_data.get("action", "unknown"),
            target=target,
            evidence=edge_data.get("evidence", "No evidence recorded")
        ))

    return [
        AttackPath(
            start_identity=start_arn,
            target_resource=target_arn,
            steps=steps,
            confidence="policy_supported"
        )
    ]
