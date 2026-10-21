"""Render an interactive IAM graph using pyvis."""

import networkx as nx
from pyvis.network import Network
from cloudjack.models import AttackPath


def render_graph(G: nx.DiGraph, paths: list[AttackPath], output_path: str) -> None:
    """Generate an interactive HTML graph highlighting the attack path."""
    net = Network(height="600px", width="100%", bgcolor="#1e1e1e", font_color="white", directed=True)

    # Highlighted nodes/edges from the first attack path
    path_nodes = set()
    path_edges = set()
    
    if paths:
        # For MVP, we only highlight the first found path visually
        path = paths[0]
        for step in path.steps:
            path_nodes.add(step.source)
            path_nodes.add(step.target)
            path_edges.add((step.source, step.target))

    # Add nodes
    for node_id, data in G.nodes(data=True):
        node_type = data.get("type", "unknown")
        label = data.get("name", node_id.split(":")[-1])
        
        # Base styling
        color = "#4a90e2"  # Blue
        shape = "dot"
        size = 20
        
        if node_type == "resource":
            color = "#50e3c2"  # Green
            shape = "box"
            size = 25
        elif node_type == "role":
            color = "#f5a623"  # Orange

        # Attack path styling
        if node_id in path_nodes:
            color = "#ff4d4d"  # Red
            size = 30
            if node_type == "resource":
                shape = "box"

        net.add_node(
            node_id,
            label=label,
            title=f"Type: {node_type}\nARN: {node_id}",
            color=color,
            shape=shape,
            size=size,
        )

    # Add edges
    for source, target, data in G.edges(data=True):
        action = data.get("action", "")
        color = "#666666"  # Grey default
        width = 1
        
        if (source, target) in path_edges:
            color = "#ff4d4d"
            width = 3
            
        net.add_edge(source, target, title=action, color=color, width=width)

    # Configure physics for a clean layout
    net.set_options("""
    var options = {
      "physics": {
        "barnesHut": {
          "gravitationalConstant": -8000,
          "springLength": 200
        },
        "minVelocity": 0.75
      }
    }
    """)
    
    # Save to file
    net.save_graph(output_path)
