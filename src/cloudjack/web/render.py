"""Render an interactive IAM graph using pyvis."""

import networkx as nx
from pyvis.network import Network
from cloudjack.models import AttackPath


def render_graph(G: nx.DiGraph, paths: list[AttackPath], output_path: str) -> None:
    """Generate an interactive HTML graph highlighting the attack path."""
    
    net = Network(
        height="100%", 
        width="100%", 
        bgcolor="#1e1e1e", 
        font_color="#ffffff", 
        directed=True
    )

    path_nodes = set()
    path_edges = set()
    
    if paths:
        path = paths[0]
        for step in path.steps:
            path_nodes.add(step.source)
            path_nodes.add(step.target)
            path_edges.add((step.source, step.target))

    for node_id, data in G.nodes(data=True):
        node_type = data.get("type", "unknown")
        label = data.get("name", node_id.split(":")[-1])
        
        color = "#4a90e2"  # User (Blue)
        shape = "dot"
        size = 25
        border_width = 2
        
        if node_type == "resource":
            color = "#50e3c2"  # Resource (Green)
            shape = "box"
            size = 30
        elif node_type == "role":
            color = "#f5a623"  # Role (Orange)
            shape = "hexagon"
            size = 25

        if node_id in path_nodes:
            color = "#ff4d4d"  # Attack Path (Red)
            border_width = 4
            size = 35
            if node_type == "resource":
                shape = "box"
                
        net.add_node(
            node_id,
            label=label,
            title=f"Type: {node_type}\nARN: {node_id}",
            color={
                "background": color,
                "border": "#ffffff" if node_id in path_nodes else color,
                "highlight": {"background": color, "border": "#ffffff"}
            },
            shape=shape,
            size=size,
            borderWidth=border_width,
            font={"size": 16, "color": "#ffffff", "face": "Arial"},
            shadow={"enabled": True, "color": "rgba(0,0,0,0.5)", "size": 10}
        )

    for source, target, data in G.edges(data=True):
        action = data.get("action", "")
        color = "#555555"
        width = 2
        dashes = False
        
        if (source, target) in path_edges:
            color = "#ff4d4d"
            width = 4
            dashes = [5, 5]
            
        net.add_edge(
            source, 
            target, 
            title=action, 
            color=color, 
            width=width,
            dashes=dashes,
            arrows="to"
        )

    # Tight physics so nodes stay large and grouped in the center
    net.set_options("""
    var options = {
      "nodes": {
        "font": { "size": 16, "face": "Arial", "color": "#ffffff" }
      },
      "edges": {
        "smooth": { "type": "curvedCW", "roundness": 0.2 }
      },
      "physics": {
        "barnesHut": {
          "gravitationalConstant": -2000,
          "centralGravity": 0.1,
          "springLength": 100,
          "springConstant": 0.04
        },
        "stabilization": { "iterations": 200 }
      },
      "interaction": {
        "navigationButtons": true,
        "keyboard": true
      }
    }
    """)
    
    net.save_graph(output_path)
    
    # Force the iframe content to be full width/height and dark mode
    with open(output_path, "r", encoding="utf-8") as f:
        html = f.read()
        
    # Inject CSS to remove margins and set dark background on the inner document
    css_injection = """
    <style>
        body { background-color: #1e1e1e !important; margin: 0; padding: 0; overflow: hidden; }
        #mynetwork { width: 100vw; height: 100vh; background-color: #1e1e1e; border: none; }
    </style>
    """
    html = html.replace("</head>", f"{css_injection}</head>")
    
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
