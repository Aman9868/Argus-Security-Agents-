"""Utility script to generate and export all LangGraph architecture diagrams.

Usage:
    python scripts/generate_graphs.py
"""

import sys
import os
from pathlib import Path

# Ensure cyber-agent root takes absolute priority in sys.path
root_dir = Path(__file__).resolve().parent.parent
if str(root_dir) in sys.path:
    sys.path.remove(str(root_dir))
sys.path.insert(0, str(root_dir))

# Evict any cached agents modules from other workspaces
for mod in list(sys.modules.keys()):
    if mod.startswith("agents") or mod.startswith("gateway") or mod.startswith("tools") or mod.startswith("storage"):
        del sys.modules[mod]

from agents.supervisor.agent import master_investigation_graph, supervisor_builder
from agents.threat_hunt.subgraph import threat_hunt_subgraph
from agents.osint.subgraph import osint_subgraph
from agents.phishing.subgraph import phishing_subgraph
from agents.vuln.subgraph import vuln_subgraph


def export_graphs():
    output_dir = root_dir / "docs" / "graphs"
    output_dir.mkdir(parents=True, exist_ok=True)

    app = master_investigation_graph

    print("Generating full expanded master graph (xray=True)...")
    try:
        expanded_png = app.get_graph(xray=True).draw_mermaid_png()
        (output_dir / "cyber_graph_full.png").write_bytes(expanded_png)
        (output_dir / "cyber_graph_full_expanded.png").write_bytes(expanded_png)
        (root_dir / "cyber_graph.png").write_bytes(expanded_png)
        print("  ✓ cyber_graph_full.png saved")
    except Exception as e:
        print("  ✗ Failed to draw expanded graph:", e)

    print("Generating high-level supervisor overview (xray=False)...")
    try:
        overview_png = app.get_graph(xray=False).draw_mermaid_png()
        (output_dir / "supervisor_overview.png").write_bytes(overview_png)
        print("  ✓ supervisor_overview.png saved")
    except Exception as e:
        print("  ✗ Failed to draw supervisor overview:", e)

    # Subgraphs
    subgraphs = {
        "threat_hunt_subgraph.png": threat_hunt_subgraph,
        "osint_subgraph.png": osint_subgraph,
        "phishing_subgraph.png": phishing_subgraph,
        "vuln_subgraph.png": vuln_subgraph,
    }

    for filename, sg in subgraphs.items():
        print(f"Generating {filename}...")
        try:
            sg_png = sg.get_graph().draw_mermaid_png()
            (output_dir / filename).write_bytes(sg_png)
            print(f"  ✓ {filename} saved")
        except Exception as e:
            print(f"  ✗ Failed to draw {filename}:", e)

    # Also export Mermaid source files (.mmd) for documentation
    print("Exporting Mermaid definitions (.mmd)...")
    try:
        (output_dir / "cyber_graph_full.mmd").write_text(app.get_graph(xray=True).draw_mermaid())
        (output_dir / "supervisor_overview.mmd").write_text(app.get_graph(xray=False).draw_mermaid())
        for filename, sg in subgraphs.items():
            mmd_name = filename.replace(".png", ".mmd")
            (output_dir / mmd_name).write_text(sg.get_graph().draw_mermaid())
        print("  ✓ Mermaid source files exported")
    except Exception as e:
        print("  ✗ Failed to export Mermaid source:", e)

    print("\nAll LangGraph architecture diagrams successfully updated in docs/graphs/")


if __name__ == "__main__":
    export_graphs()
