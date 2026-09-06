"""Unit tests for Investigation Knowledge Graph."""

import pytest
from storage.graph import InvestigationKnowledgeGraph


def test_knowledge_graph_node_and_edge():
    """Verifies graph node and edge insertions and Cytoscape serialization."""
    kg = InvestigationKnowledgeGraph()

    # Add entities
    n1 = kg.add_node("185.220.101.45", "IP", confidence=0.90, is_malicious=True)
    n2 = kg.add_node("update-microsoft-security.com", "DOMAIN", confidence=0.85, is_malicious=True)

    # Add relationship
    e1 = kg.add_edge("update-microsoft-security.com", "185.220.101.45", "RESOLVES_TO", confidence=0.95)

    assert len(kg.nodes) == 2
    assert len(kg.edges) == 1
    assert n1["is_malicious"] is True

    # Check neighbors
    neighbors = kg.get_neighbors("update-microsoft-security.com")
    assert len(neighbors) == 1
    assert neighbors[0]["id"] == "185.220.101.45"

    # Verify Cytoscape export
    elements = kg.to_cytoscape_elements()
    assert len(elements) == 3  # 2 nodes + 1 edge
    node_elements = [el for el in elements if "source" not in el["data"]]
    assert len(node_elements) == 2


def test_knowledge_graph_contradiction_detection():
    """Verifies that contradictory verdicts on the same entity are flagged."""
    kg = InvestigationKnowledgeGraph()

    kg.add_node("test-domain.com", "DOMAIN", is_malicious=False)
    updated = kg.add_node("test-domain.com", "DOMAIN", is_malicious=True)

    assert updated.get("has_contradiction") is True

