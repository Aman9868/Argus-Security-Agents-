"""Cybersecurity Knowledge Graph Engine (In-Memory with Cytoscape/NetworkX compatibility)."""

from typing import Dict, Any, List, Optional
import time
import structlog

logger = structlog.get_logger(__name__)


class InvestigationKnowledgeGraph:
    """
    Stores cybersecurity entities, threat infrastructure correlations,
    and MITRE ATT&CK mappings in an interconnected graph.
    """

    def __init__(self):
        self.nodes: Dict[str, Dict[str, Any]] = {}
        self.edges: List[Dict[str, Any]] = []

    def add_node(
        self,
        node_id: str,
        entity_type: str,
        label: Optional[str] = None,
        confidence: float = 0.5,
        is_malicious: bool = False,
        properties: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Adds or updates an entity node in the knowledge graph."""
        clean_id = node_id.strip()
        existing = self.nodes.get(clean_id)

        node_data = {
            "id": clean_id,
            "type": entity_type.upper(),
            "label": label or clean_id,
            "confidence": max(confidence, existing.get("confidence", 0.0) if existing else 0.0),
            "is_malicious": is_malicious or (existing.get("is_malicious", False) if existing else False),
            "properties": {**(existing.get("properties", {}) if existing else {}), **(properties or {})},
            "updated_at": time.time()
        }

        # Check for contradictions
        if existing and existing.get("is_malicious") != is_malicious:
            logger.info("Knowledge Graph: Contradiction flagged for entity", entity=clean_id)
            node_data["has_contradiction"] = True

        self.nodes[clean_id] = node_data
        return node_data

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        relation: str,
        confidence: float = 0.8,
        properties: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Adds a relationship edge between two entities."""
        src = source_id.strip()
        dst = target_id.strip()

        edge_data = {
            "source": src,
            "target": dst,
            "relation": relation.upper(),
            "confidence": confidence,
            "properties": properties or {},
            "created_at": time.time()
        }

        # Avoid exact duplicate edges
        for existing in self.edges:
            if existing["source"] == src and existing["target"] == dst and existing["relation"] == relation.upper():
                existing.update(edge_data)
                return existing

        self.edges.append(edge_data)
        return edge_data

    def get_neighbors(self, node_id: str) -> List[Dict[str, Any]]:
        """Returns adjacent connected nodes."""
        clean_id = node_id.strip()
        neighbor_ids = set()
        for e in self.edges:
            if e["source"] == clean_id:
                neighbor_ids.add(e["target"])
            elif e["target"] == clean_id:
                neighbor_ids.add(e["source"])

        return [self.nodes[nid] for nid in neighbor_ids if nid in self.nodes]

    def to_cytoscape_elements(self) -> List[Dict[str, Any]]:
        """Exports graph elements into Cytoscape.js format for frontend visualization."""
        elements = []
        for nid, node in self.nodes.items():
            elements.append({
                "data": {
                    "id": nid,
                    "label": node["label"],
                    "type": node["type"],
                    "confidence": node["confidence"],
                    "malicious": node["is_malicious"]
                }
            })
        for idx, edge in enumerate(self.edges):
            elements.append({
                "data": {
                    "id": f"edge_{idx}_{edge['source']}_{edge['target']}",
                    "source": edge["source"],
                    "target": edge["target"],
                    "label": edge["relation"],
                    "confidence": edge["confidence"]
                }
            })
        return elements

    def to_dict(self) -> Dict[str, Any]:
        """Serializes knowledge graph to dictionary for LangGraph state."""
        return {
            "nodes": list(self.nodes.values()),
            "edges": self.edges,
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges)
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "InvestigationKnowledgeGraph":
        """Reconstructs knowledge graph from serialized dictionary."""
        graph = cls()
        for n in data.get("nodes", []):
            graph.nodes[n["id"]] = n
        graph.edges = list(data.get("edges", []))
        return graph

