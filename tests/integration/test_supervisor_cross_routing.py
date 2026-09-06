"""Integration test for Multi-Agent Supervisor Cross-Subgraph Pivoting."""

import pytest
from agents.supervisor.agent import master_investigation_graph
from storage.graph import InvestigationKnowledgeGraph


@pytest.mark.asyncio
async def test_cross_subgraph_investigation_flow():
    """
    Validates end-to-end multi-agent orchestration:
    1. Seed C2 IP input: '185.220.101.45'
    2. Threat Hunt subgraph runs and extracts associated lookalike domain
    3. Supervisor identifies new DOMAIN entity and auto-routes to OSINT subgraph
    4. OSINT subgraph correlates infrastructure into the shared knowledge graph
    5. High-confidence containment action is safely staged for HITL review
    6. Final investigation report is synthesized
    """
    initial_state = {
        "messages": [],
        "investigation_id": "TEST-INV-001",
        "seed_ioc": "185.220.101.45",
        "active_agent": "threat_hunt",
        "iteration_count": 0,
        "hypotheses": [],
        "evidence": [],
        "knowledge_graph": {},
        "pivot_queue": [],
        "info_gain_history": [],
        "pending_actions": [],
        "hitl_status": "NONE",
        "final_report": None,
        "analyst_summary": None
    }

    final_state = await master_investigation_graph.ainvoke(initial_state)

    # 1. Verify report existence
    report = final_state.get("final_report")
    assert report is not None
    assert report["seed_ioc"] == "185.220.101.45"
    assert report["verdict"] == "CONFIRMED_MALICIOUS"

    # 2. Verify shared Knowledge Graph cross-domain correlations
    kg = InvestigationKnowledgeGraph.from_dict(final_state.get("knowledge_graph", {}))
    assert len(kg.nodes) >= 2, "Knowledge graph should contain IP, domain, and MITRE techniques"

    # Verify lookalike domain was ingested and linked
    assert any("update-microsoft-security.com" in n_id for n_id in kg.nodes.keys())

    # Verify MITRE technique mapping
    assert any("T1071" in m or "T1583" in m for m in report.get("mitre_attck_mappings", []))

    # 3. Verify Human-in-the-Loop containment gating
    pending = final_state.get("pending_actions", [])
    assert len(pending) > 0, "High-confidence malicious IP must stage HITL containment action"
    assert pending[0]["action"] == "BLOCK_IP"
    assert pending[0]["target"] == "185.220.101.45"
    assert pending[0]["status"] == "PENDING_APPROVAL"

