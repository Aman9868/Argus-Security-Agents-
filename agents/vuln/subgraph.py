"""Vulnerability Intelligence Subgraph (NVD CVE & CISA KEV Gating)."""

import time
from typing import Dict, Any
from langgraph.graph import StateGraph, END
from agents.state import CyberSessionState, Evidence
from gateway.tool_gateway.gateway import tool_gateway
from storage.graph import InvestigationKnowledgeGraph


async def vuln_intake_node(state: CyberSessionState) -> Dict[str, Any]:
    """Vuln intake node: extracts CVE ID."""
    cve_id = state.get("seed_ioc", "").upper()
    return {
        "active_agent": "vuln_analyst",
        "iteration_count": state.get("iteration_count", 0) + 1,
        "target_cve": cve_id
    }


async def vuln_query_node(state: CyberSessionState) -> Dict[str, Any]:
    """Queries NVD and CISA KEV catalog under RBAC."""
    cve_id = state.get("target_cve", "CVE-2023-34362")
    nvd_res = await tool_gateway.execute_tool("vuln_analyst", "check_nvd_cve", {"cve_id": cve_id})
    kev_res = await tool_gateway.execute_tool("vuln_analyst", "check_cisa_kev", {"cve_id": cve_id})

    new_evidence = list(state.get("evidence", []))
    if nvd_res.success and nvd_res.data:
        new_evidence.append({
            "source": "NVD Vulnerability Database",
            "claim": f"CVSS Score: {nvd_res.data.get('cvss_score')} ({nvd_res.data.get('severity')})",
            "raw_data": nvd_res.data,
            "confidence": 0.95,
            "timestamp": time.time()
        })

    if kev_res.success and kev_res.data:
        new_evidence.append({
            "source": "CISA Known Exploited Vulnerabilities",
            "claim": f"Actively Exploited: {kev_res.data.get('in_cisa_kev')}",
            "raw_data": kev_res.data,
            "confidence": 0.98,
            "timestamp": time.time()
        })

    return {"evidence": new_evidence}


async def vuln_correlator_node(state: CyberSessionState) -> Dict[str, Any]:
    """Correlator node: attaches vulnerability intelligence to Knowledge Graph."""
    cve_id = state.get("target_cve", "CVE-2023-34362")
    kg = InvestigationKnowledgeGraph.from_dict(state.get("knowledge_graph", {}))

    kg.add_node(
        node_id=cve_id,
        entity_type="VULNERABILITY",
        label=f"Exploit: {cve_id}",
        confidence=0.98,
        is_malicious=True,
        properties={"patch_priority": "CRITICAL"}
    )
    kg.add_node("T1190", "MITRE_TECHNIQUE", label="Exploit Public-Facing Application", confidence=0.95)
    kg.add_edge(cve_id, "T1190", "ENABLES_TECHNIQUE", confidence=0.95)

    return {"knowledge_graph": kg.to_dict()}


# Build compiled LangGraph for Vulnerabilities
vuln_builder = StateGraph(CyberSessionState)
vuln_builder.add_node("vuln_intake", vuln_intake_node)
vuln_builder.add_node("vuln_query", vuln_query_node)
vuln_builder.add_node("vuln_correlator", vuln_correlator_node)

vuln_builder.set_entry_point("vuln_intake")
vuln_builder.add_edge("vuln_intake", "vuln_query")
vuln_builder.add_edge("vuln_query", "vuln_correlator")
vuln_builder.add_edge("vuln_correlator", END)

vuln_subgraph = vuln_builder.compile()

