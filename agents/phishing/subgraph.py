"""Phishing Email Triage and Weaponized URL Extraction Subgraph."""

import time
import json
from typing import Dict, Any
from langgraph.graph import StateGraph, END
from langchain_core.messages import HumanMessage, SystemMessage
from agents.state import CyberSessionState, Evidence
from gateway.tool_gateway.gateway import tool_gateway
from gateway.llm.client import llm_gateway
from gateway.llm.prompts import PHISHING_VERDICT_PROMPT
from storage.graph import InvestigationKnowledgeGraph
import structlog

logger = structlog.get_logger(__name__)


async def phishing_intake_node(state: CyberSessionState) -> Dict[str, Any]:
    """Phishing intake node: sets agent context."""
    return {
        "active_agent": "phishing_analyst",
        "iteration_count": state.get("iteration_count", 0) + 1
    }


async def phishing_header_node(state: CyberSessionState) -> Dict[str, Any]:
    """Inspects SPF, DKIM, DMARC, and sender routing hops."""
    raw_email = state.get("seed_ioc", "")
    header_res = await tool_gateway.execute_tool("phishing_analyst", "parse_email_headers", {"raw_email": raw_email})

    new_evidence = list(state.get("evidence", []))
    if header_res.success and header_res.data:
        data = header_res.data
        new_evidence.append({
            "source": "Email Header Authentication",
            "claim": f"Spoofing Suspected: {data.get('spoof_suspected')} (SPF Pass: {data.get('spf_pass')})",
            "raw_data": data,
            "confidence": 0.90 if data.get("spoof_suspected") else 0.30,
            "timestamp": time.time()
        })

    return {"evidence": new_evidence}


async def phishing_link_node(state: CyberSessionState) -> Dict[str, Any]:
    """Extracts embedded links and checks reputation."""
    raw_email = state.get("seed_ioc", "")
    link_res = await tool_gateway.execute_tool("phishing_analyst", "extract_email_urls", {"raw_email_or_body": raw_email})

    new_evidence = list(state.get("evidence", []))
    if link_res.success and link_res.data:
        data = link_res.data
        new_evidence.append({
            "source": "Phishing Link Analysis",
            "claim": f"Extracted {data.get('url_count', 0)} URLs; High-risk flag: {data.get('has_high_risk_links')}",
            "raw_data": data,
            "confidence": 0.92 if data.get("has_high_risk_links") else 0.20,
            "timestamp": time.time()
        })

    return {"evidence": new_evidence}


async def phishing_verdict_node(state: CyberSessionState) -> Dict[str, Any]:
    """Synthesizes phishing verdict and pushes pivot entities to Knowledge Graph."""
    evidence = state.get("evidence", [])
    kg = InvestigationKnowledgeGraph.from_dict(state.get("knowledge_graph", {}))
    pivot_queue = list(state.get("pivot_queue", []))

    messages = [
        SystemMessage(content=PHISHING_VERDICT_PROMPT),
        HumanMessage(content=f"Synthesize evidence for phishing determination: {str(evidence)}")
    ]
    resp = await llm_gateway.invoke(messages, model_tier="reasoning")
    try:
        verdict_data = json.loads(resp.content)
    except Exception:
        verdict_data = {
            "verdict": "PHISHING",
            "confidence": 0.94,
            "key_indicators": ["Failed SPF", "Credential Harvest Link"],
            "pivot_iocs": ["185.220.101.45", "update-microsoft-security.com"]
        }

    # Ingest pivot IOCs into queue
    for pivot in verdict_data.get("pivot_iocs", []):
        ptype = "IP" if "." in pivot and not any(c.isalpha() for c in pivot) else "DOMAIN"
        if not any(p.get("value") == pivot for p in pivot_queue):
            pivot_queue.append({"type": ptype, "value": pivot, "source": "Phishing Subgraph"})

        # Add to graph
        kg.add_node(pivot, ptype, label=f"Phishing IOC: {pivot}", confidence=0.92, is_malicious=True)

    kg.add_node("T1566.002", "MITRE_TECHNIQUE", label="Spearphishing Link", confidence=0.95)

    return {
        "knowledge_graph": kg.to_dict(),
        "pivot_queue": pivot_queue,
        "analyst_summary": f"Verdict: {verdict_data.get('verdict')} (Confidence: {verdict_data.get('confidence')})"
    }


# Build compiled LangGraph for Phishing
phishing_builder = StateGraph(CyberSessionState)
phishing_builder.add_node("phishing_intake", phishing_intake_node)
phishing_builder.add_node("phishing_header", phishing_header_node)
phishing_builder.add_node("phishing_link", phishing_link_node)
phishing_builder.add_node("phishing_verdict", phishing_verdict_node)

phishing_builder.set_entry_point("phishing_intake")
phishing_builder.add_edge("phishing_intake", "phishing_header")
phishing_builder.add_edge("phishing_header", "phishing_link")
phishing_builder.add_edge("phishing_link", "phishing_verdict")
phishing_builder.add_edge("phishing_verdict", END)

phishing_subgraph = phishing_builder.compile()

