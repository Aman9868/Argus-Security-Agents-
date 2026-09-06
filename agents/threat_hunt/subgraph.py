"""Threat Hunting & Threat Intelligence (TIP) Subgraph."""

import time
import json
from typing import Dict, Any
from langgraph.graph import StateGraph, END
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from agents.state import CyberSessionState, Hypothesis, Evidence, PendingAction
from gateway.tool_gateway.gateway import tool_gateway
from gateway.llm.client import llm_gateway
from gateway.llm.prompts import THREAT_HUNT_PLANNER_PROMPT
from storage.graph import InvestigationKnowledgeGraph
from policies.hitl import ContainmentPolicy
import structlog

logger = structlog.get_logger(__name__)


async def hunt_intake_node(state: CyberSessionState) -> Dict[str, Any]:
    """Intake node: normalizes IOC and seeds knowledge graph."""
    ioc = state.get("seed_ioc", "").strip()
    kg = InvestigationKnowledgeGraph.from_dict(state.get("knowledge_graph", {}))

    # Add seed entity
    kg.add_node(
        node_id=ioc,
        entity_type="IP" if "." in ioc and not any(c.isalpha() for c in ioc) else "DOMAIN",
        label=f"Target: {ioc}",
        confidence=0.5,
        properties={"role": "initial_seed"}
    )

    return {
        "active_agent": "threat_hunter",
        "iteration_count": state.get("iteration_count", 0) + 1,
        "knowledge_graph": kg.to_dict()
    }


async def hunt_planner_node(state: CyberSessionState) -> Dict[str, Any]:
    """Planner node: decides next hypothesis and threat intel query."""
    ioc = state.get("seed_ioc", "")
    messages = [
        SystemMessage(content=THREAT_HUNT_PLANNER_PROMPT),
        HumanMessage(content=f"Analyze IOC: '{ioc}'. Current evidence items: {len(state.get('evidence', []))}")
    ]

    resp = await llm_gateway.invoke(messages, model_tier="routing")
    try:
        plan = json.loads(resp.content)
    except Exception:
        plan = {
            "hypothesis": f"IOC {ioc} exhibits malicious C2 behavior.",
            "mitre_technique": "T1071",
            "tool_to_call": "check_virustotal",
            "tool_parameters": {"ioc": ioc}
        }

    hypothesis: Hypothesis = {
        "hypothesis": plan.get("hypothesis", ""),
        "mitre_technique": plan.get("mitre_technique", "T1071"),
        "status": "UNTESTED",
        "confidence": 0.5,
        "corroboration_count": 0
    }

    current_hypotheses = list(state.get("hypotheses", []))
    current_hypotheses.append(hypothesis)

    return {
        "hypotheses": current_hypotheses,
        "messages": [AIMessage(content=f"Formulated hypothesis: {hypothesis['hypothesis']}")],
    }


async def hunt_tool_executor_node(state: CyberSessionState) -> Dict[str, Any]:
    """Tool executor: queries external threat intel through central ToolGateway."""
    ioc = state.get("seed_ioc", "")

    # Execute VirusTotal, OTX, GeoIP, and Port Enumeration under RBAC
    vt_res = await tool_gateway.execute_tool("threat_hunter", "check_virustotal", {"ioc": ioc})
    otx_res = await tool_gateway.execute_tool("threat_hunter", "check_otx", {"ioc": ioc})
    mitre_res = await tool_gateway.execute_tool("threat_hunter", "map_to_mitre", {"query_or_tag": "c2 cobalt strike"})
    geo_res = await tool_gateway.execute_tool("threat_hunter", "check_geoip", {"ioc": ioc})
    port_res = await tool_gateway.execute_tool("threat_hunter", "scan_ports", {"ioc": ioc, "mode": "passive"})

    new_evidence = list(state.get("evidence", []))
    if vt_res.success and vt_res.data:
        new_evidence.append({
            "source": "VirusTotal",
            "claim": f"Malicious detection count: {vt_res.data.get('malicious_votes', 0)}",
            "raw_data": vt_res.data,
            "confidence": 0.90 if vt_res.data.get("malicious_votes", 0) > 10 else 0.40,
            "timestamp": time.time()
        })

    if otx_res.success and otx_res.data:
        new_evidence.append({
            "source": "AlienVault OTX",
            "claim": f"Associated with {otx_res.data.get('pulse_count', 0)} threat pulses",
            "raw_data": otx_res.data,
            "confidence": 0.85,
            "timestamp": time.time()
        })

    if geo_res.success and geo_res.data:
        new_evidence.append({
            "source": "GeoIP & ASN Intelligence",
            "claim": f"Located in {geo_res.data.get('country')} via {geo_res.data.get('asn')}",
            "raw_data": geo_res.data,
            "confidence": 0.88,
            "timestamp": time.time()
        })

    if port_res.success and port_res.data:
        new_evidence.append({
            "source": "Port Enumeration",
            "claim": f"Exposed ports: {len(port_res.data.get('ports', []))} (C2 Listener: {port_res.data.get('has_c2_listeners', False)})",
            "raw_data": port_res.data,
            "confidence": 0.92 if port_res.data.get("has_c2_listeners") else 0.50,
            "timestamp": time.time()
        })

    return {"evidence": new_evidence}


async def hunt_correlator_node(state: CyberSessionState) -> Dict[str, Any]:
    """Correlator node: merges evidence into knowledge graph and checks contradictions."""
    ioc = state.get("seed_ioc", "")
    kg = InvestigationKnowledgeGraph.from_dict(state.get("knowledge_graph", {}))
    evidence = state.get("evidence", [])
    pivot_queue = list(state.get("pivot_queue", []))

    total_confidence = 0.0
    is_malicious = False
    for ev in evidence:
        total_confidence = max(total_confidence, ev.get("confidence", 0.0))
        raw = ev.get("raw_data", {})
        if raw.get("malicious_votes", 0) > 5 or raw.get("pulse_count", 0) > 0:
            is_malicious = True

        # Extract newly discovered domain pivot from OTX
        assoc_domain = raw.get("associated_domain")
        if assoc_domain and not any(p.get("value") == assoc_domain for p in pivot_queue):
            pivot_queue.append({"type": "DOMAIN", "value": assoc_domain, "source_ioc": ioc})
            # Add to graph
            kg.add_node(assoc_domain, "DOMAIN", label=f"Discovered: {assoc_domain}", confidence=0.85, is_malicious=True)
            kg.add_edge(assoc_domain, ioc, "RESOLVES_TO", confidence=0.90)

    # Update seed node in Knowledge Graph
    kg.add_node(
        node_id=ioc,
        entity_type="IP",
        confidence=total_confidence,
        is_malicious=is_malicious,
        properties={"evidence_items": len(evidence)}
    )

    # Link MITRE technique
    kg.add_node("T1071.001", "MITRE_TECHNIQUE", label="Web Protocols (C2)", confidence=0.95)
    kg.add_edge(ioc, "T1071.001", "USES_TECHNIQUE", confidence=0.90)

    # Link GeoIP, ASN, and Ports from evidence
    for ev in evidence:
        if ev.get("source") == "GeoIP & ASN Intelligence":
            geo = ev.get("raw_data", {})
            country = geo.get("country")
            asn = geo.get("asn")
            if country:
                kg.add_node(f"GEO:{country}", "GEOLOCATION", label=f"Origin: {country}", confidence=0.90)
                kg.add_edge(ioc, f"GEO:{country}", "LOCATED_IN", confidence=0.90)
            if asn:
                asn_str = str(asn).strip()
                asn_id = asn_str.split()[0] if asn_str else "UNKNOWN"
                kg.add_node(f"ASN:{asn_id}", "ASN", label=f"BGP: {asn_str}", confidence=0.92)
                kg.add_edge(ioc, f"ASN:{asn_id}", "ROUTED_BY", confidence=0.95)
        elif ev.get("source") == "Port Enumeration":
            port_data = ev.get("raw_data", {})
            for p in port_data.get("ports", []):
                port_num = p["port"] if isinstance(p, dict) else int(p)
                service_name = p.get("service", "TCP") if isinstance(p, dict) else "Open Port"
                port_id = f"PORT:{port_num}/TCP"
                is_c2_port = port_num in [4444, 50050]
                kg.add_node(port_id, "OPEN_PORT", label=f"{port_num}/TCP ({service_name})", confidence=0.95, is_malicious=is_c2_port)
                kg.add_edge(ioc, port_id, "EXPOSES_PORT", confidence=0.95)

    # Update hypothesis status
    hypotheses = list(state.get("hypotheses", []))
    if hypotheses:
        hypotheses[-1]["status"] = "CONFIRMED" if is_malicious else "REFUTED"
        hypotheses[-1]["confidence"] = total_confidence
        hypotheses[-1]["corroboration_count"] = len(evidence)

    return {
        "knowledge_graph": kg.to_dict(),
        "hypotheses": hypotheses,
        "pivot_queue": pivot_queue
    }


async def hunt_hitl_gate_node(state: CyberSessionState) -> Dict[str, Any]:
    """Human-in-the-Loop safety gate: stages containment action if threshold exceeded."""
    ioc = state.get("seed_ioc", "")
    hypotheses = state.get("hypotheses", [])
    confidence = hypotheses[-1].get("confidence", 0.0) if hypotheses else 0.0

    pending = list(state.get("pending_actions", []))
    hitl_status = state.get("hitl_status", "NONE")

    if confidence >= 0.75 and not any(p.get("target") == ioc for p in pending):
        requires_approval, reason = ContainmentPolicy.evaluate_containment_request("BLOCK_IP", ioc, confidence)
        if requires_approval:
            action: PendingAction = {
                "action": "BLOCK_IP",
                "target": ioc,
                "confidence": confidence,
                "policy_reason": reason,
                "status": "PENDING_APPROVAL",
                "task_id": f"HITL-{int(time.time())}"
            }
            pending.append(action)
            hitl_status = "PENDING"
            logger.info("ThreatHunt: Staged containment action requiring HITL approval", target=ioc)

    return {
        "pending_actions": pending,
        "hitl_status": hitl_status
    }


# Build compiled LangGraph for Threat Hunt
threat_hunt_builder = StateGraph(CyberSessionState)
threat_hunt_builder.add_node("hunt_intake", hunt_intake_node)
threat_hunt_builder.add_node("hunt_planner", hunt_planner_node)
threat_hunt_builder.add_node("hunt_tool_executor", hunt_tool_executor_node)
threat_hunt_builder.add_node("hunt_correlator", hunt_correlator_node)
threat_hunt_builder.add_node("hunt_hitl_gate", hunt_hitl_gate_node)

threat_hunt_builder.set_entry_point("hunt_intake")
threat_hunt_builder.add_edge("hunt_intake", "hunt_planner")
threat_hunt_builder.add_edge("hunt_planner", "hunt_tool_executor")
threat_hunt_builder.add_edge("hunt_tool_executor", "hunt_correlator")
threat_hunt_builder.add_edge("hunt_correlator", "hunt_hitl_gate")
threat_hunt_builder.add_edge("hunt_hitl_gate", END)

threat_hunt_subgraph = threat_hunt_builder.compile()

