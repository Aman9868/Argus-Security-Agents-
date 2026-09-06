"""Master Supervisor Graph: Orchestrates Cross-Subgraph Routing & Entity Loop-Backs."""

import json
import time
from typing import Dict, Any, Literal
from langgraph.graph import StateGraph, END
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from agents.state import CyberSessionState
from agents.threat_hunt.subgraph import threat_hunt_subgraph
from agents.osint.subgraph import osint_subgraph
from agents.phishing.subgraph import phishing_subgraph
from agents.vuln.subgraph import vuln_subgraph
from gateway.llm.client import llm_gateway
from gateway.llm.prompts import SUPERVISOR_SYSTEM_PROMPT
from storage.graph import InvestigationKnowledgeGraph
import structlog

logger = structlog.get_logger(__name__)


async def supervisor_router_node(state: CyberSessionState) -> Dict[str, Any]:
    """
    Supervisor node: analyzes accumulated state, queued pivots, and determines
    whether to continue in current subgraph, pivot to another domain, or synthesize report.
    """
    iteration = state.get("iteration_count", 0)
    pivot_queue = state.get("pivot_queue", [])
    seed = state.get("seed_ioc", "")

    # Check for un-investigated pivots
    messages = [
        SystemMessage(content=SUPERVISOR_SYSTEM_PROMPT),
        HumanMessage(content=f"Seed IOC: {seed}. Iteration: {iteration}. Pivots in queue: {json.dumps(pivot_queue)}.")
    ]

    resp = await llm_gateway.invoke(messages, model_tier="routing")
    try:
        decision = json.loads(resp.content)
        next_agent = decision.get("next_agent", "COMPLETE")
    except Exception:
        next_agent = "COMPLETE"

    # Algorithmic fallback if LLM is ambiguous:
    # 1. If we have a domain pivot from Threat Hunt that has not been OSINT'd yet
    if iteration <= 2 and any(p.get("type") == "DOMAIN" for p in pivot_queue):
        next_agent = "OSINT"
    # 2. If iteration >= 3, prevent infinite looping
    elif iteration >= 3:
        next_agent = "COMPLETE"

    logger.info("Supervisor: Routing decision made", next_agent=next_agent, iteration=iteration)

    return {
        "active_agent": next_agent.lower(),
        "messages": [AIMessage(content=f"Supervisor Routing: Dispatched investigation to [{next_agent}].")]
    }


def route_decision(state: CyberSessionState) -> Literal["threat_hunt", "osint", "phishing", "vuln", "synthesizer"]:
    """Conditional edge router based on supervisor active_agent."""
    agent = state.get("active_agent", "complete").lower()
    if "threat" in agent:
        return "threat_hunt"
    elif "osint" in agent:
        return "osint"
    elif "phish" in agent:
        return "phishing"
    elif "vuln" in agent:
        return "vuln"
    return "synthesizer"


async def supervisor_synthesizer_node(state: CyberSessionState) -> Dict[str, Any]:
    """Synthesizer node: produces the final unified incident report."""
    kg = InvestigationKnowledgeGraph.from_dict(state.get("knowledge_graph", {}))
    evidence = state.get("evidence", [])
    hypotheses = state.get("hypotheses", [])
    pending_actions = state.get("pending_actions", [])

    high_confidence_threats = [n for n in kg.nodes.values() if n.get("is_malicious")]
    mitre_nodes = [n for n in kg.nodes.values() if n.get("type") == "MITRE_TECHNIQUE"]

    # Map MITRE ATT&CK to MITRE D3FEND Countermeasures
    from tools.mitre import map_to_d3fend
    from tools.detection import generate_sigma_rule, generate_yara_rule, export_stix21_bundle

    d3fend_countermeasures = []
    seen_d3fend_ids = set()
    for m in mitre_nodes:
        cms = map_to_d3fend(m["id"])
        for cm in cms:
            if cm["id"] not in seen_d3fend_ids:
                seen_d3fend_ids.add(cm["id"])
                d3fend_countermeasures.append(cm)

    # Generate Sigma, YARA, and STIX 2.1 for malicious investigations
    seed_ioc = state.get("seed_ioc", "")
    ioc_type = "IP" if "." in seed_ioc and not any(c.isalpha() for c in seed_ioc) else "DOMAIN"
    sigma_res = generate_sigma_rule(
        title=f"Autonomous Defense for {seed_ioc}",
        ioc_type=ioc_type,
        ioc_value=seed_ioc,
        threat_description="Confirmed Adversary Infrastructure",
        mitre_technique=mitre_nodes[0]["id"] if mitre_nodes else "T1071.001"
    )
    yara_res = generate_yara_rule(
        rule_name=f"c2_{seed_ioc.replace('.', '_')}",
        ioc_value=seed_ioc
    )
    stix_res = export_stix21_bundle(
        investigation_id=state.get("investigation_id", f"INV-{int(time.time())}"),
        seed_ioc=seed_ioc,
        ioc_type=ioc_type,
        verdict="CONFIRMED_MALICIOUS" if high_confidence_threats else "BENIGN",
        mitre_technique=mitre_nodes[0]["id"] if mitre_nodes else "T1071.001"
    )

    report = {
        "investigation_id": state.get("investigation_id", f"INV-{int(time.time())}"),
        "seed_ioc": seed_ioc,
        "verdict": "CONFIRMED_MALICIOUS" if high_confidence_threats else "BENIGN",
        "confidence_score": max([h.get("confidence", 0.0) for h in hypotheses] + [0.5]),
        "total_entities_discovered": len(kg.nodes),
        "total_infrastructure_links": len(kg.edges),
        "mitre_attck_mappings": [m["id"] for m in mitre_nodes],
        "d3fend_countermeasures": d3fend_countermeasures,
        "sigma_rule": sigma_res.data.get("sigma_yaml") if sigma_res.success else None,
        "yara_rule": yara_res.data.get("yara_code") if yara_res.success else None,
        "stix_bundle": stix_res.data.get("stix_bundle") if stix_res.success else None,
        "key_findings": [e.get("claim") for e in evidence[:5]],
        "pending_containment_actions": pending_actions,
        "generated_at": time.time()
    }

    summary = (
        f"Investigation completed for IOC `{seed_ioc}`.\n"
        f"- Verdict: **{report['verdict']}** (Confidence: {report['confidence_score']:.2f})\n"
        f"- Correlated Entities: {report['total_entities_discovered']} nodes across {report['total_infrastructure_links']} edges\n"
        f"- MITRE ATT&CK: {', '.join(report['mitre_attck_mappings']) or 'None'}\n"
        f"- MITRE D3FEND Countermeasures: {', '.join([d['id'] + ' (' + d['name'] + ')' for d in d3fend_countermeasures[:2]]) or 'None'}\n"
        f"- Detection Rules: Sigma (YAML) & YARA generated\n"
        f"- Containment Status: {len(pending_actions)} action(s) pending SOC authorization."
    )

    return {
        "final_report": report,
        "analyst_summary": summary,
        "messages": [AIMessage(content=summary)]
    }


# Build Master Supervisor LangGraph
supervisor_builder = StateGraph(CyberSessionState)

# Add subgraphs as callable nodes
supervisor_builder.add_node("threat_hunt", threat_hunt_subgraph)
supervisor_builder.add_node("osint", osint_subgraph)
supervisor_builder.add_node("phishing", phishing_subgraph)
supervisor_builder.add_node("vuln", vuln_subgraph)
supervisor_builder.add_node("supervisor_router", supervisor_router_node)
supervisor_builder.add_node("synthesizer", supervisor_synthesizer_node)

# Flow: Initial evaluation -> Route to Subgraph -> Loop back to Router -> Synthesizer
supervisor_builder.set_entry_point("supervisor_router")

supervisor_builder.add_conditional_edges(
    "supervisor_router",
    route_decision,
    {
        "threat_hunt": "threat_hunt",
        "osint": "osint",
        "phishing": "phishing",
        "vuln": "vuln",
        "synthesizer": "synthesizer"
    }
)

# Loop-back: After any subgraph finishes, return to supervisor router to check new pivots!
supervisor_builder.add_edge("threat_hunt", "supervisor_router")
supervisor_builder.add_edge("osint", "supervisor_router")
supervisor_builder.add_edge("phishing", "supervisor_router")
supervisor_builder.add_edge("vuln", "supervisor_router")
supervisor_builder.add_edge("synthesizer", END)

master_investigation_graph = supervisor_builder.compile()

