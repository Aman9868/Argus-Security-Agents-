"""OSINT Investigation Subgraph (Domain Typosquatting, Cert Transparency, Identity Pivot)."""

import time
from typing import Dict, Any
from langgraph.graph import StateGraph, END
from agents.state import CyberSessionState, Evidence
from gateway.tool_gateway.gateway import tool_gateway
from storage.graph import InvestigationKnowledgeGraph
import structlog

logger = structlog.get_logger(__name__)


async def osint_intake_node(state: CyberSessionState) -> Dict[str, Any]:
    """OSINT intake node: selects next pivot target domain or identity from queue."""
    target_domain = None
    pivot_queue = list(state.get("pivot_queue", []))

    for item in pivot_queue:
        if item.get("type") == "DOMAIN":
            target_domain = item.get("value")
            break

    if not target_domain:
        seed = state.get("seed_ioc", "")
        target_domain = seed if "." in seed and not any(c.isdigit() for c in seed.split(".")[0]) else "update-microsoft-security.com"

    return {
        "active_agent": "osint_analyst",
        "iteration_count": state.get("iteration_count", 0) + 1,
        "current_pivot_target": target_domain
    }


async def osint_executor_node(state: CyberSessionState) -> Dict[str, Any]:
    """OSINT executor node: calls crt.sh, dnstwist, and sherlock under RBAC."""
    target_domain = state.get("current_pivot_target", "update-microsoft-security.com")
    new_evidence = list(state.get("evidence", []))

    # 1. Certificate transparency query
    crt_res = await tool_gateway.execute_tool("osint_analyst", "check_crtsh", {"domain": target_domain})
    if crt_res.success and crt_res.data:
        new_evidence.append({
            "source": "crt.sh Certificate Transparency",
            "claim": f"Discovered {crt_res.data.get('subdomain_count', 0)} subdomains for {target_domain}",
            "raw_data": crt_res.data,
            "confidence": 0.85,
            "timestamp": time.time()
        })

    # 2. dnstwist lookalike permutations
    dns_res = await tool_gateway.execute_tool("osint_analyst", "check_dnstwist", {"domain": target_domain})
    if dns_res.success and dns_res.data:
        new_evidence.append({
            "source": "dnstwist Lookalike Analysis",
            "claim": f"Identified {len(dns_res.data.get('active_threats', []))} active lookalike domains",
            "raw_data": dns_res.data,
            "confidence": 0.88,
            "timestamp": time.time()
        })

    # 3. RDAP Registration Intelligence
    rdap_res = await tool_gateway.execute_tool("osint_analyst", "check_rdap", {"target": target_domain})
    if rdap_res.success and rdap_res.data:
        new_evidence.append({
            "source": "RDAP Registration Intelligence",
            "claim": f"Registrar: {rdap_res.data.get('registrar')} (Domain Age: {rdap_res.data.get('domain_age_days')} days)",
            "raw_data": rdap_res.data,
            "confidence": 0.94 if rdap_res.data.get("is_newly_registered_domain") else 0.60,
            "timestamp": time.time()
        })

    return {"evidence": new_evidence}


async def osint_correlator_node(state: CyberSessionState) -> Dict[str, Any]:
    """OSINT correlator node: links OSINT artifacts into the unified Knowledge Graph."""
    target_domain = state.get("current_pivot_target", "update-microsoft-security.com")
    kg = InvestigationKnowledgeGraph.from_dict(state.get("knowledge_graph", {}))
    evidence = state.get("evidence", [])

    # Register target domain
    kg.add_node(
        target_domain,
        "DOMAIN",
        label=f"OSINT Target: {target_domain}",
        confidence=0.88,
        is_malicious=True
    )

    # Link dnstwist discoveries
    for ev in evidence:
        if ev.get("source") == "dnstwist Lookalike Analysis":
            threats = ev.get("raw_data", {}).get("active_threats", [])
            for t in threats:
                domain_name = t.get("domain")
                ip = t.get("ip")
                if domain_name:
                    kg.add_node(domain_name, "LOOKALIKE_DOMAIN", confidence=0.90, is_malicious=True)
                    kg.add_edge(target_domain, domain_name, "POTENTIAL_IMPERSONATION", confidence=0.85)
                    if ip:
                        kg.add_node(ip, "IP", confidence=0.90, is_malicious=True)
                        kg.add_edge(domain_name, ip, "RESOLVES_TO", confidence=0.95)

    # Link MITRE technique for Lookalike Domains (T1583.001)
    kg.add_node("T1583.001", "MITRE_TECHNIQUE", label="Acquire Domains (TypoSquatting)", confidence=0.90)
    kg.add_edge(target_domain, "T1583.001", "USES_TECHNIQUE", confidence=0.88)

    # Link RDAP Registrar and Domain Age
    for ev in evidence:
        if ev.get("source") == "RDAP Registration Intelligence":
            rdap = ev.get("raw_data", {})
            reg = rdap.get("registrar")
            if reg:
                kg.add_node(f"REGISTRAR:{reg}", "REGISTRAR", label=f"Registrar: {reg}", confidence=0.92)
                kg.add_edge(target_domain, f"REGISTRAR:{reg}", "REGISTERED_WITH", confidence=0.95)
            if rdap.get("is_newly_registered_domain"):
                kg.add_node("NRD:ALERT", "THREAT_INDICATOR", label="Newly Registered Domain (<30d)", confidence=0.95, is_malicious=True)
                kg.add_edge(target_domain, "NRD:ALERT", "EXHIBITS_INDICATOR", confidence=0.95)

    return {"knowledge_graph": kg.to_dict()}


# Build compiled LangGraph for OSINT
osint_builder = StateGraph(CyberSessionState)
osint_builder.add_node("osint_intake", osint_intake_node)
osint_builder.add_node("osint_executor", osint_executor_node)
osint_builder.add_node("osint_correlator", osint_correlator_node)

osint_builder.set_entry_point("osint_intake")
osint_builder.add_edge("osint_intake", "osint_executor")
osint_builder.add_edge("osint_executor", "osint_correlator")
osint_builder.add_edge("osint_correlator", END)

osint_subgraph = osint_builder.compile()

