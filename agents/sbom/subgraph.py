"""Autonomous SBOM, AI-BOM, and Supply Chain LangGraph Subgraph.

Orchestrates multi-agent dependency cataloging, AST reachability analysis,
machine-readable OpenVEX document generation, and safe self-healing patch creation.
"""

import time
from typing import Dict, Any, List
from langgraph.graph import StateGraph, END
from agents.state import CyberSessionState, Evidence
from gateway.tool_gateway.gateway import tool_gateway
from storage.graph import InvestigationKnowledgeGraph
from tools.git_scanner import GitConnector
import structlog

logger = structlog.get_logger(__name__)


async def sbom_intake_node(state: CyberSessionState) -> Dict[str, Any]:
    """Intake node: scans local or remote Git repository from seed_ioc or workspace."""
    seed = state.get("seed_ioc", "").strip() or "cyber-agent"
    scan_res = GitConnector.scan_local_or_remote_repo(seed)
    target_repo = {
        "name": scan_res.project_name,
        "version": scan_res.project_version,
        "manifest": scan_res.manifest_content,
        "source_files": scan_res.source_files,
        "ai_assets": scan_res.ai_assets,
        "git_meta": scan_res.git_meta.model_dump()
    }

    return {
        "active_agent": "supply_chain_analyst",
        "iteration_count": state.get("iteration_count", 0) + 1,
        "target_repo": target_repo
    }


async def sbom_catalog_node(state: CyberSessionState) -> Dict[str, Any]:
    """Generates CycloneDX 1.6 SBOM and extracts AI-BOM model/tool assets."""
    target_repo = state.get("target_repo", {})
    manifest = target_repo.get("manifest", "")
    ai_assets = target_repo.get("ai_assets", [])

    sbom_res = await tool_gateway.execute_tool(
        "supply_chain_analyst",
        "generate_sbom",
        {
            "project_name": target_repo.get("name", "TargetRepo"),
            "project_version": target_repo.get("version", "1.0.0"),
            "manifest": manifest,
            "ai_assets": ai_assets
        }
    )

    new_evidence = list(state.get("evidence", []))
    if sbom_res.success and sbom_res.data:
        data = sbom_res.data
        new_evidence.append({
            "source": "CycloneDX 1.6 & AI-BOM Generator",
            "claim": f"Cataloged {data.get('total_components')} components and {data.get('total_ai_assets')} AI assets.",
            "raw_data": data.get("bom", {}),
            "confidence": 0.99,
            "timestamp": time.time()
        })

    return {
        "evidence": new_evidence,
        "sbom_data": sbom_res.data
    }


async def sbom_reachability_node(state: CyberSessionState) -> Dict[str, Any]:
    """Executes AST call-graph reachability triage."""
    target_repo = state.get("target_repo", {})
    source_files = target_repo.get("source_files") or target_repo.get("source_code", {})
    manifest = target_repo.get("manifest", "")

    # Parse packages dict: pkg -> version
    manifest_pkgs = {}
    for line in manifest.splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "==" in line:
            parts = line.split("==")
            manifest_pkgs[parts[0].strip()] = parts[1].strip()

    reach_res = await tool_gateway.execute_tool(
        "supply_chain_analyst",
        "analyze_reachability",
        {
            "manifest_packages": manifest_pkgs,
            "source_files": source_files
        }
    )

    reachability_results = reach_res.data.get("results", []) if reach_res.success else []
    
    new_evidence = list(state.get("evidence", []))
    reachable_cves = [r["cve_id"] for r in reachability_results if r.get("vex_status") == "affected"]
    unreachable_cves = [r["cve_id"] for r in reachability_results if r.get("vex_status") == "not_affected"]

    new_evidence.append({
        "source": "AST Call-Graph Reachability Engine",
        "claim": f"Reachability Triage: {len(reachable_cves)} reachable threats, {len(unreachable_cves)} unreachable (VEX candidate).",
        "raw_data": reachability_results,
        "confidence": 0.96,
        "timestamp": time.time()
    })

    return {
        "evidence": new_evidence,
        "reachability_results": reachability_results
    }


async def sbom_vex_synthesis_node(state: CyberSessionState) -> Dict[str, Any]:
    """Synthesizes compliant OpenVEX v0.2.0 and CSAF 2.0 documents."""
    target_repo = state.get("target_repo", {})
    reach_results = state.get("reachability_results", [])

    vex_res = await tool_gateway.execute_tool(
        "supply_chain_analyst",
        "generate_vex_document",
        {
            "project_name": target_repo.get("name", "TargetRepo"),
            "project_version": target_repo.get("version", "1.0.0"),
            "reachability_results": reach_results
        }
    )

    new_evidence = list(state.get("evidence", []))
    if vex_res.success and vex_res.data:
        d = vex_res.data
        new_evidence.append({
            "source": "OpenVEX & CSAF Synthesizer",
            "claim": f"Generated OpenVEX advisory: {d.get('noise_reduction_percentage')}% noise reduction, saved {d.get('estimated_triage_hours_saved')} triage hours.",
            "raw_data": d,
            "confidence": 0.98,
            "timestamp": time.time()
        })

    return {
        "evidence": new_evidence,
        "vex_summary": vex_res.data
    }


async def sbom_remediation_node(state: CyberSessionState) -> Dict[str, Any]:
    """Generates autonomous code refactoring and dependency bump patches."""
    target_repo = state.get("target_repo", {})
    reach_results = state.get("reachability_results", [])
    manifest = target_repo.get("manifest", "")
    source_files = target_repo.get("source_files") or target_repo.get("source_code", {})

    remediation_plans = []
    for r in reach_results:
        if r.get("vex_status") == "affected":
            rem_res = await tool_gateway.execute_tool(
                "supply_chain_analyst",
                "generate_remediation_patch",
                {
                    "reachability_result": r,
                    "manifest_text": manifest,
                    "source_files": source_files
                }
            )
            if rem_res.success and rem_res.data:
                remediation_plans.append(rem_res.data)

    return {"remediation_plans": remediation_plans}


async def sbom_correlator_node(state: CyberSessionState) -> Dict[str, Any]:
    """Attaches supply chain assets and reachability evidence to Knowledge Graph."""
    target_repo = state.get("target_repo", {})
    reach_results = state.get("reachability_results", [])
    kg = InvestigationKnowledgeGraph.from_dict(state.get("knowledge_graph", {}))

    repo_id = f"REPO:{target_repo.get('name', 'App')}"
    kg.add_node(
        node_id=repo_id,
        entity_type="SOFTWARE_REPOSITORY",
        label=target_repo.get("name", "App"),
        confidence=0.99,
        is_malicious=False,
        properties={"version": target_repo.get("version", "1.0.0")}
    )

    for r in reach_results:
        pkg_node_id = f"PKG:{r['package_name']}@{r['installed_version']}"
        kg.add_node(
            node_id=pkg_node_id,
            entity_type="DEPENDENCY_PACKAGE",
            label=f"{r['package_name']} ({r['installed_version']})",
            confidence=0.95,
            is_malicious=r["vex_status"] == "affected",
            properties={"reachability": r["reachability_verdict"], "vex_status": r["vex_status"]}
        )
        kg.add_edge(repo_id, pkg_node_id, "DEPENDS_ON", confidence=0.95)

        cve_id = r["cve_id"]
        kg.add_node(
            node_id=cve_id,
            entity_type="VULNERABILITY",
            label=f"{cve_id} ({r['severity']})",
            confidence=0.98,
            is_malicious=r["vex_status"] == "affected",
            properties={"cvss": r["cvss_score"], "epss": r["epss_score"]}
        )
        kg.add_edge(pkg_node_id, cve_id, "AFFECTED_BY", confidence=0.95)

    return {"knowledge_graph": kg.to_dict()}


# Build compiled LangGraph for SBOM & Supply Chain
sbom_builder = StateGraph(CyberSessionState)
sbom_builder.add_node("sbom_intake", sbom_intake_node)
sbom_builder.add_node("sbom_catalog", sbom_catalog_node)
sbom_builder.add_node("sbom_reachability", sbom_reachability_node)
sbom_builder.add_node("sbom_vex_synthesis", sbom_vex_synthesis_node)
sbom_builder.add_node("sbom_remediation", sbom_remediation_node)
sbom_builder.add_node("sbom_correlator", sbom_correlator_node)

sbom_builder.set_entry_point("sbom_intake")
sbom_builder.add_edge("sbom_intake", "sbom_catalog")
sbom_builder.add_edge("sbom_catalog", "sbom_reachability")
sbom_builder.add_edge("sbom_reachability", "sbom_vex_synthesis")
sbom_builder.add_edge("sbom_vex_synthesis", "sbom_remediation")
sbom_builder.add_edge("sbom_remediation", "sbom_correlator")
sbom_builder.add_edge("sbom_correlator", END)

sbom_subgraph = sbom_builder.compile()
