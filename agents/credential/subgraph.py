"""Autonomous Credential & Secret Leaks Protection LangGraph Subgraph.

Orchestrates multi-agent secret detection, Git history diff scanning, AI reasoning on
exploitability & attack paths, Knowledge Graph entity correlation, and automated email
Human-in-the-Loop (HITL) dispatch.
"""

import time
import os
import json
from typing import Dict, Any, List
from langgraph.graph import StateGraph, END
from langchain_core.messages import AIMessage, HumanMessage
from agents.state import CyberSessionState, Evidence, Hypothesis, PendingAction
from gateway.tool_gateway.gateway import tool_gateway
from storage.graph import InvestigationKnowledgeGraph
from tools.git_scanner import GitConnector
import structlog

logger = structlog.get_logger(__name__)


async def credential_intake_node(state: CyberSessionState) -> Dict[str, Any]:
    """Intake node: Resolves target workspace directory or clones remote Git repository."""
    seed = state.get("seed_ioc", "").strip() or "cyber-agent"
    local_path, meta = GitConnector.clone_or_locate_repo(seed)

    target_repo = {
        "name": meta.name,
        "path": local_path,
        "is_git": meta.is_git,
        "branch": meta.branch,
        "commit_sha": meta.commit_sha,
        "remote_url": meta.remote_url
    }

    msg = AIMessage(content=f"Credential Analyst Agent: Initialized intake for repository '{meta.name}' at path '{local_path}'.")

    return {
        "active_agent": "credential_analyst",
        "iteration_count": state.get("iteration_count", 0) + 1,
        "target_repo": target_repo,
        "messages": [msg]
    }


async def credential_scan_node(state: CyberSessionState) -> Dict[str, Any]:
    """Executes high-speed regex, Shannon entropy, and git commit diff scanning via ToolGateway."""
    target_repo = state.get("target_repo", {})
    target_path = target_repo.get("path", "")
    recipient_email = state.get("recipient_email")

    res = await tool_gateway.execute_tool(
        "credential_analyst",
        "scan_credentials",
        {
            "target_path": target_path,
            "scan_git_history": True,
            "max_commits": 15,
            "ai_triage": True,
            "recipient_email": recipient_email
        }
    )

    findings = []
    summary = {}
    if res.success and res.data:
        summary = res.data.get("summary", {})
        findings = res.data.get("findings", [])

    new_evidence = list(state.get("evidence", []))
    new_evidence.append({
        "source": "Autonomous Credential Scanner",
        "claim": f"Scanned {summary.get('total_files_scanned', 0)} files & {summary.get('total_diffs_scanned', 0)} diffs; detected {len(findings)} potential credential exposures.",
        "raw_data": summary,
        "confidence": 0.98,
        "timestamp": time.time()
    })

    msg = AIMessage(content=f"Credential Analyst Agent: Scan complete. Detected {len(findings)} findings ({summary.get('critical_count', 0)} Critical, {summary.get('high_count', 0)} High).")

    return {
        "evidence": new_evidence,
        "credential_scan_result": summary,
        "credential_findings": findings,
        "messages": [msg]
    }


async def credential_reasoning_node(state: CyberSessionState) -> Dict[str, Any]:
    """AI reasoning: Formulates MITRE ATT&CK hypotheses and evaluates potential blast radius."""
    findings = state.get("credential_findings", [])
    target_repo = state.get("target_repo", {})
    hypotheses = list(state.get("hypotheses", []))

    for f in findings[:10]:
        sev = f.get("severity", "HIGH")
        rule = f.get("rule_name", "Unknown Secret")
        loc = f.get("file_path", "unknown")
        verdict = f.get("ai_verdict", "ACTIVE_EXPOSURE")

        # MITRE ATT&CK T1552 - Unsecured Credentials
        hyp_text = f"Exposed {rule} in '{loc}' permits unauthorized access and potential lateral movement."
        if verdict == "ACTIVE_EXPOSURE":
            status = "CONFIRMED"
            conf = 0.95
        elif verdict == "TEST_MOCK_FIXTURE":
            status = "REFUTED"
            conf = 0.85
        else:
            status = "UNTESTED"
            conf = 0.70

        hypotheses.append({
            "hypothesis": hyp_text,
            "mitre_technique": "T1552 - Unsecured Credentials",
            "status": status,
            "confidence": conf,
            "corroboration_count": 1
        })

    msg = AIMessage(content=f"Credential Analyst Agent: Formulated {len(hypotheses)} MITRE ATT&CK T1552 security hypotheses.")

    return {
        "hypotheses": hypotheses,
        "messages": [msg]
    }


async def credential_kg_correlator_node(state: CyberSessionState) -> Dict[str, Any]:
    """Correlates detected secrets, repositories, and cloud providers in Knowledge Graph."""
    target_repo = state.get("target_repo", {})
    findings = state.get("credential_findings", [])
    kg = InvestigationKnowledgeGraph.from_dict(state.get("knowledge_graph", {}))

    repo_name = target_repo.get("name", "TargetRepo")
    repo_node_id = f"REPO:{repo_name}"

    kg.add_node(
        node_id=repo_node_id,
        entity_type="SOFTWARE_REPOSITORY",
        label=repo_name,
        confidence=0.99,
        is_malicious=False,
        properties={"branch": target_repo.get("branch"), "commit": target_repo.get("commit_sha")}
    )

    for f in findings:
        cred_id = f"SECRET:{f.get('fingerprint', 'unknown')}"
        rule = f.get("rule_name", "Secret")
        cat = f.get("category", "Credential")
        sev = f.get("severity", "HIGH")

        kg.add_node(
            node_id=cred_id,
            entity_type="EXPOSED_SECRET",
            label=f"{rule} ({f.get('masked_value', '****')})",
            confidence=0.95,
            is_malicious=sev in ["CRITICAL", "HIGH"],
            properties={
                "category": cat,
                "severity": sev,
                "file_path": f.get("file_path"),
                "entropy": f.get("entropy_score")
            }
        )
        kg.add_edge(repo_node_id, cred_id, "EXPOSES", confidence=0.95)

        # Provider Node
        provider_name = cat.split()[0].upper()
        provider_id = f"PROVIDER:{provider_name}"
        kg.add_node(
            node_id=provider_id,
            entity_type="CLOUD_OR_SERVICE_PROVIDER",
            label=provider_name,
            confidence=0.90,
            is_malicious=False,
            properties={"category": cat}
        )
        kg.add_edge(cred_id, provider_id, "AUTHENTICATES_TO", confidence=0.95)

        # Author node if present in commit
        author = f.get("commit_author")
        if author:
            author_id = f"DEVELOPER:{author}"
            kg.add_node(
                node_id=author_id,
                entity_type="DEVELOPER_AUTHOR",
                label=author,
                confidence=0.90,
                is_malicious=False
            )
            kg.add_edge(author_id, cred_id, "COMMITTED", confidence=0.90)

    return {"knowledge_graph": kg.to_dict()}


async def credential_hitl_dispatch_node(state: CyberSessionState) -> Dict[str, Any]:
    """Generates HITL actions and dispatches automated security alert email."""
    findings = state.get("credential_findings", [])
    summary = state.get("credential_scan_result", {})
    target_repo = state.get("target_repo", {})
    recipient_email = state.get("recipient_email")

    pending_actions: List[PendingAction] = list(state.get("pending_actions", []))
    hitl_status = "NONE"
    email_delivery = None

    if findings:
        hitl_status = "PENDING"
        for f in findings[:10]:
            pending_actions.append({
                "action": "REVOKE_AND_ROTATE_SECRET",
                "target": f"{f.get('rule_name')} in {f.get('file_path')}",
                "confidence": 0.95,
                "policy_reason": "Mandatory Human Approval required under Secret Protection Governance.",
                "status": "PENDING_APPROVAL",
                "task_id": f.get("hitl_token", "")
            })

    if recipient_email and recipient_email.strip() and findings:
        email_res = await tool_gateway.execute_tool(
            "credential_analyst",
            "send_credential_hitl_email",
            {
                "recipient_email": recipient_email.strip(),
                "scan_id": summary.get("scan_id", "cscan_001"),
                "target_path": target_repo.get("path", ""),
                "target_type": "git_repository" if target_repo.get("is_git") else "local_directory",
                "total_findings": summary.get("total_findings", len(findings)),
                "critical_count": summary.get("critical_count", 0),
                "high_count": summary.get("high_count", 0),
                "medium_count": summary.get("medium_count", 0),
                "low_count": summary.get("low_count", 0),
                "findings": findings,
                "git_branch": target_repo.get("branch"),
                "git_commit": target_repo.get("commit_sha")
            }
        )
        if email_res.success:
            email_delivery = email_res.data

    msg = AIMessage(content=f"Credential Analyst Agent: Dispatched {len(pending_actions)} HITL containment review tasks. Automated email sent: {bool(email_delivery)}.")

    return {
        "pending_actions": pending_actions,
        "hitl_status": hitl_status,
        "credential_email_delivery": email_delivery,
        "messages": [msg]
    }


async def credential_synthesizer_node(state: CyberSessionState) -> Dict[str, Any]:
    """Produces the final executive security incident summary."""
    summary = state.get("credential_scan_result", {})
    findings = state.get("credential_findings", [])
    target_repo = state.get("target_repo", {})

    report = {
        "status": "COMPLETED",
        "agent": "credential_analyst",
        "repository": target_repo.get("name"),
        "total_leaks": len(findings),
        "critical": summary.get("critical_count", 0),
        "high": summary.get("high_count", 0),
        "hitl_status": state.get("hitl_status", "NONE"),
        "email_delivery": state.get("credential_email_delivery")
    }

    analyst_summary = (
        f"Autonomous Credential Analyst evaluated repository '{target_repo.get('name')}'. "
        f"Detected {len(findings)} credential exposures ({summary.get('critical_count', 0)} Critical). "
        f"Correlated into Threat Knowledge Graph and dispatched automated HITL review."
    )

    msg = AIMessage(content=f"Credential Analyst Agent: Final synthesis complete. {analyst_summary}")

    return {
        "final_report": report,
        "analyst_summary": analyst_summary,
        "messages": [msg]
    }


# ---------------------------------------------------------------------------
# Compile LangGraph Subgraph
# ---------------------------------------------------------------------------

credential_builder = StateGraph(CyberSessionState)
credential_builder.add_node("credential_intake", credential_intake_node)
credential_builder.add_node("credential_scan", credential_scan_node)
credential_builder.add_node("credential_reasoning", credential_reasoning_node)
credential_builder.add_node("credential_kg_correlator", credential_kg_correlator_node)
credential_builder.add_node("credential_hitl_dispatch", credential_hitl_dispatch_node)
credential_builder.add_node("credential_synthesizer", credential_synthesizer_node)

credential_builder.set_entry_point("credential_intake")
credential_builder.add_edge("credential_intake", "credential_scan")
credential_builder.add_edge("credential_scan", "credential_reasoning")
credential_builder.add_edge("credential_reasoning", "credential_kg_correlator")
credential_builder.add_edge("credential_kg_correlator", "credential_hitl_dispatch")
credential_builder.add_edge("credential_hitl_dispatch", "credential_synthesizer")
credential_builder.add_edge("credential_synthesizer", END)

credential_subgraph = credential_builder.compile()

