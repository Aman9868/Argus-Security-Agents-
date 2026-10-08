"""FastAPI Router for Credential Leaks Sentinel, Automated Email Alerting, and HITL."""

import os
import time
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, HTTPException, Query, status
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field, EmailStr
from langchain_core.messages import HumanMessage
import structlog

from tools.credential_scanner import CredentialScanner, CredentialScanResult
from tools.git_scanner import GitConnector
from services.email_service import EmailService
from agents.credential.subgraph import credential_subgraph
import storage.db as db

logger = structlog.get_logger(__name__)
router = APIRouter(prefix="/credentials", tags=["Credential Leaks Sentinel"])


# ---------------------------------------------------------------------------
# Request & Response Schemas
# ---------------------------------------------------------------------------

class CredentialScanRequest(BaseModel):
    target_path_or_url: str = Field(..., description="Workspace folder name, local path, or remote Git clone URL")
    recipient_email: Optional[str] = Field(None, description="Recipient email address for automated alert and HITL review")
    branch: Optional[str] = Field(None, description="Optional Git branch to scan")
    scan_git_history: bool = Field(True, description="Whether to inspect git commit diffs")
    max_commits: int = Field(15, ge=1, le=50, description="Number of recent commit diffs to analyze")
    ai_triage: bool = Field(True, description="Leverage LLM for false-positive filtering")


class CredentialReviewRequest(BaseModel):
    finding_id: str = Field(..., description="Finding ID to review")
    status: str = Field(..., description="REMEDIATED, ACCEPTED_RISK, or FALSE_POSITIVE")
    analyst_notes: Optional[str] = Field(None, description="Analyst comments or remediation notes")
    reviewed_by: Optional[str] = Field("SOC_ANALYST", description="Analyst identity")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/projects")
async def list_available_projects():
    """Lists local workspace repositories and folders for one-click selection."""
    try:
        projects = GitConnector.list_workspace_projects()
        return {
            "status": "success",
            "total": len(projects),
            "projects": [p.model_dump() for p in projects]
        }
    except Exception as e:
        logger.error("Failed to list workspace projects", error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to discover workspace projects: {str(e)}")


@router.post("/scan")
async def run_credential_scan(req: CredentialScanRequest):
    """Executes an autonomous LangGraph agent credential scan, records findings in SQLite, and sends automated alert email."""
    try:
        initial_state = {
            "messages": [HumanMessage(content=f"Analyze repository '{req.target_path_or_url}' for hardcoded credentials, API keys, and sensitive leaks.")],
            "investigation_id": f"inv_cred_{int(time.time())}",
            "seed_ioc": req.target_path_or_url,
            "active_agent": "credential_analyst",
            "iteration_count": 0,
            "hypotheses": [],
            "evidence": [],
            "knowledge_graph": {},
            "pivot_queue": [],
            "info_gain_history": [],
            "pending_actions": [],
            "hitl_status": "NONE",
            "recipient_email": req.recipient_email
        }

        # Run the autonomous LangGraph Agent Subgraph
        final_state = await credential_subgraph.ainvoke(initial_state)

        summary = final_state.get("credential_scan_result", {})
        findings = final_state.get("credential_findings", [])
        email_status = final_state.get("credential_email_delivery")
        pending_actions = final_state.get("pending_actions", [])
        hypotheses = final_state.get("hypotheses", [])
        kg = final_state.get("knowledge_graph", {})

        # Persist to SQLite
        if summary:
            db.save_credential_scan_record(
                scan_id=summary.get("scan_id", f"cscan_{int(time.time())}"),
                target_path=summary.get("target_path", req.target_path_or_url),
                target_type=summary.get("target_type", "local_directory"),
                total_files=summary.get("total_files_scanned", 0),
                total_diffs=summary.get("total_diffs_scanned", 0),
                total_findings=summary.get("total_findings", len(findings)),
                critical_count=summary.get("critical_count", 0),
                high_count=summary.get("high_count", 0),
                medium_count=summary.get("medium_count", 0),
                low_count=summary.get("low_count", 0),
                scan_duration_sec=summary.get("scan_duration_sec", 0.0),
                recipient_email=req.recipient_email,
                email_sent=bool(email_status),
                git_branch=summary.get("git_branch"),
                git_commit=summary.get("git_commit")
            )

            for f in findings:
                f["scan_id"] = summary.get("scan_id")

            db.save_credential_findings_batch(findings)

        agent_messages = [
            m.content if hasattr(m, "content") else str(m)
            for m in final_state.get("messages", [])
        ]

        return {
            "status": "success",
            "summary": summary,
            "findings": findings,
            "email_delivery": email_status,
            "agent_trace": agent_messages,
            "hypotheses": hypotheses,
            "pending_actions": pending_actions,
            "knowledge_graph": kg,
            "analyst_summary": final_state.get("analyst_summary")
        }

    except Exception as e:
        logger.error("Credential agent scan failed", target=req.target_path_or_url, error=str(e))
        raise HTTPException(status_code=500, detail=f"Credential agent scan error: {str(e)}")


@router.get("/scans")
async def list_past_scans(limit: int = Query(30, ge=1, le=100)):
    """Retrieves history of credential scan runs."""
    scans = db.get_all_credential_scans(limit=limit)
    return {"status": "success", "total": len(scans), "scans": scans}


@router.get("/scans/{scan_id}")
async def get_scan_details(scan_id: str):
    """Retrieves full details and findings for a given scan ID."""
    data = db.get_credential_scan_details(scan_id)
    if not data:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found.")
    return {"status": "success", "data": data}


@router.post("/review")
async def review_finding(req: CredentialReviewRequest):
    """Human-in-the-Loop review endpoint from UI."""
    if req.status not in ["REMEDIATED", "ACCEPTED_RISK", "FALSE_POSITIVE", "PENDING_REVIEW"]:
        raise HTTPException(status_code=400, detail=f"Invalid review status: '{req.status}'")

    updated = db.update_credential_finding_status(
        finding_id=req.finding_id,
        hitl_status=req.status,
        analyst_notes=req.analyst_notes,
        reviewed_by=req.reviewed_by or "SOC_ANALYST"
    )
    if not updated:
        raise HTTPException(status_code=404, detail="Finding not found or update failed.")

    return {
        "status": "success",
        "message": f"Finding '{req.finding_id}' marked as {req.status}",
        "finding_id": req.finding_id,
        "hitl_status": req.status
    }


@router.get("/hitl-action/{token}", response_class=HTMLResponse)
async def handle_email_hitl_action(
    token: str,
    action: str = Query(..., pattern="^(REMEDIATED|ACCEPTED_RISK|FALSE_POSITIVE)$")
):
    """One-click Human-in-the-Loop review resolution triggered directly from email buttons."""
    finding = db.get_credential_finding_by_token(token)
    if not finding:
        return HTMLResponse(
            status_code=404,
            content="""
            <html>
            <body style="background: #0d1117; color: #f87171; font-family: sans-serif; text-align: center; padding: 50px;">
              <h2>⚠️ Token Not Found or Expired</h2>
              <p>The requested Human-in-the-Loop token could not be verified.</p>
              <a href="/" style="color: #38bdf8;">Return to Cyber Sentinel XDR</a>
            </body>
            </html>
            """
        )

    # Perform update
    db.update_credential_finding_status(
        finding_id=finding["id"],
        hitl_status=action,
        analyst_notes=f"Resolved via one-click email HITL link ({action})",
        reviewed_by="EMAIL_ANALYST"
    )

    badge_color = "#10b981" if action == "REMEDIATED" else ("#f59e0b" if action == "ACCEPTED_RISK" else "#6b7280")
    readable_action = action.replace("_", " ")

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <title>Cyber Sentinel — HITL Action Confirmed</title>
    </head>
    <body style="background: #0d1117; color: #c9d1d9; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0;">
      <div style="background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 36px; max-width: 500px; text-align: center; box-shadow: 0 10px 40px rgba(0,0,0,0.6);">
        <div style="font-size: 32px; margin-bottom: 12px;">✅</div>
        <h2 style="color: #ffffff; margin: 0 0 8px 0;">HITL Action Recorded</h2>
        <div style="margin: 16px 0;">
          <span style="background: {badge_color}22; border: 1px solid {badge_color}; color: {badge_color}; padding: 6px 14px; border-radius: 6px; font-weight: bold; font-size: 13px;">
            {readable_action}
          </span>
        </div>
        <p style="color: #8b949e; font-size: 14px; line-height: 1.5;">
          Finding <strong>{finding['rule_name']}</strong> in <code style="color: #58a6ff;">{finding['file_path']}</code> has been updated in the Cyber Sentinel incident ledger.
        </p>
        <div style="margin-top: 24px;">
          <a href="/" style="background: #2563eb; color: #ffffff; text-decoration: none; padding: 10px 20px; border-radius: 6px; font-size: 13px; font-weight: bold; display: inline-block;">
            Open Cyber Sentinel XDR
          </a>
        </div>
      </div>
    </body>
    </html>
    """
    return HTMLResponse(content=html)


@router.get("/outbox")
async def list_outbox_emails(limit: int = Query(20, ge=1, le=50)):
    """Inspects recent alert emails dispatched or stored in the local outbox."""
    messages = EmailService.get_outbox_messages(limit=limit)
    return {
        "status": "success",
        "total": len(messages),
        "outbox": messages
    }
