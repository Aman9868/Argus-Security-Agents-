"""Human-in-the-Loop (HITL) Containment Approval Routes."""

from fastapi import APIRouter, HTTPException
from apps.api.schemas.investigation import HITLApprovalRequest, HITLApprovalResponse
from gateway.tool_gateway.gateway import tool_gateway
from tools.containment import block_ip, quarantine_domain
import storage.db as db
import structlog
import time

logger = structlog.get_logger(__name__)
router = APIRouter(prefix="/hitl", tags=["Human-in-the-Loop"])

# In-memory storage for active pending tasks
ACTIVE_HITL_TASKS = {}


@router.get("/pending")
async def list_pending_actions():
    """Lists all pending defensive containment actions awaiting human approval."""
    return {"pending_actions": list(ACTIVE_HITL_TASKS.values())}


@router.get("/containments")
async def list_containments():
    """Retrieves all historical and active quarantine/containment records from SQLite DB."""
    records = db.get_all_containment_records(limit=100)
    return {"containments": records, "total": len(records)}


@router.post("/review", response_model=HITLApprovalResponse)
async def review_containment_action(request: HITLApprovalRequest):
    """Approves or rejects a staged defensive containment action and persists it to SQLite DB."""
    task = ACTIVE_HITL_TASKS.get(request.task_id)
    if not task:
        # Create on-the-fly task if reviewed directly from UI
        target = request.target or "185.220.101.45"
        action_type = request.action_type or ("QUARANTINE_DOMAIN" if "." in target and not target.replace(".", "").isdigit() else "BLOCK_IP")
        task = {
            "task_id": request.task_id,
            "action": action_type,
            "target": target,
            "status": "PENDING_APPROVAL"
        }

    action_type = request.action_type or task.get("action", "BLOCK_IP")
    target = request.target or task.get("target", "185.220.101.45")

    if not request.approved:
        task["status"] = "REJECTED"
        logger.info("HITL: Action rejected by analyst", task_id=request.task_id)
        db.save_containment_action(
            task_id=request.task_id,
            target=target,
            action_type=action_type,
            status="REJECTED",
            firewall_rule="N/A (Rejected by analyst)",
            enforcement_details={"status": "CANCELLED_BY_ANALYST"}
        )
        return HITLApprovalResponse(
            task_id=request.task_id,
            status="REJECTED",
            action_result={"status": "CANCELLED_BY_ANALYST"}
        )

    # If approved, execute containment action through ToolGateway
    if action_type == "BLOCK_IP":
        res = await tool_gateway.execute_tool("incident_responder", "block_ip", {"ip": target})
        fw_rule = f"nft add rule ip quarantine input ip saddr {target} drop; nft add rule ip quarantine output ip daddr {target} drop"
    elif action_type == "QUARANTINE_DOMAIN":
        res = await tool_gateway.execute_tool("incident_responder", "quarantine_domain", {"domain": target})
        fw_rule = f"local-zone: \"{target}\" redirect; local-data: \"{target} A 127.0.0.1\""
    else:
        res = await tool_gateway.execute_tool("incident_responder", "block_ip", {"ip": target})
        fw_rule = f"iptables -I FORWARD -s {target} -j DROP; iptables -I FORWARD -d {target} -j DROP"

    task["status"] = "APPROVED_AND_EXECUTED"
    logger.info("HITL: Containment executed and persisted to SQLite", task_id=request.task_id, target=target)

    # Persist directly into SQLite database
    rec_id = db.save_containment_action(
        task_id=request.task_id,
        target=target,
        action_type=action_type,
        status="APPROVED_AND_EXECUTED",
        firewall_rule=fw_rule,
        enforcement_details=res.data if res else {},
        analyst_notes="Autonomous policy containment approved by SOC analyst via Web Console."
    )

    result_data = (res.data if res else {}) or {}
    result_data["db_record_id"] = rec_id
    result_data["firewall_rule"] = fw_rule
    result_data["persisted_to_database"] = True

    return HITLApprovalResponse(
        task_id=request.task_id,
        status="APPROVED_AND_EXECUTED",
        action_result=result_data
    )


@router.post("/revoke")
async def revoke_quarantine(payload: dict):
    """Revokes an active perimeter containment rule in the database."""
    target = payload.get("target") or payload.get("record_id")
    if not target:
        raise HTTPException(status_code=400, detail="Missing target or record_id to revoke")
    
    success = db.revoke_containment_action(target)
    return {"status": "SUCCESS" if success else "FAILED", "revoked_target": target}

