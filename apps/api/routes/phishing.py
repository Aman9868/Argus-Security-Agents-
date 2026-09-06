"""FastAPI Routes for Quishing (QR Phishing) & Advanced Email Forensic Dissection."""

from typing import Optional
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
import structlog
from tools.quishing_engine import QuishingForensicEngine
from storage.db import (
    save_phishing_investigation,
    get_phishing_investigation,
    get_all_phishing_investigations
)

logger = structlog.get_logger(__name__)
router = APIRouter(prefix="/phishing", tags=["Quishing & Email Phishing Forensics"])


class PhishingAnalyzeRequest(BaseModel):
    sample_id: str = Field(..., description="Target sample ID or email artifact (e.g. 'sample_quishing_m365', 'sample_quishing_payroll', 'sample_docusign_invoice')")
    custom_text: Optional[str] = Field(None, description="Optional raw email body or custom text to dissect")


class FleetPurgeRequest(BaseModel):
    sample_id: Optional[str] = Field(None, description="The sample ID to purge")
    analysis_id: Optional[str] = Field(None, description="The analysis ID or message fingerprint to purge from tenant inboxes")


@router.get("/samples")
async def list_phishing_samples():
    """Returns catalog of realistic Quishing and email phishing scenarios."""
    try:
        samples = QuishingForensicEngine.list_samples()
        return {"total": len(samples), "samples": samples}
    except Exception as e:
        logger.error("Failed to list phishing samples", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve phishing samples.")


@router.post("/analyze", status_code=status.HTTP_200_OK)
async def analyze_phishing_artifact(req: PhishingAnalyzeRequest):
    """Executes static Quishing matrix parsing, redirect unrolling, and header evaluation."""
    try:
        analysis = QuishingForensicEngine.analyze_sample(req.sample_id, req.custom_text)
        try:
            save_phishing_investigation(analysis)
        except Exception as db_err:
            logger.warning("Failed to persist phishing analysis to DB", error=str(db_err))

        return analysis
    except Exception as e:
        logger.error("Failed to analyze phishing artifact", sample_id=req.sample_id, error=str(e))
        raise HTTPException(status_code=500, detail="Failed to execute phishing analysis.")


@router.post("/purge-fleet", status_code=status.HTTP_200_OK)
async def execute_fleet_purge_action(req: FleetPurgeRequest):
    """Executes enterprise-wide Microsoft Graph / Workspace tenant search-and-purge."""
    try:
        target = req.analysis_id or req.sample_id or "sample_quishing_m365"
        purge_result = QuishingForensicEngine.execute_fleet_purge(target)
        return purge_result
    except Exception as e:
        logger.error("Failed to execute fleet mailbox purge", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to execute fleet mailbox purge.")


@router.get("/history")
async def get_phishing_history():
    """Retrieves all past Quishing and email phishing investigations."""
    try:
        history = get_all_phishing_investigations()
        return {"total": len(history), "history": history}
    except Exception as e:
        logger.error("Failed to retrieve phishing history", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve phishing history.")


@router.get("/investigation/{analysis_id}")
async def get_investigation_details(analysis_id: str):
    """Retrieves specific phishing analysis report."""
    try:
        inv = get_phishing_investigation(analysis_id)
        if not inv:
            raise HTTPException(status_code=404, detail="Investigation not found.")
        return inv
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to fetch investigation details", analysis_id=analysis_id, error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve investigation.")
