"""FastAPI Routes for Generative Chameleon Deception and Honeytokens."""

from typing import Optional
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
import structlog
from tools.deception import ChameleonDeceptionEngine

logger = structlog.get_logger(__name__)
router = APIRouter(prefix="/deception", tags=["Deception & Honeytokens"])
engine = ChameleonDeceptionEngine()


class GenerateTrapRequest(BaseModel):
    trap_type: str = Field(..., description="Type of trap: 'AWS_KEY', 'AZURE_SECRET', 'SSO_LURE', 'DNS_SINKHOLE'")
    target_ioc: Optional[str] = Field(None, description="Associated IOC target, e.g. '185.220.101.45'")
    context: Optional[str] = Field(None, description="Deployment context / notes")


class SimulateTripRequest(BaseModel):
    trap_id: str = Field(..., description="The unique trap identifier")
    intruder_ip: Optional[str] = Field(None, description="IP of the simulated probing adversary")


class DisarmTrapRequest(BaseModel):
    trap_id: str = Field(..., description="The unique trap identifier to disarm")


@router.post("/generate", status_code=status.HTTP_201_CREATED)
async def generate_honeytoken_trap(req: GenerateTrapRequest):
    """Autonomously generates and arms a new deceptive honeytoken lure."""
    try:
        trap = engine.generate_trap(
            trap_type=req.trap_type,
            target_ioc=req.target_ioc,
            context=req.context
        )
        return trap
    except Exception as e:
        logger.error("Failed to generate deception trap", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to generate deception trap.")


@router.get("/traps")
async def list_deception_traps():
    """Retrieves all active and historical deception lures."""
    try:
        traps = engine.list_traps()
        return {"total": len(traps), "traps": traps}
    except Exception as e:
        logger.error("Failed to list deception traps", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to list deception traps.")


@router.post("/simulate-trip")
async def simulate_trap_trigger(req: SimulateTripRequest):
    """Simulates an adversary tripping an armed trap, auto-staging perimeter containment."""
    try:
        result = engine.simulate_trip(trap_id=req.trap_id, intruder_ip=req.intruder_ip)
        if result.get("status") == "ERROR":
            raise HTTPException(status_code=404, detail=result.get("message"))
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to simulate trip", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to simulate trap trip.")


@router.post("/disarm")
async def disarm_trap(req: DisarmTrapRequest):
    """Disarms an active honeytoken lure."""
    try:
        success = engine.disarm_trap(trap_id=req.trap_id)
        return {"status": "SUCCESS" if success else "FAILED", "trap_id": req.trap_id}
    except Exception as e:
        logger.error("Failed to disarm trap", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to disarm trap.")
