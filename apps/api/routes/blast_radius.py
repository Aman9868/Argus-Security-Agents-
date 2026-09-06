"""FastAPI Routes for Autonomous Attack Path & Blast Radius Simulation."""

from typing import Optional
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
import structlog
from tools.blast_radius import AttackPathPredictor
from storage.db import save_attack_path_simulation, get_attack_path_simulation

logger = structlog.get_logger(__name__)
router = APIRouter(prefix="/blast-radius", tags=["Attack Path & Blast Radius"])

class AttackPathSimulateRequest(BaseModel):
    ioc_or_host: str = Field(..., description="Target IOC or initial compromised host (e.g. '185.220.101.45', '10.0.1.50', 'SRV-DEV-01')")
    iterations: Optional[int] = Field(500, description="Monte Carlo simulation iterations")

@router.post("/simulate", status_code=status.HTTP_200_OK)
async def run_attack_path_simulation(req: AttackPathSimulateRequest):
    """Executes Monte Carlo lateral movement simulation and blast radius calculation."""
    try:
        sim_result = AttackPathPredictor.simulate_lateral_movement(
            start_ioc_or_host=req.ioc_or_host,
            iterations=req.iterations or 500
        )
        # Persist to database
        try:
            save_attack_path_simulation(sim_result)
        except Exception as db_err:
            logger.warning("Failed to persist simulation to DB", error=str(db_err))

        return sim_result
    except Exception as e:
        logger.error("Failed to run attack path simulation", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to run attack path simulation.")

@router.get("/topology")
async def get_network_topology():
    """Returns baseline internal enterprise network and identity topology."""
    try:
        return AttackPathPredictor.get_internal_topology()
    except Exception as e:
        logger.error("Failed to fetch topology", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve topology.")

@router.get("/simulation/{sim_id}")
async def get_simulation_by_id(sim_id: str):
    """Retrieves a previously computed simulation result."""
    try:
        sim = get_attack_path_simulation(sim_id)
        if not sim:
            raise HTTPException(status_code=404, detail="Simulation not found.")
        return sim
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to fetch simulation", sim_id=sim_id, error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve simulation.")
