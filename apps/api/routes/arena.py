"""FastAPI Routes for Autonomous Adversarial Arena (Red vs. Blue Self-Play)."""

from typing import Optional
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
import structlog
from agents.arena.engine import AdversarialArenaEngine, APT_PERSONA_PROFILES
from storage.db import get_all_arena_simulations, get_arena_simulation_by_id

logger = structlog.get_logger(__name__)
router = APIRouter(prefix="/arena", tags=["Adversarial Arena"])
engine = AdversarialArenaEngine()


class SimulateDuelRequest(BaseModel):
    adversary: str = Field("APT29", description="Target adversary profile: 'APT29', 'FIN7', 'LAZARUS'")
    defense_posture: str = Field("Balanced SOC", description="Defensive posture: 'Strict Zero-Trust', 'Balanced SOC', 'Aggressive Autonomous'")


@router.post("/simulate", status_code=status.HTTP_200_OK)
async def simulate_adversarial_duel(req: SimulateDuelRequest):
    """Pits Red Agent against Blue Agent in a simulated multi-round cyber duel."""
    try:
        match_result = engine.run_duel(
            adversary_key=req.adversary,
            defense_posture=req.defense_posture
        )
        return match_result
    except Exception as e:
        logger.error("Adversarial duel simulation failed", error=str(e))
        raise HTTPException(status_code=500, detail=f"Simulation failed: {str(e)}")


@router.get("/history")
async def list_arena_history(limit: int = 15):
    """Retrieves history of past adversarial battles from SQLite."""
    try:
        matches = get_all_arena_simulations(limit=limit)
        return {"total": len(matches), "matches": matches}
    except Exception as e:
        logger.error("Failed to fetch arena history", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to fetch arena history.")


@router.get("/match/{match_id}")
async def get_match_replay(match_id: str):
    """Retrieves round-by-round replay and generated Sigma rules for a match."""
    match = get_arena_simulation_by_id(match_id)
    if not match:
        raise HTTPException(status_code=404, detail="Arena match not found.")
    return match


@router.get("/personas")
async def get_adversary_personas():
    """Returns supported APT adversary personas and defensive posture options."""
    personas = [
        {"key": k, "name": v["name"], "origin": v["origin"], "motivation": v["primary_motivation"], "tools": v["signature_tools"]}
        for k, v in APT_PERSONA_PROFILES.items()
    ]
    postures = [
        {"key": "Strict Zero-Trust", "description": "Instant micro-segmentation & token revocation, ultra-low TTD (<100ms)"},
        {"key": "Balanced SOC", "description": "Telemetry correlation, standard SIEM/EDR detection, balanced response"},
        {"key": "Aggressive Autonomous", "description": "Autonomous honeypot trapping & proactive C2 egress shutdown"}
    ]
    return {"personas": personas, "postures": postures}
