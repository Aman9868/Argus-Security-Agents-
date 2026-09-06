"""Integration tests for Adversarial Arena API endpoints."""

import pytest
from httpx import AsyncClient, ASGITransport
from apps.api.main import app


@pytest.mark.asyncio
async def test_arena_personas_endpoint():
    """Verify GET /api/arena/personas returns personas and defense postures."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://127.0.0.1:8001") as client:
        resp = await client.get("/api/arena/personas")
        assert resp.status_code == 200
        data = resp.json()
        assert "personas" in data
        assert "postures" in data
        assert any(p["key"] == "APT29" for p in data["personas"])
        assert any(p["key"] == "Strict Zero-Trust" for p in data["postures"])


@pytest.mark.asyncio
async def test_arena_simulate_and_history():
    """Verify POST /api/arena/simulate executes a match and persists in history."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://127.0.0.1:8001") as client:
        # 1. Run simulation
        req_body = {
            "adversary": "APT29",
            "defense_posture": "Balanced SOC"
        }
        resp = await client.post("/api/arena/simulate", json=req_body)
        assert resp.status_code == 200
        data = resp.json()
        assert "match_id" in data
        assert "rounds" in data
        assert len(data["rounds"]) == 4
        assert "sigma_rules" in data
        match_id = data["match_id"]

        # 2. Fetch history
        hist_resp = await client.get("/api/arena/history")
        assert hist_resp.status_code == 200
        hist_data = hist_resp.json()
        assert "matches" in hist_data
        matches = hist_data["matches"]
        assert isinstance(matches, list)
        found = any(m["match_id"] == match_id for m in matches)
        assert found is True

        # 3. Fetch specific match by ID
        match_resp = await client.get(f"/api/arena/match/{match_id}")
        assert match_resp.status_code == 200
        match_data = match_resp.json()
        assert match_data["match_id"] == match_id
        assert match_data["adversary_persona"] == data["adversary_persona"]
        assert len(match_data["rounds"]) == 4


@pytest.mark.asyncio
async def test_arena_match_not_found():
    """Verify GET /api/arena/match/invalid-id returns 404."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://127.0.0.1:8001") as client:
        resp = await client.get("/api/arena/match/non-existent-match-id-999")
        assert resp.status_code == 404

