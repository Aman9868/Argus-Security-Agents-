"""Integration tests for Blast Radius & Attack Path API endpoints."""

import pytest
from httpx import AsyncClient, ASGITransport
from apps.api.main import app

@pytest.mark.asyncio
async def test_topology_endpoint():
    """Verify GET /api/blast-radius/topology returns enterprise nodes and relations."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://127.0.0.1:8001") as client:
        resp = await client.get("/api/blast-radius/topology")
        assert resp.status_code == 200
        data = resp.json()
        assert "nodes" in data
        assert "edges" in data
        assert len(data["nodes"]) >= 5

@pytest.mark.asyncio
async def test_simulate_attack_path_endpoint():
    """Verify POST /api/blast-radius/simulate executes simulation and persists."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://127.0.0.1:8001") as client:
        payload = {
            "ioc_or_host": "185.220.101.45",
            "iterations": 200
        }
        resp = await client.post("/api/blast-radius/simulate", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert "simulation_id" in data
        assert "compromise_probability" in data
        assert "mttb_minutes" in data
        assert "critical_attack_paths" in data
        assert "crown_jewels_at_risk" in data
        assert "chokepoint_defenses" in data
        assert "cytoscape_elements" in data

        sim_id = data["simulation_id"]

        # Fetch simulation by ID
        get_resp = await client.get(f"/api/blast-radius/simulation/{sim_id}")
        assert get_resp.status_code == 200
        sim_data = get_resp.json()
        assert sim_data["simulation_id"] == sim_id
        assert sim_data["compromised_origin"] == "185.220.101.45"
