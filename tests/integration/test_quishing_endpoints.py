"""Integration tests for Autonomous Quishing & Phishing API endpoints."""

import pytest
from httpx import AsyncClient, ASGITransport
from apps.api.main import app

@pytest.mark.asyncio
async def test_list_phishing_samples_endpoint():
    """Verify GET /api/phishing/samples returns available phishing scenarios."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://127.0.0.1:8001") as client:
        resp = await client.get("/api/phishing/samples")
        assert resp.status_code == 200
        data = resp.json()
        assert "samples" in data
        assert data["total"] >= 3
        sample_ids = [s["sample_id"] for s in data["samples"]]
        assert "sample_quishing_m365" in sample_ids
        assert "sample_quishing_payroll" in sample_ids
        assert "sample_docusign_invoice" in sample_ids

@pytest.mark.asyncio
async def test_analyze_quishing_and_purge_endpoint():
    """Verify POST /api/phishing/analyze, history retrieval, and fleet mailbox purge."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://127.0.0.1:8001") as client:
        # 1. Trigger Quishing analysis
        req_payload = {"sample_id": "sample_quishing_m365"}
        resp = await client.post("/api/phishing/analyze", json=req_payload)
        assert resp.status_code == 200
        analysis = resp.json()
        assert analysis["sample_id"] == "sample_quishing_m365"
        assert "analysis_id" in analysis
        assert analysis["risk_score"] >= 90
        assert "CRITICAL" in analysis["verdict"]
        assert analysis["has_qr_code"] is True
        assert len(analysis["redirect_chain"]) >= 3
        assert analysis["headers"]["homograph_detected"] is True

        analysis_id = analysis["analysis_id"]

        # 2. Retrieve history and ensure record exists
        hist_resp = await client.get("/api/phishing/history")
        assert hist_resp.status_code == 200
        hist_data = hist_resp.json()
        assert "history" in hist_data
        assert any(item["analysis_id"] == analysis_id for item in hist_data["history"])

        # 3. Retrieve individual investigation by analysis_id
        single_resp = await client.get(f"/api/phishing/investigation/{analysis_id}")
        assert single_resp.status_code == 200
        single_data = single_resp.json()
        assert single_data["analysis_id"] == analysis_id
        assert "CRITICAL" in single_data["verdict"]

        # 4. Trigger enterprise fleet mailbox purge
        purge_payload = {"analysis_id": analysis_id}
        purge_resp = await client.post("/api/phishing/purge-fleet", json=purge_payload)
        assert purge_resp.status_code == 200
        purge_data = purge_resp.json()
        assert purge_data["status"] == "COMPLETED"
        assert purge_data["analysis_id"] == analysis_id
        assert purge_data["mailboxes_scanned"] > 0
        assert purge_data["mailboxes_purged"] > 0
        assert purge_data["threat_neutralized"] is True

@pytest.mark.asyncio
async def test_analyze_custom_dynamic_quishing_endpoint():
    """Verify POST /api/phishing/analyze handles user-submitted dynamic content."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://127.0.0.1:8001") as client:
        custom_body = (
            "From: Security Team <admin@mіcrosoft-security-portal.com>\n"
            "Subject: Immediate Action Required: Verify Okta Credentials\n"
            "URL: https://www.google.com/url?q=https://okta-fake-portal.xyz/login\n"
        )
        req_payload = {
            "sample_id": "custom_input",
            "custom_text": custom_body
        }
        resp = await client.post("/api/phishing/analyze", json=req_payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["sample_id"] == "custom_input"
        assert "analysis_id" in data
        assert data["headers"]["homograph_detected"] is True
        assert len(data["redirect_chain"]) >= 2
        assert data["risk_score"] > 60

