"""Integration tests for Credential Leaks Sentinel REST Endpoints and Email HITL."""

import pytest
import tempfile
import os
from httpx import AsyncClient, ASGITransport
from apps.api.main import app


@pytest.mark.asyncio
async def test_list_projects_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://127.0.0.1:8001") as client:
        resp = await client.get("/api/credentials/projects")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "success"
        assert isinstance(data["projects"], list)


@pytest.mark.asyncio
async def test_credential_scan_and_email_outbox_flow():
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create test repository with credentials
        secret_file = os.path.join(tmpdir, "secrets.py")
        with open(secret_file, "w") as f:
            f.write('GITHUB_TOKEN = "ghp_1234567890abcdef1234567890abcdef1234"\n')
            f.write('OPENAI_KEY = "sk-proj-testkeyabcdefghijklmnopqrstuvwxyz1234567890"\n')

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://127.0.0.1:8001") as client:
            scan_req = {
                "target_path_or_url": tmpdir,
                "recipient_email": "security-lead@company.local",
                "scan_git_history": False,
                "ai_triage": False
            }
            resp = await client.post("/api/credentials/scan", json=scan_req)
            assert resp.status_code == 200
            data = resp.json()
            assert data["status"] == "success"
            summary = data["summary"]
            assert summary["total_findings"] >= 2
            assert summary["recipient_email"] == "security-lead@company.local"
            assert data["email_delivery"] is not None

            # Verify Agentic LangGraph outputs
            assert "agent_trace" in data
            assert len(data["agent_trace"]) >= 5
            assert "hypotheses" in data
            assert len(data["hypotheses"]) > 0
            assert "knowledge_graph" in data
            assert "analyst_summary" in data
            assert data["analyst_summary"] is not None
            assert "pending_actions" in data
            assert len(data["pending_actions"]) > 0

            scan_id = summary["scan_id"]
            findings = data["findings"]
            first_finding = findings[0]
            finding_id = first_finding["finding_id"]
            hitl_token = first_finding["hitl_token"]

            # 2. Test Scan Details Endpoint
            details_resp = await client.get(f"/api/credentials/scans/{scan_id}")
            assert details_resp.status_code == 200
            details = details_resp.json()["data"]
            assert details["scan"]["id"] == scan_id
            assert len(details["findings"]) >= 2

            # 3. Test Web Console HITL Review
            rev_req = {
                "finding_id": finding_id,
                "status": "REMEDIATED",
                "analyst_notes": "Rotated secret in vault"
            }
            rev_resp = await client.post("/api/credentials/review", json=rev_req)
            assert rev_resp.status_code == 200
            assert rev_resp.json()["hitl_status"] == "REMEDIATED"

            # 4. Test One-Click Email HITL Link
            second_token = findings[1]["hitl_token"]
            action_resp = await client.get(f"/api/credentials/hitl-action/{second_token}?action=ACCEPTED_RISK")
            assert action_resp.status_code == 200
            assert "HITL Action Recorded" in action_resp.text
            assert "ACCEPTED RISK" in action_resp.text

            # 5. Test Outbox Endpoint
            outbox_resp = await client.get("/api/credentials/outbox")
            assert outbox_resp.status_code == 200
            outbox = outbox_resp.json()["outbox"]
            assert len(outbox) > 0
            assert any(m["recipient"] == "security-lead@company.local" for m in outbox)

