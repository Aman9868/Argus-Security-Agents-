"""Integration tests for Threat Intel (AbuseIPDB), Macro Dissector, and Sigma Detection API endpoints."""

import pytest
from httpx import AsyncClient, ASGITransport
from apps.api.main import app


@pytest.mark.asyncio
async def test_macro_dissection_endpoints():
    """Verifies macro sample listing and forensic dissection endpoints."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://127.0.0.1:8001") as client:
        # 1. List samples
        samples_resp = await client.get("/api/malware/macros/samples")
        assert samples_resp.status_code == 200
        samples_data = samples_resp.json()
        assert samples_data["total"] >= 3

        # 2. Dissect known sample
        dissect_resp = await client.post("/api/malware/macros/dissect", json={"sample_id": "invoice.docx"})
        assert dissect_resp.status_code == 200
        dissect_data = dissect_resp.json()
        assert dissect_data["success"] is True
        assert dissect_data["data"]["has_macros"] is True
        assert dissect_data["data"]["risk_score"] >= 70

        # 3. Dissect raw VBA snippet
        raw_resp = await client.post(
            "/api/malware/macros/dissect",
            json={"raw_vba": "Sub Document_Open()\n    CreateObject(\"WScript.Shell\").Run \"powershell.exe\"\nEnd Sub"}
        )
        assert raw_resp.status_code == 200
        raw_data = raw_resp.json()
        assert raw_data["success"] is True
        assert "Document_Open" in raw_data["data"]["auto_exec_triggers"]


@pytest.mark.asyncio
async def test_threat_intel_reputation_endpoints():
    """Verifies aggregated threat intelligence and AbuseIPDB direct queries."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://127.0.0.1:8001") as client:
        # Aggregated multi-provider query
        rep_resp = await client.post("/api/intel/reputation", json={"ioc": "185.220.101.45"})
        assert rep_resp.status_code == 200
        rep_data = rep_resp.json()
        assert rep_data["success"] is True
        assert rep_data["unified_verdict"] == "MALICIOUS"
        assert "abuseipdb" in rep_data["telemetry"]
        assert rep_data["telemetry"]["abuseipdb"]["abuse_confidence_score"] == 100

        # Direct AbuseIPDB GET endpoint
        abuse_resp = await client.get("/api/intel/abuseipdb/185.220.101.45")
        assert abuse_resp.status_code == 200
        abuse_data = abuse_resp.json()
        assert abuse_data["ip"] == "185.220.101.45"
        assert abuse_data["total_reports"] >= 800


@pytest.mark.asyncio
async def test_sigma_and_yara_generation_endpoints():
    """Verifies Sigma rule compiler and YARA generator endpoints."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://127.0.0.1:8001") as client:
        # Sigma generation
        sigma_resp = await client.post(
            "/api/detection/sigma/generate",
            json={
                "title": "C2 Traffic Block Rule",
                "ioc_type": "IP",
                "ioc_value": "185.220.101.45",
                "threat_description": "Cobalt Strike C2",
                "severity": "high"
            }
        )
        assert sigma_resp.status_code == 200
        sigma_data = sigma_resp.json()
        assert "sigma_yaml" in sigma_data
        assert "siem_targets" in sigma_data
        assert "splunk_spl" in sigma_data["siem_targets"]
        assert "elastic_kql" in sigma_data["siem_targets"]
        assert "microsoft_sentinel_kql" in sigma_data["siem_targets"]

        # YARA generation
        yara_resp = await client.post(
            "/api/detection/yara/generate",
            json={
                "rule_name": "cobalt_c2_test",
                "ioc_value": "185.220.101.45",
                "threat_family": "CobaltStrike"
            }
        )
        assert yara_resp.status_code == 200
        yara_data = yara_resp.json()
        assert "yara_code" in yara_data
        assert "rule_cobalt_c2_test" in yara_data["yara_code"]

