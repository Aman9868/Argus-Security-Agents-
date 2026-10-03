"""Integration tests for SBOM & Supply Chain REST endpoints and LangGraph Subgraph."""

import pytest
from httpx import AsyncClient, ASGITransport
from apps.api.main import app
from agents.sbom.subgraph import sbom_subgraph


@pytest.mark.asyncio
async def test_sbom_generate_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://127.0.0.1:8001") as client:
        req = {
            "project_name": "TestService",
            "project_version": "1.2.0",
            "manifest": "fastapi==0.111.0\nuvicorn==0.30.0\n",
            "ai_assets": [
                {
                    "asset_id": "test_model",
                    "asset_type": "foundation-model",
                    "name": "llama-3-8b",
                    "version_or_tag": "latest",
                    "source_uri": "hf://meta-llama/Llama-3-8B",
                    "serialization_format": "safetensors"
                }
            ]
        }
        resp = await client.post("/api/sbom/generate", json=req)
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["total_components"] == 2
        assert data["total_ai_assets"] == 1
        assert data["bom"]["bomFormat"] == "CycloneDX"


@pytest.mark.asyncio
async def test_sbom_analyze_endpoint_with_manifest_and_code():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://127.0.0.1:8001") as client:
        req = {
            "project_name": "SecureApp",
            "project_version": "1.0.0",
            "manifest": "fastapi==0.111.0\npyyaml==5.3.1\nrequests==2.28.1\n",
            "source_files": {
                "main.py": "import yaml\n\ndef load_cfg(s):\n    return yaml.safe_load(s)\n"
            },
            "ai_assets": [
                {
                    "asset_id": "model_1",
                    "asset_type": "foundation-model",
                    "name": "mistral-7b",
                    "version_or_tag": "v0.3",
                    "source_uri": "hf://mistralai/Mistral-7B",
                    "serialization_format": "safetensors"
                }
            ]
        }
        resp = await client.post("/api/sbom/analyze", json=req)
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert "cyclonedx_bom" in data
        assert len(data["ai_assets"]) == 1
        assert len(data["reachability_results"]) >= 1
        assert "triage_summary" in data
        
        # Verify noise reduction was calculated
        summary = data["triage_summary"]
        assert summary["noise_reduction_percentage"] > 0
        assert summary["not_affected_count"] > 0


@pytest.mark.asyncio
async def test_sbom_slopsquat_check_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://127.0.0.1:8001") as client:
        req = {"packages": ["fastapi", "reqeusts", "torch", "langchain-core-ai"]}
        resp = await client.post("/api/sbom/slopsquat-check", json=req)
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["findings_count"] == 2


@pytest.mark.asyncio
async def test_sbom_stats_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://127.0.0.1:8001") as client:
        resp = await client.get("/api/sbom/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_repositories_monitored" in data
        assert "total_manifests_detected" in data
        assert "projects_with_git" in data
        assert data["total_repositories_monitored"] > 0


@pytest.mark.asyncio
async def test_langgraph_sbom_subgraph_execution():
    """Verifies that the compiled LangGraph sbom_subgraph executes cleanly end-to-end on real workspace repo."""
    initial_state = {
        "messages": [],
        "investigation_id": "INV-SBOM-TEST-001",
        "seed_ioc": "cyber-agent",
        "active_agent": "supervisor",
        "iteration_count": 0,
        "hypotheses": [],
        "evidence": [],
        "knowledge_graph": {"nodes": {}, "edges": []},
        "pivot_queue": [],
        "info_gain_history": [],
        "pending_actions": [],
        "hitl_status": "NONE",
        "final_report": None,
        "analyst_summary": None
    }

    result = await sbom_subgraph.ainvoke(initial_state)
    assert result["active_agent"] == "supply_chain_analyst"
    assert len(result["evidence"]) >= 1
    assert "reachability_results" in result
    assert "vex_summary" in result
    assert "remediation_plans" in result
    assert len(result["knowledge_graph"]["nodes"]) > 0


@pytest.mark.asyncio
async def test_git_projects_and_scan_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://127.0.0.1:8001") as client:
        # 1. Test workspace discovery
        r1 = await client.get("/api/sbom/git/projects")
        assert r1.status_code == 200
        data1 = r1.json()
        assert data1["success"] is True
        assert data1["total_projects"] > 0
        proj_names = [p["name"] for p in data1["projects"]]
        assert "cyber-agent" in proj_names

        # 2. Test scanning a local project (cyber-agent itself)
        r2 = await client.post("/api/sbom/git/scan", json={"repo_path_or_url": "cyber-agent"})
        assert r2.status_code == 200
        data2 = r2.json()
        assert data2["success"] is True
        assert data2["project_name"] == "cyber-agent"
        assert "git_meta" in data2
        assert "cyclonedx_bom" in data2
        assert "reachability_results" in data2
        assert "triage_summary" in data2
        assert "executive_report_markdown" in data2
        assert "# 🛡️ Argus Cyber Sentinel" in data2["executive_report_markdown"]


@pytest.mark.asyncio
async def test_sbom_export_pdf_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://127.0.0.1:8001") as client:
        # First scan the real local repository
        scan_resp = await client.post("/api/sbom/git/scan", json={"repo_path_or_url": "cyber-agent"})
        assert scan_resp.status_code == 200
        scan_data = scan_resp.json()

        pdf_payload = {
            "project_name": scan_data["project_name"],
            "git_meta": scan_data.get("git_meta", {}),
            "components": scan_data["cyclonedx_bom"]["components"],
            "triage_summary": scan_data["triage_summary"],
            "reachability_results": scan_data["reachability_results"],
            "ai_assets": scan_data["ai_assets"],
            "slopsquat_findings": scan_data["slopsquat_findings"],
            "remediation_plans": scan_data["remediation_plans"]
        }

        resp = await client.post("/api/sbom/export-pdf", json=pdf_payload)
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "application/pdf"
        assert resp.content.startswith(b"%PDF-")
        assert len(resp.content) > 5000  # Multi-page PDF should be substantial

