"""Integration tests for Cyber LSP Daemon and REST endpoints."""

import pytest
from httpx import AsyncClient, ASGITransport
from apps.api.main import app
from tools.lsp.server import CyberLspServer
from tools.lsp.protocol import Position, Range


@pytest.mark.asyncio
async def test_lsp_server_rpc_dispatcher():
    server = CyberLspServer()

    # 1. Initialize request
    init_req = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
    init_resp = server.handle_request(init_req)
    assert init_resp["id"] == 1
    assert "capabilities" in init_resp["result"]
    assert init_resp["result"]["serverInfo"]["name"] == "Argus-Cyber-LSP-Sentinel"

    # 2. didOpen notification with vulnerable code
    code = """from fastapi import Request
import yaml
async def ep(req: Request):
    b = await req.body()
    yaml.load(b, Loader=yaml.Loader)
"""
    open_notif = {
        "jsonrpc": "2.0",
        "method": "textDocument/didOpen",
        "params": {
            "textDocument": {
                "uri": "file:///workspace/app.py",
                "text": code
            }
        }
    }
    open_resp = server.handle_notification(open_notif)
    assert open_resp["method"] == "textDocument/publishDiagnostics"
    diags = open_resp["params"]["diagnostics"]
    assert len(diags) == 1
    assert diags[0]["severity"] == 1  # Error

    # 3. codeAction request
    action_req = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "textDocument/codeAction",
        "params": {
            "textDocument": {"uri": "file:///workspace/app.py"}
        }
    }
    action_resp = server.handle_request(action_req)
    assert action_resp["id"] == 2
    actions = action_resp["result"]
    assert len(actions) == 1
    assert "yaml.safe_load" in actions[0]["title"]

    # 4. hover request
    hover_req = {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "textDocument/hover",
        "params": {
            "textDocument": {"uri": "file:///workspace/app.py"},
            "position": {"line": 4, "character": 6}
        }
    }
    hover_resp = server.handle_request(hover_req)
    assert hover_resp["id"] == 3
    assert hover_resp["result"] is not None
    assert "CVE-2020-14343" in hover_resp["result"]["contents"]["value"]


@pytest.mark.asyncio
async def test_lsp_rest_capabilities_and_catalog():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://127.0.0.1:8001") as client:
        # Capabilities
        r1 = await client.get("/api/lsp/capabilities")
        assert r1.status_code == 200
        d1 = r1.json()
        assert d1["success"] is True
        assert "server_info" in d1
        assert "vscode_settings" in d1["ide_setup"]

        # Catalog
        r2 = await client.get("/api/lsp/catalog")
        assert r2.status_code == 200
        d2 = r2.json()
        assert len(d2["sources"]) > 0
        assert len(d2["sinks"]) > 0
        assert len(d2["sanitizers"]) > 0


@pytest.mark.asyncio
async def test_lsp_rest_analyze_and_quick_fix():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://127.0.0.1:8001") as client:
        vulnerable_code = """from flask import request
import pickle

def handler():
    token = request.args.get("auth")
    user = pickle.loads(token)
    return user
"""
        # 1. Analyze
        r1 = await client.post("/api/lsp/analyze", json={
            "file_path": "auth.py",
            "source_code": vulnerable_code
        })
        assert r1.status_code == 200
        d1 = r1.json()
        assert d1["success"] is True
        assert d1["tainted_exploitable_count"] == 1
        assert len(d1["diagnostics"]) == 1
        assert d1["diagnostics"][0]["severity"] == 1
        assert len(d1["code_actions"]) == 1

        # 2. Quick Fix
        r2 = await client.post("/api/lsp/quick-fix", json={
            "source_code": vulnerable_code,
            "target_line": 5,
            "quick_fix_text": "    user = json.loads(token)"
        })
        assert r2.status_code == 200
        d2 = r2.json()
        assert d2["success"] is True
        assert "json.loads" in d2["refactored_code"]
        assert d2["verified_safe"] is True
        assert d2["remaining_diagnostics"] == 0
