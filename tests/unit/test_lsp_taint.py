"""Unit tests for LSP 3.17 Protocol, Interprocedural Taint Tracking, and Quick-Fixes."""

import pytest
from tools.lsp.protocol import (
    Position,
    Range,
    Diagnostic,
    DiagnosticSeverity,
    CodeAction,
    WorkspaceEdit,
    TextEdit,
    JsonRpcMessage
)
from tools.lsp.taint_engine import (
    TaintFlowEngine,
    TaintFinding,
    TaintSink,
    TaintSource
)


def test_lsp_protocol_models_and_json_rpc():
    pos1 = Position(line=10, character=4)
    pos2 = Position(line=10, character=24)
    rng = Range(start=pos1, end=pos2)

    diag = Diagnostic(
        range=rng,
        severity=DiagnosticSeverity.Error,
        code="CVE-2020-14343",
        source="Argus Cyber LSP",
        message="Tainted yaml.load call detected",
        data={"quick_fix": "yaml.safe_load(payload)"}
    )

    action = CodeAction(
        title="Refactor to yaml.safe_load",
        kind="quickfix",
        diagnostics=[diag],
        edit=WorkspaceEdit(
            changes={"file:///app.py": [TextEdit(range=rng, newText="yaml.safe_load(payload)")]}
        )
    )

    dumped = action.model_dump(by_alias=True)
    assert dumped["title"] == "Refactor to yaml.safe_load"
    assert dumped["kind"] == "quickfix"
    assert "file:///app.py" in dumped["edit"]["changes"]

    # Test JSON-RPC framing
    msg_bytes = JsonRpcMessage.make_response(req_id=1, result={"status": "ok"})
    assert msg_bytes.startswith(b"Content-Length: ")
    assert b"\r\n\r\n" in msg_bytes
    assert b'"result": {"status": "ok"}' in msg_bytes


def test_taint_flow_fastapi_body_to_yaml_load():
    code = """from fastapi import FastAPI, Request
import yaml

app = FastAPI()

@app.post("/upload")
async def handle_upload(req: Request):
    payload = await req.body()
    data = yaml.load(payload, Loader=yaml.Loader)
    return {"status": "done"}
"""
    findings = TaintFlowEngine.analyze_source_code("api.py", code)
    assert len(findings) == 1

    f = findings[0]
    assert f.verdict == "TAINTED_EXPLOITABLE"
    assert f.sink.sink_symbol == "yaml.load"
    assert f.sink.cve_id == "CVE-2020-14343"
    assert f.sink.severity == "CRITICAL"
    assert f.is_tainted is True
    assert f.taint_source is not None
    assert f.taint_source.name == "req.body"
    assert "yaml.safe_load" in f.suggested_quick_fix

    # Check LSP diagnostic conversion
    diags = TaintFlowEngine.to_lsp_diagnostics(findings, "file:///api.py")
    assert len(diags) == 1
    assert diags[0].severity == DiagnosticSeverity.Error
    assert diags[0].code == "CVE-2020-14343"
    assert len(diags[0].related_information) >= 2


def test_taint_flow_flask_args_to_os_system():
    code = """import os
from flask import request

def execute_ping():
    target = request.args.get("ip")
    os.system("ping -c 1 " + target)
"""
    findings = TaintFlowEngine.analyze_source_code("ping_svc.py", code)
    assert len(findings) == 1
    assert findings[0].verdict == "TAINTED_EXPLOITABLE"
    assert findings[0].sink.sink_symbol == "os.system"
    assert findings[0].sink.cve_id == "CWE-78"
    assert findings[0].taint_source.name == "request.args"


def test_taint_static_constant_suppressed_as_safe():
    code = """import yaml

def load_app_defaults():
    # Hardcoded string literal config - no user control
    return yaml.load("timeout: 60\\nretries: 5", Loader=yaml.Loader)
"""
    findings = TaintFlowEngine.analyze_source_code("defaults.py", code)
    assert len(findings) == 1
    assert findings[0].verdict == "STATIC_SAFE_SUPPRESSED"
    assert findings[0].is_tainted is False

    diags = TaintFlowEngine.to_lsp_diagnostics(findings, "file:///defaults.py")
    assert len(diags) == 1
    # Suppressed diagnostics should be Information (3), not an Error!
    assert diags[0].severity == DiagnosticSeverity.Information
    assert "SUPPRESSED VEX" in diags[0].message


def test_taint_sanitizer_mitigation_zero_false_positives():
    code = """from fastapi import FastAPI, Request
import yaml

app = FastAPI()

@app.post("/safe-upload")
async def safe_upload(req: Request):
    payload = await req.body()
    # Explicit safe load sanitizer
    data = yaml.safe_load(payload)
    return {"keys": list(data.keys())}
"""
    findings = TaintFlowEngine.analyze_source_code("safe.py", code)
    # Zero findings because safe_load is not an insecure sink
    assert len(findings) == 0


def test_code_action_quick_fix_generation():
    code = """import yaml
data = yaml.load(user_text, Loader=yaml.Loader)
"""
    findings = TaintFlowEngine.analyze_source_code("handler.py", code)
    diags = TaintFlowEngine.to_lsp_diagnostics(findings, "file:///handler.py")
    actions = TaintFlowEngine.generate_code_actions("file:///handler.py", diags, code)

    assert len(actions) == 1
    action = actions[0]
    assert "yaml.safe_load" in action.title
    assert "file:///handler.py" in action.edit.changes
    
    edit = action.edit.changes["file:///handler.py"][0]
    assert edit.new_text == "data = yaml.safe_load(user_text)"
