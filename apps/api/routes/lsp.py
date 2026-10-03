"""FastAPI Router for Real-time Cyber LSP (Language Server Protocol) and Taint Analysis."""

from typing import Dict, Any, List, Optional
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
import structlog

from tools.lsp import (
    CyberLspServer,
    TaintFlowEngine,
    TaintFinding,
    Diagnostic,
    CodeAction
)
from tools.lsp.taint_engine import KNOWN_SINKS, TAINT_SOURCES, SANITIZER_FUNCTIONS

logger = structlog.get_logger(__name__)
router = APIRouter(prefix="/lsp", tags=["Cyber LSP & Taint Tracking"])

_lsp_server = CyberLspServer()


# ---------------------------------------------------------------------------
# Request & Response Schemas
# ---------------------------------------------------------------------------

class LSPAnalyzeRequest(BaseModel):
    file_path: Optional[str] = "main.py"
    source_code: str = Field(..., description="Python source code to analyze through the AST Taint Flow Engine")


class LSPQuickFixRequest(BaseModel):
    source_code: str
    target_line: int = Field(..., description="0-indexed line number to apply quick fix to")
    quick_fix_text: str = Field(..., description="Replacement text for the line")


# ---------------------------------------------------------------------------
# API Endpoints
# ---------------------------------------------------------------------------

@router.get("/capabilities")
async def get_lsp_capabilities():
    """Returns LSP 3.17 server metadata and setup instructions for VS Code, Neovim, and Cursor."""
    caps = _lsp_server.get_server_capabilities()
    return {
        "success": True,
        "capabilities": caps["capabilities"],
        "server_info": caps["serverInfo"],
        "ide_setup": {
            "stdio_command": "python -m tools.lsp.server",
            "vscode_settings": {
                "argus-cyber-lsp.serverPath": "python",
                "argus-cyber-lsp.serverArgs": ["-m", "tools.lsp.server"]
            },
            "neovim_lua": """vim.api.nvim_create_autocmd("FileType", {
  pattern = "python",
  callback = function()
    vim.lsp.start({
      name = "argus-cyber-lsp",
      cmd = { "python", "-m", "tools.lsp.server" },
      root_dir = vim.fs.dirname(vim.fs.find({ ".git", "requirements.txt" }, { upward = true })[1]),
    })
  end,
})"""
        }
    }


@router.get("/catalog")
async def get_taint_catalog():
    """Returns the catalog of supported untrusted sources, dangerous execution sinks, and sanitizers."""
    return {
        "success": True,
        "sources": sorted(list(TAINT_SOURCES)),
        "sinks": [
            {
                "symbol": k,
                "package": v["package"],
                "cve": v.get("cve"),
                "cvss": v.get("cvss"),
                "severity": v.get("severity"),
                "description": v["description"],
                "safe_alternative": v["safe_alternative"]
            }
            for k, v in KNOWN_SINKS.items()
        ],
        "sanitizers": sorted(list(SANITIZER_FUNCTIONS))
    }


@router.post("/analyze", status_code=status.HTTP_200_OK)
async def analyze_source_code(req: LSPAnalyzeRequest):
    """
    Real-time LSP analysis: parses code, constructs source-to-sink dataflow paths,
    and returns LSP 3.17 diagnostics and 1-click QuickFix CodeActions.
    """
    try:
        uri = f"file:///{req.file_path.lstrip('/')}"
        diagnostics, findings = _lsp_server.analyze_document(uri, req.source_code)
        code_actions = _lsp_server.get_code_actions_for_range(uri)

        # Statistics
        total_tainted = sum(1 for f in findings if f.verdict == "TAINTED_EXPLOITABLE")
        total_suppressed = sum(1 for f in findings if f.verdict == "STATIC_SAFE_SUPPRESSED")

        return {
            "success": True,
            "file_uri": uri,
            "total_findings": len(findings),
            "tainted_exploitable_count": total_tainted,
            "static_suppressed_count": total_suppressed,
            "diagnostics": [d.model_dump(by_alias=True) for d in diagnostics],
            "findings": [f.model_dump() for f in findings],
            "code_actions": [a.model_dump(by_alias=True) for a in code_actions]
        }
    except Exception as e:
        logger.error("LSP analysis failed", error=str(e))
        raise HTTPException(status_code=500, detail=f"LSP analysis failed: {str(e)}")


@router.post("/quick-fix", status_code=status.HTTP_200_OK)
async def apply_quick_fix(req: LSPQuickFixRequest):
    """Applies an LSP TextEdit refactor to the code and verifies the resulting syntax."""
    lines = req.source_code.splitlines()
    if not (0 <= req.target_line < len(lines)):
        raise HTTPException(status_code=400, detail=f"Line index {req.target_line} out of range (0-{len(lines)-1})")

    original_line = lines[req.target_line]
    lines[req.target_line] = req.quick_fix_text
    refactored_code = "\n".join(lines) + ("\n" if req.source_code.endswith("\n") else "")

    # Re-verify through taint engine
    diags, findings = _lsp_server.analyze_document("file:///refactored.py", refactored_code)
    still_tainted = any(f.verdict == "TAINTED_EXPLOITABLE" for f in findings)

    return {
        "success": True,
        "original_line": original_line,
        "refactored_line": req.quick_fix_text,
        "refactored_code": refactored_code,
        "verified_safe": not still_tainted,
        "remaining_diagnostics": len(diags)
    }
