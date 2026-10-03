"""Asynchronous Language Server Protocol (LSP 3.17) Daemon for Cyber Defense.

Provides real-time AST taint tracking, live IDE security diagnostics,
hover exploit paths, and 1-click QuickFix CodeActions.
"""

import sys
import json
import asyncio
import os
from typing import Dict, Any, List, Optional, Tuple, Union
import structlog

from tools.lsp.protocol import (
    JsonRpcMessage,
    Diagnostic,
    CodeAction,
    Position,
    Range
)
from tools.lsp.taint_engine import TaintFlowEngine, TaintFinding

logger = structlog.get_logger(__name__)


class CyberLspServer:
    """Production LSP 3.17 daemon serving JSON-RPC over stdio, socket, or in-memory API."""

    def __init__(self):
        # Open documents cache: uri -> text_content
        self.documents: Dict[str, str] = {}
        # Document diagnostics: uri -> list of Diagnostics
        self.diagnostics_cache: Dict[str, List[Diagnostic]] = {}
        # Document findings: uri -> list of TaintFinding
        self.findings_cache: Dict[str, List[TaintFinding]] = {}
        # Is running flag
        self.is_running = False

    def get_server_capabilities(self) -> Dict[str, Any]:
        """Declares supported LSP 3.17 capabilities to client editors."""
        return {
            "capabilities": {
                "textDocumentSync": 1,  # 1 = Full sync
                "codeActionProvider": {
                    "codeActionKinds": ["quickfix", "refactor", "source.fixAll"]
                },
                "hoverProvider": True,
                "diagnosticProvider": {
                    "interFileDependencies": True,
                    "workspaceDiagnostics": True
                }
            },
            "serverInfo": {
                "name": "Argus-Cyber-LSP-Sentinel",
                "version": "2.0.0"
            }
        }

    def analyze_document(self, uri: str, content: str) -> Tuple[List[Diagnostic], List[TaintFinding]]:
        """Parses document through AST taint engine, updating caches."""
        self.documents[uri] = content
        file_path = uri.replace("file://", "")
        
        findings = TaintFlowEngine.analyze_source_code(file_path, content)
        diagnostics = TaintFlowEngine.to_lsp_diagnostics(findings, uri)

        self.findings_cache[uri] = findings
        self.diagnostics_cache[uri] = diagnostics
        return diagnostics, findings

    def get_code_actions_for_range(self, uri: str, target_range: Optional[Range] = None) -> List[CodeAction]:
        """Returns 1-click QuickFix CodeActions for the requested file and cursor range."""
        content = self.documents.get(uri, "")
        diags = self.diagnostics_cache.get(uri, [])
        if not content or not diags:
            return []

        # If range specified, filter diagnostics intersecting range
        if target_range:
            filtered = [
                d for d in diags
                if d.range.start.line <= target_range.end.line and d.range.end.line >= target_range.start.line
            ]
        else:
            filtered = diags

        return TaintFlowEngine.generate_code_actions(uri, filtered, content)

    def get_hover_info(self, uri: str, position: Position) -> Optional[Dict[str, Any]]:
        """Returns hover documentation with full CVE info and source-to-sink flow steps."""
        findings = self.findings_cache.get(uri, [])
        for f in findings:
            sink = f.sink
            line_idx = sink.line_number - 1
            if line_idx == position.line and (sink.column_start <= position.character <= sink.column_end + 15):
                # Build rich Markdown hover card
                md = f"### 🛡️ Argus Cyber Sentinel Diagnostic\n"
                md += f"**Exploit Sink Detected**: `{sink.sink_symbol}` "
                if sink.cve_id:
                    md += f"([**{sink.cve_id}**](https://nvd.nist.gov/vuln/detail/{sink.cve_id}))\n"
                else:
                    md += f"\n"
                md += f"- **Severity**: `{sink.severity}` (CVSS {sink.cvss_score})\n"
                md += f"- **Verdict**: `{f.verdict}`\n"
                md += f"- **Remediation**: `{sink.remediation_suggestion}`\n\n"

                if f.flow_path:
                    md += "**Taint Flow Path**:\n"
                    for idx, step in enumerate(f.flow_path, 1):
                        md += f"{idx}. `{step.step_type}` (line {step.line_number}): {step.description}\n"

                return {
                    "contents": {
                        "kind": "markdown",
                        "value": md
                    }
                }
        return None

    # -----------------------------------------------------------------------
    # JSON-RPC Message Dispatcher
    # -----------------------------------------------------------------------

    def handle_request(self, msg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        method = msg.get("method")
        req_id = msg.get("id")
        params = msg.get("params", {})

        if method == "initialize":
            return {"jsonrpc": "2.0", "id": req_id, "result": self.get_server_capabilities()}

        elif method == "textDocument/codeAction":
            uri = params.get("textDocument", {}).get("uri", "")
            actions = self.get_code_actions_for_range(uri)
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": [a.model_dump(by_alias=True) for a in actions]
            }

        elif method == "textDocument/hover":
            uri = params.get("textDocument", {}).get("uri", "")
            pos_dict = params.get("position", {})
            pos = Position(line=pos_dict.get("line", 0), character=pos_dict.get("character", 0))
            hover = self.get_hover_info(uri, pos)
            return {"jsonrpc": "2.0", "id": req_id, "result": hover}

        elif method == "shutdown":
            self.is_running = False
            return {"jsonrpc": "2.0", "id": req_id, "result": None}

        return None

    def handle_notification(self, msg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Handles non-response notifications like didOpen and didChange."""
        method = msg.get("method")
        params = msg.get("params", {})

        if method == "textDocument/didOpen":
            doc = params.get("textDocument", {})
            uri = doc.get("uri", "")
            text = doc.get("text", "")
            diags, _ = self.analyze_document(uri, text)
            # Emit textDocument/publishDiagnostics
            return {
                "jsonrpc": "2.0",
                "method": "textDocument/publishDiagnostics",
                "params": {
                    "uri": uri,
                    "diagnostics": [d.model_dump(by_alias=True) for d in diags]
                }
            }

        elif method == "textDocument/didChange":
            doc = params.get("textDocument", {})
            uri = doc.get("uri", "")
            changes = params.get("contentChanges", [])
            if changes:
                new_text = changes[-1].get("text", "")
                diags, _ = self.analyze_document(uri, new_text)
                return {
                    "jsonrpc": "2.0",
                    "method": "textDocument/publishDiagnostics",
                    "params": {
                        "uri": uri,
                        "diagnostics": [d.model_dump(by_alias=True) for d in diags]
                    }
                }

        return None

    # -----------------------------------------------------------------------
    # Async Stdio Server Loop
    # -----------------------------------------------------------------------

    async def run_stdio_server(self):
        """Standard LSP JSON-RPC loop reading from stdin and writing to stdout."""
        loop = asyncio.get_event_loop()
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        await loop.connect_read_pipe(lambda: protocol, sys.stdin)

        w_transport, w_protocol = await loop.connect_write_pipe(
            asyncio.streams.FlowControlMixin, sys.stdout
        )
        writer = asyncio.StreamWriter(w_transport, w_protocol, reader, loop)

        self.is_running = True
        logger.info("Cyber LSP Server daemon started in stdio mode")

        buffer = b""
        while self.is_running:
            line = await reader.readline()
            if not line:
                break
            line_str = line.decode("latin1")
            if line_str.startswith(JsonRpcMessage.HEADER_PREFIX):
                content_len = int(line_str.split(":")[1].strip())
                # Read empty line (\r\n)
                await reader.readline()
                # Read JSON body
                body_bytes = await reader.readexactly(content_len)
                try:
                    payload = json.loads(body_bytes.decode("utf-8"))
                    
                    if "id" in payload and "method" in payload:
                        # Request
                        resp = self.handle_request(payload)
                        if resp:
                            writer.write(JsonRpcMessage.encode(resp))
                            await writer.drain()
                    elif "method" in payload:
                        # Notification
                        notif = self.handle_notification(payload)
                        if notif:
                            writer.write(JsonRpcMessage.encode(notif))
                            await writer.drain()
                except Exception as e:
                    logger.error("LSP message parsing error", error=str(e))


# ---------------------------------------------------------------------------
# CLI Command Entrypoint
# ---------------------------------------------------------------------------

def main():
    """CLI entrypoint for running as stdio server or standalone file scan."""
    server = CyberLspServer()
    if len(sys.argv) > 1 and sys.argv[1] == "--check":
        target = sys.argv[2] if len(sys.argv) > 2 else "apps/api/main.py"
        if not os.path.exists(target):
            print(f"File not found: {target}")
            sys.exit(1)
        with open(target, "r", encoding="utf-8") as f:
            content = f.read()
        diags, findings = server.analyze_document(f"file://{os.path.abspath(target)}", content)
        print(f"\n🛡️ Argus Cyber LSP Analysis for: {target}")
        print(f"Total Security Diagnostics: {len(diags)}")
        for d in diags:
            print(f" - Line {d.range.start.line + 1}: {d.message}")
    else:
        asyncio.run(server.run_stdio_server())


if __name__ == "__main__":
    main()
