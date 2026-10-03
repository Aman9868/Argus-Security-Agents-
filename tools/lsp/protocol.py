"""LSP 3.17 Specification Data Models & JSON-RPC 2.0 Framing.

Implements standard Language Server Protocol specifications compatible with
VS Code, Cursor, Neovim, Emacs, PyCharm, and Helix.
"""

import json
from typing import Dict, Any, List, Optional, Union
from pydantic import BaseModel, Field, ConfigDict


class Position(BaseModel):
    """Line and character offset (0-indexed) in a text document."""
    line: int
    character: int


class Range(BaseModel):
    """Range inside a text document."""
    start: Position
    end: Position


class Location(BaseModel):
    """Represents a location inside a resource, such as a line inside a text file."""
    uri: str
    range: Range


class DiagnosticSeverity:
    Error: int = 1
    Warning: int = 2
    Information: int = 3
    Hint: int = 4


class DiagnosticRelatedInformation(BaseModel):
    location: Location
    message: str


class Diagnostic(BaseModel):
    """LSP Diagnostic representing an in-editor error, warning, or security finding."""
    range: Range
    severity: int = DiagnosticSeverity.Error
    code: Optional[str] = None
    source: str = "Argus Cyber LSP"
    message: str
    related_information: Optional[List[DiagnosticRelatedInformation]] = Field(default=None, alias="relatedInformation")
    data: Optional[Dict[str, Any]] = None

    model_config = ConfigDict(populate_by_name=True)


class TextEdit(BaseModel):
    """A textual edit applicable to a document."""
    range: Range
    new_text: str = Field(..., alias="newText")

    model_config = ConfigDict(populate_by_name=True)


class WorkspaceEdit(BaseModel):
    """Workspace-wide edits, mapping URI string to a list of TextEdits."""
    changes: Dict[str, List[TextEdit]] = Field(default_factory=dict)


class CodeActionKind:
    QuickFix: str = "quickfix"
    Refactor: str = "refactor"
    RefactorRewrite: str = "refactor.rewrite"
    SourceFixAll: str = "source.fixAll"


class CodeAction(BaseModel):
    """LSP CodeAction offering interactive 1-click Quick Fixes under developer's cursor."""
    title: str
    kind: str = CodeActionKind.QuickFix
    diagnostics: Optional[List[Diagnostic]] = None
    is_preferred: bool = Field(True, alias="isPreferred")
    edit: Optional[WorkspaceEdit] = None
    command: Optional[Dict[str, Any]] = None

    model_config = ConfigDict(populate_by_name=True)


# ---------------------------------------------------------------------------
# JSON-RPC 2.0 Framing Utilities
# ---------------------------------------------------------------------------

class JsonRpcMessage:
    """Helper for encoding and decoding standard LSP JSON-RPC packets."""

    HEADER_PREFIX = "Content-Length: "

    @classmethod
    def encode(cls, payload: Dict[str, Any]) -> bytes:
        """Formats a JSON-RPC dictionary with Content-Length header and CRLF CRLF."""
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        header = f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
        return header + body

    @classmethod
    def make_response(cls, req_id: Union[int, str, None], result: Any = None, error: Any = None) -> bytes:
        msg: Dict[str, Any] = {"jsonrpc": "2.0", "id": req_id}
        if error is not None:
            msg["error"] = error
        else:
            msg["result"] = result
        return cls.encode(msg)

    @classmethod
    def make_notification(cls, method: str, params: Any = None) -> bytes:
        msg: Dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        return cls.encode(msg)
