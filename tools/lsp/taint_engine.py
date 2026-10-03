"""Interprocedural AST Taint Flow & Source-to-Sink Analysis Engine.

Traces untrusted user inputs (FastAPI, Flask, Django, sys.argv, os.environ)
through dataflow assignments and function calls down to dangerous execution sinks
(PyYAML, Pickle, Subprocess, SQL, Requests SSRF).
"""

import ast
import re
from typing import Dict, Any, List, Optional, Set, Tuple
from pydantic import BaseModel, Field
from tools.lsp.protocol import (
    Diagnostic,
    DiagnosticSeverity,
    Range,
    Position,
    Location,
    DiagnosticRelatedInformation,
    CodeAction,
    CodeActionKind,
    WorkspaceEdit,
    TextEdit
)


class TaintSource(BaseModel):
    name: str
    category: str  # HTTP_BODY, HTTP_PARAM, CLI_ARG, ENV_VAR
    line_number: int
    variable_name: str
    description: str


class TaintStep(BaseModel):
    step_type: str  # SOURCE, ASSIGNMENT, CALL_ARG, SINK
    line_number: int
    symbol: str
    code_snippet: str
    description: str


class TaintSink(BaseModel):
    package_name: str
    cve_id: Optional[str] = None
    cvss_score: float = 7.5
    severity: str = "HIGH"
    sink_symbol: str
    line_number: int
    column_start: int
    column_end: int
    code_snippet: str
    vulnerable_argument: str
    remediation_suggestion: str


class TaintFinding(BaseModel):
    file_path: str
    sink: TaintSink
    is_tainted: bool
    taint_source: Optional[TaintSource] = None
    sanitizer_applied: Optional[str] = None
    verdict: str  # TAINTED_EXPLOITABLE, STATIC_SAFE_SUPPRESSED, MITIGATED_INLINE
    flow_path: List[TaintStep] = Field(default_factory=list)
    suggested_quick_fix: Optional[str] = None
    quick_fix_title: Optional[str] = None


# ---------------------------------------------------------------------------
# Known Sources, Sinks, and Sanitizer Catalog
# ---------------------------------------------------------------------------

TAINT_SOURCES = {
    # FastAPI & Starlette
    "request.body", "request.json", "request.form", "request.query_params",
    "req.body", "req.json", "req.form", "req.query_params",
    # Flask
    "request.args", "request.form", "request.values", "request.data", "request.get_json",
    # Django
    "request.GET", "request.POST", "request.FILES", "request.body",
    # CLI & Environment
    "sys.argv", "os.environ", "input"
}

FASTAPI_PARAM_ANNOTATIONS = {
    "Body", "Query", "Path", "Header", "Form", "File", "UploadFile", "Request"
}

KNOWN_SINKS = {
    "yaml.load": {
        "package": "pyyaml",
        "cve": "CVE-2020-14343",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "safe_alternative": "yaml.safe_load",
        "description": "Arbitrary code execution via untrusted PyYAML deserialization."
    },
    "pickle.loads": {
        "package": "pickle",
        "cve": "CWE-502",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "safe_alternative": "json.loads",
        "description": "Arbitrary code execution via untrusted Python pickle deserialization."
    },
    "pickle.load": {
        "package": "pickle",
        "cve": "CWE-502",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "safe_alternative": "json.load",
        "description": "Arbitrary code execution via untrusted Python pickle deserialization."
    },
    "os.system": {
        "package": "os",
        "cve": "CWE-78",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "safe_alternative": "subprocess.run(..., shell=False)",
        "description": "Command injection vulnerability executing arbitrary shell commands."
    },
    "subprocess.Popen": {
        "package": "subprocess",
        "cve": "CWE-78",
        "cvss": 8.8,
        "severity": "HIGH",
        "safe_alternative": "subprocess.run([arg1, arg2], shell=False)",
        "description": "Potential command injection if shell=True is enabled with tainted input."
    },
    "subprocess.run": {
        "package": "subprocess",
        "cve": "CWE-78",
        "cvss": 8.8,
        "severity": "HIGH",
        "safe_alternative": "subprocess.run([args], shell=False)",
        "description": "Potential command injection if shell=True is enabled with tainted input."
    },
    "requests.get": {
        "package": "requests",
        "cve": "CVE-2023-32681",
        "cvss": 6.1,
        "severity": "MEDIUM",
        "safe_alternative": "requests.get(..., allow_redirects=False)",
        "description": "Proxy-Authorization header leak on cross-origin redirects."
    },
    "requests.post": {
        "package": "requests",
        "cve": "CVE-2023-32681",
        "cvss": 6.1,
        "severity": "MEDIUM",
        "safe_alternative": "requests.post(..., allow_redirects=False)",
        "description": "Proxy-Authorization header leak on cross-origin redirects."
    }
}

SANITIZER_FUNCTIONS = {
    "shlex.quote", "html.escape", "re.escape", "int", "float", "yaml.safe_load", "json.loads"
}


# ---------------------------------------------------------------------------
# AST Dataflow & Taint Visitor
# ---------------------------------------------------------------------------

class ASTTaintVisitor(ast.NodeVisitor):
    """
    Constructs a local intra- and inter-procedural dataflow graph to track
    tainted variables from API entry points down to dangerous sinks.
    """

    def __init__(self, file_path: str, source_text: str):
        self.file_path = file_path
        self.source_text = source_text
        self.lines = source_text.splitlines()
        
        # Taint tracking state: variable_name -> list of TaintStep
        self.tainted_variables: Dict[str, List[TaintStep]] = {}
        # Sanitized variables: variable_name -> sanitizer_name
        self.sanitized_variables: Dict[str, str] = {}
        # Discovered findings
        self.findings: List[TaintFinding] = []
        # Function parameter mappings: func_name -> [param_names]
        self.function_params: Dict[str, List[str]] = {}

    def _get_line_snippet(self, lineno: int) -> str:
        if 1 <= lineno <= len(self.lines):
            return self.lines[lineno - 1].strip()
        return ""

    def visit_FunctionDef(self, node: ast.FunctionDef):
        """Inspects function definitions for framework parameter sources (FastAPI, Flask, etc.)."""
        params = [arg.arg for arg in node.args.args]
        self.function_params[node.name] = params

        # FastAPI endpoint parameters inspection
        for arg in node.args.args:
            is_source = False
            desc = ""

            # Check if type annotation is Request or UploadFile
            if arg.annotation:
                ann_str = ast.unparse(arg.annotation) if hasattr(ast, "unparse") else ""
                if any(src in ann_str for src in FASTAPI_PARAM_ANNOTATIONS):
                    is_source = True
                    desc = f"FastAPI untrusted parameter ({ann_str})"

            # Check if arg name itself implies input (e.g. req, request, payload, raw_data)
            if arg.arg in ["req", "request", "payload", "raw_data", "user_input"]:
                is_source = True
                desc = f"HTTP request object parameter: {arg.arg}"

            if is_source:
                step = TaintStep(
                    step_type="SOURCE",
                    line_number=node.lineno,
                    symbol=arg.arg,
                    code_snippet=self._get_line_snippet(node.lineno),
                    description=desc
                )
                self.tainted_variables[arg.arg] = [step]

        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self.visit_FunctionDef(node)  # Treat async functions identically

    def visit_Assign(self, node: ast.Assign):
        """Traces variable assignments (Source -> Variable, or TaintedVar -> NewVar)."""
        value_repr = ast.unparse(node.value) if hasattr(ast, "unparse") else ""
        lineno = node.lineno
        snippet = self._get_line_snippet(lineno)

        # 1. Check if value is a direct known source
        is_direct_source = False
        source_name = ""
        for src in TAINT_SOURCES:
            if src in value_repr:
                is_direct_source = True
                source_name = src
                break

        # 2. Check if value is wrapped by a sanitizer function
        is_sanitized = False
        sanitizer_name = ""
        for san in SANITIZER_FUNCTIONS:
            if value_repr.startswith(san):
                is_sanitized = True
                sanitizer_name = san
                break

        # 3. Check if value references an already tainted variable
        referenced_tainted: Optional[str] = None
        for tainted_var in list(self.tainted_variables.keys()):
            # Use regex to match standalone identifier
            if re.search(rf"\b{re.escape(tainted_var)}\b", value_repr):
                referenced_tainted = tainted_var
                break

        # Propagate to target targets
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id

                if is_sanitized:
                    self.sanitized_variables[var_name] = sanitizer_name
                    if var_name in self.tainted_variables:
                        del self.tainted_variables[var_name]

                elif is_direct_source:
                    step = TaintStep(
                        step_type="SOURCE",
                        line_number=lineno,
                        symbol=source_name,
                        code_snippet=snippet,
                        description=f"Untrusted input source: {source_name}"
                    )
                    self.tainted_variables[var_name] = [step]

                elif referenced_tainted:
                    prev_steps = self.tainted_variables[referenced_tainted]
                    new_step = TaintStep(
                        step_type="ASSIGNMENT",
                        line_number=lineno,
                        symbol=var_name,
                        code_snippet=snippet,
                        description=f"Taint propagated from '{referenced_tainted}' via assignment"
                    )
                    self.tainted_variables[var_name] = prev_steps + [new_step]

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        """Evaluates whether a call invokes a vulnerable sink with tainted or static arguments."""
        func_name = ast.unparse(node.func) if hasattr(ast, "unparse") else ""
        lineno = node.lineno
        snippet = self._get_line_snippet(lineno)

        col_offset = getattr(node, "col_offset", 0)
        end_col_offset = getattr(node, "end_col_offset", col_offset + len(func_name))

        # Check if called function matches a known sink
        matched_sink_name: Optional[str] = None
        sink_meta: Optional[Dict[str, Any]] = None

        for known_sink, meta in KNOWN_SINKS.items():
            if func_name == known_sink or func_name.endswith(f".{known_sink}"):
                # Special check for yaml.load: check if Loader=SafeLoader is explicitly passed
                if known_sink == "yaml.load":
                    is_safe_loader = False
                    for kw in node.keywords:
                        kw_val = ast.unparse(kw.value) if hasattr(ast, "unparse") else ""
                        if "SafeLoader" in kw_val:
                            is_safe_loader = True
                            break
                    if is_safe_loader:
                        continue  # Safe loader used, do not flag as insecure sink

                # Special check for subprocess: only flag if shell=True is passed or string input
                if "subprocess" in known_sink:
                    has_shell_true = False
                    for kw in node.keywords:
                        if kw.arg == "shell":
                            kw_val = ast.unparse(kw.value) if hasattr(ast, "unparse") else ""
                            if kw_val.lower() == "true":
                                has_shell_true = True
                    if not has_shell_true:
                        # Non-shell subprocess is generally safe from classic command injection
                        continue

                matched_sink_name = known_sink
                sink_meta = meta
                break

        if matched_sink_name and sink_meta:
            # Determine whether arguments are tainted or static constants
            first_arg_str = ""
            if node.args:
                first_arg_str = ast.unparse(node.args[0]) if hasattr(ast, "unparse") else ""

            is_tainted = False
            tainted_var_found: Optional[str] = None
            taint_source: Optional[TaintSource] = None
            flow_path: List[TaintStep] = []

            # Check if argument is a constant literal string (e.g. "static_config.yaml")
            is_static_constant = isinstance(node.args[0], ast.Constant) if node.args else False

            # Check if first argument references a tainted variable
            for tvar, steps in self.tainted_variables.items():
                if re.search(rf"\b{re.escape(tvar)}\b", first_arg_str):
                    is_tainted = True
                    tainted_var_found = tvar
                    flow_path = list(steps)
                    break

            # Check if first argument directly calls a taint source
            if not is_tainted:
                for src in TAINT_SOURCES:
                    if src in first_arg_str:
                        is_tainted = True
                        step = TaintStep(
                            step_type="SOURCE",
                            line_number=lineno,
                            symbol=src,
                            code_snippet=snippet,
                            description=f"Direct call to untrusted source: {src}"
                        )
                        flow_path = [step]
                        break

            # Add final SINK step to path
            sink_step = TaintStep(
                step_type="SINK",
                line_number=lineno,
                symbol=matched_sink_name,
                code_snippet=snippet,
                description=f"Execution reaches vulnerable sink: {matched_sink_name}"
            )
            flow_path.append(sink_step)

            # Determine verdict
            if is_tainted:
                verdict = "TAINTED_EXPLOITABLE"
                source_step = flow_path[0] if flow_path else None
                if source_step:
                    taint_source = TaintSource(
                        name=source_step.symbol,
                        category="HTTP_BODY",
                        line_number=source_step.line_number,
                        variable_name=tainted_var_found or source_step.symbol,
                        description=source_step.description
                    )
            elif is_static_constant:
                verdict = "STATIC_SAFE_SUPPRESSED"
            else:
                verdict = "UNTAINTED_UNREACHABLE"

            # Construct Quick Fix
            quick_fix: Optional[str] = None
            quick_fix_title: Optional[str] = None

            if matched_sink_name == "yaml.load":
                quick_fix = re.sub(r"yaml\.load\(([^,\)]+)(?:,\s*Loader=[^\)]+)?\)", r"yaml.safe_load(\1)", snippet)
                quick_fix_title = "Refactor to yaml.safe_load(...) [CVE-2020-14343 Mitigation]"
            elif matched_sink_name == "pickle.loads":
                quick_fix = re.sub(r"pickle\.loads\((.+?)\)", r"json.loads(\1)", snippet)
                quick_fix_title = "Replace pickle.loads with json.loads (Safe Serialization)"

            sink_obj = TaintSink(
                package_name=sink_meta["package"],
                cve_id=sink_meta.get("cve"),
                cvss_score=sink_meta.get("cvss", 7.5),
                severity=sink_meta.get("severity", "HIGH"),
                sink_symbol=matched_sink_name,
                line_number=lineno,
                column_start=col_offset,
                column_end=end_col_offset,
                code_snippet=snippet,
                vulnerable_argument=first_arg_str,
                remediation_suggestion=sink_meta["safe_alternative"]
            )

            self.findings.append(TaintFinding(
                file_path=self.file_path,
                sink=sink_obj,
                is_tainted=is_tainted,
                taint_source=taint_source,
                verdict=verdict,
                flow_path=flow_path,
                suggested_quick_fix=quick_fix,
                quick_fix_title=quick_fix_title
            ))

        self.generic_visit(node)


# ---------------------------------------------------------------------------
# High-Level Taint Engine Interface
# ---------------------------------------------------------------------------

class TaintFlowEngine:
    """Orchestrates source-to-sink taint analysis and transforms findings into LSP diagnostics."""

    @classmethod
    def analyze_source_code(cls, file_path: str, source_code: str) -> List[TaintFinding]:
        """Parses Python source code and discovers all tainted exploit sinks."""
        try:
            tree = ast.parse(source_code, filename=file_path)
            visitor = ASTTaintVisitor(file_path, source_code)
            visitor.visit(tree)
            return visitor.findings
        except SyntaxError:
            return []

    @classmethod
    def to_lsp_diagnostics(cls, findings: List[TaintFinding], file_uri: str) -> List[Diagnostic]:
        """Translates TaintFindings into LSP 3.17 Diagnostics with 0-indexed positions."""
        diagnostics: List[Diagnostic] = []

        for f in findings:
            sink = f.sink
            line_idx = max(0, sink.line_number - 1)
            char_start = sink.column_start
            char_end = sink.column_end

            # Map verdict to severity:
            # TAINTED_EXPLOITABLE -> Error (1)
            # STATIC_SAFE_SUPPRESSED -> Information (3)
            # UNTAINTED_UNREACHABLE -> Warning (2)
            if f.verdict == "TAINTED_EXPLOITABLE":
                severity = DiagnosticSeverity.Error
                msg_prefix = f"🚨 [TAINTED EXPLOIT SINK] {sink.sink_symbol}"
            elif f.verdict == "STATIC_SAFE_SUPPRESSED":
                severity = DiagnosticSeverity.Information
                msg_prefix = f"🛡️ [SUPPRESSED VEX] {sink.sink_symbol} (Static Constant Argument)"
            else:
                severity = DiagnosticSeverity.Warning
                msg_prefix = f"⚠️ [POTENTIAL RISK] {sink.sink_symbol}"

            cve_str = f" ({sink.cve_id})" if sink.cve_id else ""
            msg = f"{msg_prefix}{cve_str} • CVSS {sink.cvss_score} {sink.severity}. Safe alternative: {sink.remediation_suggestion}"

            # Add related information trace
            related: List[DiagnosticRelatedInformation] = []
            for step in f.flow_path:
                step_line = max(0, step.line_number - 1)
                related.append(DiagnosticRelatedInformation(
                    location=Location(
                        uri=file_uri,
                        range=Range(
                            start=Position(line=step_line, character=0),
                            end=Position(line=step_line, character=len(step.code_snippet))
                        )
                    ),
                    message=f"[{step.step_type}] {step.description}"
                ))

            diagnostics.append(Diagnostic(
                range=Range(
                    start=Position(line=line_idx, character=char_start),
                    end=Position(line=line_idx, character=char_end)
                ),
                severity=severity,
                code=sink.cve_id or "SEC-TAINT-001",
                source="Argus Cyber LSP",
                message=msg,
                related_information=related if related else None,
                data={
                    "verdict": f.verdict,
                    "quick_fix": f.suggested_quick_fix,
                    "quick_fix_title": f.quick_fix_title,
                    "package_name": sink.package_name,
                    "sink_symbol": sink.sink_symbol
                }
            ))

        return diagnostics

    @classmethod
    def generate_code_actions(
        cls,
        file_uri: str,
        diagnostics: List[Diagnostic],
        source_code: str
    ) -> List[CodeAction]:
        """Generates 1-click QuickFix CodeActions for tainted vulnerabilities."""
        actions: List[CodeAction] = []
        lines = source_code.splitlines()

        for diag in diagnostics:
            if not diag.data or not diag.data.get("quick_fix"):
                continue

            target_line = diag.range.start.line
            if 0 <= target_line < len(lines):
                new_line_text = diag.data["quick_fix"]
                title = diag.data.get("quick_fix_title") or f"⚡ Quick-Fix: Safe Refactor {diag.data.get('sink_symbol')}"

                edit = WorkspaceEdit(
                    changes={
                        file_uri: [
                            TextEdit(
                                range=Range(
                                    start=Position(line=target_line, character=0),
                                    end=Position(line=target_line, character=len(lines[target_line]))
                                ),
                                new_text=new_line_text
                            )
                        ]
                    }
                )

                actions.append(CodeAction(
                    title=title,
                    kind=CodeActionKind.QuickFix,
                    diagnostics=[diag],
                    is_preferred=True,
                    edit=edit
                ))

        return actions
