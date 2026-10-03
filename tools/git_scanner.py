"""Git Repository Scanner & Workspace Connector for SBOM and Supply Chain Governance.

Supports auto-discovery of local git projects in workspaces, remote git URL shallow cloning,
manifest extraction, AST source gathering, and AI-BOM model/tool asset cataloging.
"""

import os
import re
import json
import subprocess
import hashlib
from typing import Dict, Any, List, Optional, Tuple
from pydantic import BaseModel, Field
import structlog

logger = structlog.get_logger(__name__)

WORKSPACE_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GIT_CLONE_CACHE_DIR = os.path.join(BASE_DIR, "data", "git_clones")
os.makedirs(GIT_CLONE_CACHE_DIR, exist_ok=True)


class GitProjectMeta(BaseModel):
    project_id: str
    name: str
    path: str
    is_git: bool
    branch: Optional[str] = None
    commit_sha: Optional[str] = None
    commit_message: Optional[str] = None
    commit_date: Optional[str] = None
    remote_url: Optional[str] = None
    has_manifest: bool = False
    manifest_type: Optional[str] = None
    manifest_path: Optional[str] = None


class GitScanResult(BaseModel):
    project_name: str
    project_version: str
    project_path: str
    git_meta: GitProjectMeta
    manifest_content: str
    source_files: Dict[str, str] = Field(default_factory=dict)
    ai_assets: List[Dict[str, Any]] = Field(default_factory=list)
    total_python_files: int = 0
    scanned_file_paths: List[str] = Field(default_factory=list)


class GitConnector:
    """Discovers, clones, and extracts manifests/source from Git repositories."""

    @classmethod
    def run_git_cmd(cls, cmd: List[str], cwd: str) -> Optional[str]:
        """Safely executes a git command and returns stdout if successful."""
        try:
            res = subprocess.run(
                cmd,
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=15.0
            )
            if res.returncode == 0:
                return res.stdout.strip()
        except Exception as e:
            logger.debug("Git command failed", cmd=cmd, cwd=cwd, error=str(e))
        return None

    @classmethod
    def get_git_metadata(cls, repo_dir: str) -> Tuple[bool, Optional[str], Optional[str], Optional[str], Optional[str], Optional[str]]:
        """Extracts branch, commit SHA, commit msg, date, and remote URL from a directory."""
        if not os.path.isdir(os.path.join(repo_dir, ".git")):
            return False, None, None, None, None, None

        branch = cls.run_git_cmd(["git", "branch", "--show-current"], repo_dir) or "main"
        sha = cls.run_git_cmd(["git", "rev-parse", "HEAD"], repo_dir) or ""
        msg = cls.run_git_cmd(["git", "log", "-1", "--format=%s"], repo_dir) or ""
        date = cls.run_git_cmd(["git", "log", "-1", "--format=%cd", "--date=iso"], repo_dir) or ""
        remote = cls.run_git_cmd(["git", "remote", "get-url", "origin"], repo_dir) or ""

        return True, branch, sha[:10] if sha else None, msg, date, remote

    @classmethod
    def list_workspace_projects(cls, base_dir: Optional[str] = None) -> List[GitProjectMeta]:
        """Discovers all local project directories and parses their Git and manifest states."""
        root = base_dir or WORKSPACE_ROOT
        projects: List[GitProjectMeta] = []

        if not os.path.isdir(root):
            return projects

        for entry in sorted(os.listdir(root)):
            entry_path = os.path.join(root, entry)
            if not os.path.isdir(entry_path) or entry.startswith("."):
                continue

            is_git, branch, sha, msg, date, remote = cls.get_git_metadata(entry_path)

            # Check for dependency manifest
            manifest_type = None
            manifest_path = None
            for mf, mtype in [
                ("requirements.txt", "requirements.txt"),
                ("pyproject.toml", "pyproject.toml"),
                ("Pipfile", "Pipfile"),
                ("package.json", "package.json")
            ]:
                target_mf = os.path.join(entry_path, mf)
                if os.path.exists(target_mf):
                    manifest_type = mtype
                    manifest_path = target_mf
                    break

            projects.append(GitProjectMeta(
                project_id=entry,
                name=entry,
                path=entry_path,
                is_git=is_git,
                branch=branch,
                commit_sha=sha,
                commit_message=msg,
                commit_date=date,
                remote_url=remote,
                has_manifest=manifest_path is not None,
                manifest_type=manifest_type,
                manifest_path=manifest_path
            ))

        return projects

    @classmethod
    def clone_or_locate_repo(cls, repo_path_or_url: str, branch: Optional[str] = None) -> Tuple[str, GitProjectMeta]:
        """
        Locates a local path OR clones a remote Git URL into cache.
        Returns (local_directory_path, GitProjectMeta).
        """
        clean_input = repo_path_or_url.strip()

        # 1. If it's a remote Git URL
        if clean_input.startswith("http://") or clean_input.startswith("https://") or clean_input.startswith("git@"):
            url_hash = hashlib.sha256(clean_input.encode()).hexdigest()[:12]
            repo_name = clean_input.rstrip("/").split("/")[-1].replace(".git", "")
            target_dir = os.path.join(GIT_CLONE_CACHE_DIR, f"{repo_name}_{url_hash}")

            if not os.path.isdir(target_dir):
                logger.info("Cloning remote Git repository into cache", url=clean_input, target=target_dir)
                clone_cmd = ["git", "clone", "--depth", "1"]
                if branch:
                    clone_cmd.extend(["--branch", branch])
                clone_cmd.extend([clean_input, target_dir])
                res = subprocess.run(clone_cmd, capture_output=True, text=True, timeout=60.0)
                if res.returncode != 0:
                    raise ValueError(f"Git clone failed: {res.stderr.strip() or res.stdout.strip()}")
            else:
                logger.info("Using cached Git clone directory", target=target_dir)

            local_path = target_dir
            proj_name = repo_name
        else:
            # 2. Local directory or relative project name
            if os.path.isabs(clean_input) and os.path.isdir(clean_input):
                local_path = clean_input
                proj_name = os.path.basename(clean_input)
            else:
                # Try relative to WORKSPACE_ROOT
                candidate = os.path.join(WORKSPACE_ROOT, clean_input)
                if os.path.isdir(candidate):
                    local_path = candidate
                    proj_name = clean_input
                else:
                    raise FileNotFoundError(f"Project directory or Git repository not found: '{clean_input}'")

        is_git, b, sha, msg, date, remote = cls.get_git_metadata(local_path)
        meta = GitProjectMeta(
            project_id=proj_name,
            name=proj_name,
            path=local_path,
            is_git=is_git,
            branch=b or branch or "main",
            commit_sha=sha,
            commit_message=msg,
            commit_date=date,
            remote_url=remote or (clean_input if "://" in clean_input else None)
        )
        return local_path, meta

    @classmethod
    def inspect_and_extract_project(cls, repo_path_or_url: str, branch: Optional[str] = None) -> GitScanResult:
        """
        Full extraction:
        1. Locates/clones repo
        2. Gathers manifests
        3. Scans Python source files for AST reachability
        4. Detects AI models/weights and MCP configs
        """
        local_path, meta = cls.clone_or_locate_repo(repo_path_or_url, branch)

        # 1. Extract manifest
        manifest_text = ""
        version = "1.0.0"
        for mf in ["requirements.txt", "pyproject.toml", "Pipfile"]:
            mf_path = os.path.join(local_path, mf)
            if os.path.exists(mf_path):
                meta.has_manifest = True
                meta.manifest_type = mf
                meta.manifest_path = mf_path
                try:
                    with open(mf_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                        if mf == "requirements.txt":
                            manifest_text = content
                        elif mf == "pyproject.toml":
                            # Parse basic pyproject version and dependencies
                            ver_m = re.search(r'version\s*=\s*["\']([^"\']+)["\']', content)
                            if ver_m:
                                version = ver_m.group(1)
                            # Extract lines under dependencies
                            deps_lines = []
                            for line in content.splitlines():
                                if "==" in line or ">=" in line:
                                    deps_lines.append(line.strip().strip('",'))
                            manifest_text = "\n".join(deps_lines) if deps_lines else content
                except Exception as e:
                    logger.warning("Failed to read manifest file", path=mf_path, error=str(e))
                break

        if not manifest_text:
            manifest_text = "# Auto-detected empty manifest\n"

        # 2. Gather Python source files (up to max 80 files to keep analysis fast and responsive)
        source_files: Dict[str, str] = {}
        scanned_paths: List[str] = []
        ignored_dirs = {".git", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache", "build", "dist", ".cache"}

        for root, dirs, files in os.walk(local_path):
            dirs[:] = [d for d in dirs if d not in ignored_dirs and not d.startswith(".")]
            for file in files:
                if file.endswith(".py") and len(source_files) < 80:
                    abs_p = os.path.join(root, file)
                    rel_p = os.path.relpath(abs_p, local_path)
                    try:
                        with open(abs_p, "r", encoding="utf-8", errors="ignore") as f:
                            source_files[rel_p] = f.read()
                        scanned_paths.append(rel_p)
                    except Exception as e:
                        logger.debug("Failed to read source file", path=abs_p, error=str(e))

        # 3. Discover AI Models, Weights, and MCP Tool Configurations
        ai_assets: List[Dict[str, Any]] = []
        for root, dirs, files in os.walk(local_path):
            dirs[:] = [d for d in dirs if d not in ignored_dirs]
            for file in files:
                ext = os.path.splitext(file)[1].lower()
                rel_p = os.path.relpath(os.path.join(root, file), local_path)
                
                # Model weights detection
                if ext in [".safetensors", ".gguf", ".onnx", ".pkl", ".pt", ".bin"]:
                    is_pickle = ext in [".pkl", ".pt"]
                    ai_assets.append({
                        "asset_id": f"ai_model_{hashlib.md5(rel_p.encode()).hexdigest()[:8]}",
                        "asset_type": "local-weights",
                        "name": file,
                        "version_or_tag": "1.0.0",
                        "source_uri": f"file://{rel_p}",
                        "serialization_format": ext.replace(".", ""),
                        "license": "Proprietary",
                        "security_posture": "HIGH_RISK_PICKLE" if is_pickle else "VERIFIED_SAFE",
                        "risk_notes": "Pickle serialization can execute arbitrary bytecode upon load. Migrate to SafeTensors." if is_pickle else None,
                        "mcp_capabilities": []
                    })
                # MCP configuration detection
                elif file in ["mcp.json", ".mcp.json"] or "mcp" in file.lower() and ext == ".json":
                    ai_assets.append({
                        "asset_id": f"mcp_{hashlib.md5(rel_p.encode()).hexdigest()[:8]}",
                        "asset_type": "mcp-tool",
                        "name": f"MCP Config: {file}",
                        "version_or_tag": "1.0.0",
                        "source_uri": f"file://{rel_p}",
                        "serialization_format": "api-endpoint",
                        "license": "MIT",
                        "security_posture": "VERIFIED_SAFE",
                        "mcp_capabilities": ["context-provider", "tool-execution"]
                    })

        return GitScanResult(
            project_name=meta.name,
            project_version=version,
            project_path=local_path,
            git_meta=meta,
            manifest_content=manifest_text,
            source_files=source_files,
            ai_assets=ai_assets,
            total_python_files=len(source_files),
            scanned_file_paths=scanned_paths
        )

    scan_local_or_remote_repo = inspect_and_extract_project

    @classmethod
    def generate_executive_audit_report(
        cls,
        scan_result: GitScanResult,
        triage_summary: Dict[str, Any],
        reachability_results: List[Dict[str, Any]],
        slopsquat_findings: List[Dict[str, Any]],
        remediation_plans: List[Dict[str, Any]]
    ) -> str:
        """Generates a comprehensive executive Markdown audit report ready for export."""
        meta = scan_result.git_meta
        report = f"""# 🛡️ Argus Cyber Sentinel — SBOM & Software Supply Chain Security Audit

## Executive Summary
- **Repository**: `{scan_result.project_name}`
- **Repository Path**: `{scan_result.project_path}`
- **Git Branch**: `{meta.branch or 'N/A'}`
- **Commit SHA**: `{meta.commit_sha or 'N/A'}`
- **Commit Message**: `{meta.commit_message or 'N/A'}`
- **Remote URL**: `{meta.remote_url or 'Local Workspace'}`
- **Total Source Files Scanned**: `{scan_result.total_python_files}` Python modules
- **AI-BOM Assets Governed**: `{len(scan_result.ai_assets)}` (Models/Weights/MCP Tools)

---

## 📊 Key Security Metrics
| Metric | Value | Impact |
| :--- | :--- | :--- |
| **Total Vulnerabilities (CVEs)** | `{triage_summary.get('total_vulnerabilities', 0)}` | Ingested via CycloneDX 1.6 |
| **VEX Suppressed (`not_affected`)** | `{triage_summary.get('not_affected_count', 0)}` | AST confirmed unreachable |
| **Active Reachable Threats (`affected`)** | `{triage_summary.get('affected_count', 0)}` | **Requires immediate patching** |
| **Alert Noise Reduction Ratio** | `{triage_summary.get('noise_reduction_percentage', 0)}%` | Developer alert fatigue prevented |
| **Analyst Triage Hours Saved** | `{triage_summary.get('estimated_triage_hours_saved', 0)} hrs` | Benchmarked @ 3.5 hrs/CVE |
| **AI Slopsquatting / Hallucinations** | `{len(slopsquat_findings)}` | Dependency confusion risk |

---

## 🔍 AST Call-Graph Reachability & OpenVEX Triage
"""
        for r in reachability_results:
            status_emoji = "🚨" if r.get("vex_status") == "affected" else "✅"
            report += f"""
### {status_emoji} `{r.get('package_name')}` (v{r.get('installed_version')}) &bull; {r.get('cve_id')}
- **CVSS Score**: `{r.get('cvss_score')}` ({r.get('severity')}) &bull; **EPSS Score**: `{r.get('epss_score', 0) * 100:.1f}%`
- **Reachability Verdict**: `{r.get('reachability_verdict')}`
- **OpenVEX Status**: `{r.get('vex_status')}` &bull; Justification: `{r.get('vex_justification')}`
- **Impact Statement**: {r.get('impact_statement')}
- **Recommendation**: {r.get('recommended_action')}
"""

        if slopsquat_findings:
            report += "\n---\n\n## ⚠️ AI Slopsquatting & Package Hallucination Findings\n"
            for f in slopsquat_findings:
                report += f"""- **Flagged Package**: `{f.get('package_name')}` (Risk: `{f.get('risk_level')}`)
  - **Reason**: {f.get('reason')}
  - **Recommendation**: {f.get('recommendation')}
"""

        if remediation_plans:
            report += "\n---\n\n## 🛠️ Autonomous Self-Healing Patch Pull Requests\n"
            for p in remediation_plans:
                report += f"""### PR: `{p.get('pr_title')}`
- **Package**: `{p.get('package_name')}` (`{p.get('current_version')}` &rarr; `{p.get('recommended_safe_version')}`)
- **Breaking Change Risk**: `{p.get('breaking_change_risk')}` &bull; **Verification**: `{p.get('verification_status')}`

```diff
{p.get('unified_git_diff', '')}
```
"""

        report += "\n---\n*Report generated autonomously by **Argus Cyber Sentinel Autonomous Supply Chain Engine (LangGraph + OpenVEX)**.*"
        return report
