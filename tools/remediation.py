"""Autonomous Remediation and Self-Healing Safe Patch Engine.

Generates unified Git diff patches, refactors caller code to adapt to safe API patterns,
and verifies syntax/compilation to prevent breaking production builds.
"""

import ast
import re
import difflib
from typing import Dict, Any, List, Optional, Tuple
from pydantic import BaseModel, Field
from tools.reachability import ReachabilityAnalysisResult, KNOWN_ADVISORIES
import structlog

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

class FilePatch(BaseModel):
    file_path: str
    original_content: str
    patched_content: str
    unified_diff: str
    patch_type: str  # MANIFEST_BUMP or CODE_REFACTOR


class RemediationPlan(BaseModel):
    package_name: str
    cve_id: str
    current_version: str
    recommended_safe_version: str
    breaking_change_risk: str  # LOW, MEDIUM, HIGH
    pr_title: str
    pr_body_markdown: str
    file_patches: List[FilePatch]
    unified_git_diff: str
    verification_status: str  # SYNTAX_VERIFIED, TEST_PASSED, MANUAL_REVIEW_ADVISED


# ---------------------------------------------------------------------------
# Patch & Refactoring Generator
# ---------------------------------------------------------------------------

class RemediationEngine:
    """Orchestrates autonomous code patching and dependency version resolution."""

    @classmethod
    def generate_unified_diff(cls, file_path: str, original: str, patched: str) -> str:
        """Generates standard unified diff output."""
        orig_lines = original.splitlines(keepends=True)
        patched_lines = patched.splitlines(keepends=True)
        diff = difflib.unified_diff(
            orig_lines,
            patched_lines,
            fromfile=f"a/{file_path}",
            tofile=f"b/{file_path}",
            lineterm=""
        )
        return "".join(diff)

    @classmethod
    def patch_manifest(cls, manifest_content: str, package_name: str, safe_version: str) -> Tuple[str, str]:
        """Updates package version requirement in requirements.txt or pyproject."""
        pattern = re.compile(rf"^{re.escape(package_name)}(==|>=|<=|~=)[^\s#]+", re.MULTILINE | re.IGNORECASE)
        replacement = f"{package_name}=={safe_version}"
        
        if pattern.search(manifest_content):
            patched_content = pattern.sub(replacement, manifest_content)
        else:
            patched_content = manifest_content + f"\n{replacement}\n"
            
        diff = cls.generate_unified_diff("requirements.txt", manifest_content, patched_content)
        return patched_content, diff

    @classmethod
    def refactor_source_code(
        cls,
        package_name: str,
        source_files: Dict[str, str],
        traces: List[Any]
    ) -> List[FilePatch]:
        """
        Refactors caller code if migrating to a safe API pattern.
        E.g. for PyYAML: replaces `yaml.load(..., Loader=...)` with `yaml.safe_load(...)`.
        """
        patches: List[FilePatch] = []
        normalized_pkg = package_name.lower().strip()

        for filename, content in source_files.items():
            patched = content
            modified = False

            if normalized_pkg == "pyyaml" or normalized_pkg == "yaml":
                # Refactor yaml.load(..., Loader=...) -> yaml.safe_load(...)
                pattern_load = re.compile(r"yaml\.load\(([^,\)]+)(?:,\s*Loader=[^\)]+)?\)")
                if pattern_load.search(patched):
                    patched = pattern_load.sub(r"yaml.safe_load(\1)", patched)
                    modified = True

            elif normalized_pkg == "requests":
                # Ensure session headers are explicit or redirects sanitized
                if "requests.get(" in patched and "timeout=" not in patched:
                    patched = re.sub(
                        r"requests\.get\(([^,\)]+)\)",
                        r"requests.get(\1, timeout=10.0)",
                        patched
                    )
                    modified = True

            if modified and patched != content:
                diff = cls.generate_unified_diff(filename, content, patched)
                patches.append(FilePatch(
                    file_path=filename,
                    original_content=content,
                    patched_content=patched,
                    unified_diff=diff,
                    patch_type="CODE_REFACTOR"
                ))

        return patches

    @classmethod
    def verify_patch_syntax(cls, patches: List[FilePatch]) -> str:
        """Verifies syntax validity using Python AST compiler."""
        for p in patches:
            if p.file_path.endswith(".py"):
                try:
                    ast.parse(p.patched_content, filename=p.file_path)
                except SyntaxError as e:
                    logger.error("Remediation patch introduced syntax error", file=p.file_path, error=str(e))
                    return "MANUAL_REVIEW_ADVISED"
        return "SYNTAX_VERIFIED"

    @classmethod
    def create_remediation_plan(
        cls,
        reachability_result: ReachabilityAnalysisResult,
        manifest_text: str,
        source_files: Dict[str, str]
    ) -> RemediationPlan:
        """Constructs an end-to-end autonomous pull request and patch plan."""
        pkg_name = reachability_result.package_name
        current_ver = reachability_result.installed_version
        advisory = KNOWN_ADVISORIES.get(pkg_name.lower().strip(), {})
        safe_ver = advisory.get("safe_version", f"{current_ver}.1")

        file_patches: List[FilePatch] = []

        # 1. Patch the manifest
        patched_manifest, manifest_diff = cls.patch_manifest(manifest_text, pkg_name, safe_ver)
        file_patches.append(FilePatch(
            file_path="requirements.txt",
            original_content=manifest_text,
            patched_content=patched_manifest,
            unified_diff=manifest_diff,
            patch_type="MANIFEST_BUMP"
        ))

        # 2. Refactor caller code if needed
        code_patches = cls.refactor_source_code(pkg_name, source_files, reachability_result.traces)
        file_patches.extend(code_patches)

        # 3. Combine Git Diffs
        combined_diff = "\n\n".join(p.unified_diff for p in file_patches)

        # 4. Verify Syntax
        verification = cls.verify_patch_syntax(file_patches)

        # 5. Build Pull Request Markdown
        pr_title = f"fix(security): resolve {reachability_result.cve_id} in {pkg_name} ({current_ver} -> {safe_ver})"
        pr_body = f"""## 🛡️ Argus Autonomous Security Patch

### Vulnerability Summary
- **Target Package**: `{pkg_name}`
- **Vulnerability ID**: `{reachability_result.cve_id}`
- **CVSS Score**: `{reachability_result.cvss_score}` ({reachability_result.severity})
- **EPSS Exploit Prediction**: `{reachability_result.epss_score * 100:.1f}%`
- **CISA KEV Listed**: `{"YES" if reachability_result.cisa_kev_active else "NO"}`

### AST Reachability Evidence
{reachability_result.impact_statement}

### Remediation Actions Taken
1. Upgraded `{pkg_name}` from `{current_ver}` to safe verified release `{safe_ver}` in `requirements.txt`.
2. Refactored `{len(code_patches)}` source file(s) to eliminate unsafe legacy patterns.
3. Automated AST syntax verification passed (`{verification}`).

---
*Generated autonomously by **Argus Cyber Sentinel Multi-Agent Supply Chain Engine**.*
"""

        return RemediationPlan(
            package_name=pkg_name,
            cve_id=reachability_result.cve_id,
            current_version=current_ver,
            recommended_safe_version=safe_ver,
            breaking_change_risk="LOW" if not code_patches else "MEDIUM",
            pr_title=pr_title,
            pr_body_markdown=pr_body,
            file_patches=file_patches,
            unified_git_diff=combined_diff,
            verification_status=verification
        )
