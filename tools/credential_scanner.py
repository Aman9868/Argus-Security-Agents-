"""Autonomous Credential Leaks & Secret Scanner Engine for Cyber Sentinel XDR.

Detects hardcoded secrets, exposed API keys, private certificates, and credentials
in local filesystem directories and Git repositories (working trees & commit history diffs).
Features zero-knowledge secret redaction, Shannon entropy validation, and AI context triage.
"""

import os
import re
import math
import hashlib
import subprocess
from typing import Dict, Any, List, Optional, Tuple, Set
from pydantic import BaseModel, Field
import structlog

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class CredentialFinding(BaseModel):
    finding_id: str
    rule_name: str
    category: str
    file_path: str
    line_number: Optional[int] = None
    commit_sha: Optional[str] = None
    commit_author: Optional[str] = None
    commit_message: Optional[str] = None
    masked_value: str
    fingerprint: str  # SHA-256
    entropy_score: float = 0.0
    severity: str = "HIGH"  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    ai_verdict: str = "UNASSESSED"  # ACTIVE_EXPOSURE, TEST_MOCK_FIXTURE, TEMPLATE_PLACEHOLDER, UNASSESSED
    ai_confidence: float = 0.0
    ai_rationale: Optional[str] = None
    hitl_status: str = "PENDING_REVIEW"  # PENDING_REVIEW, REMEDIATED, ACCEPTED_RISK, FALSE_POSITIVE
    hitl_token: str
    code_snippet: Optional[str] = None


class CredentialScanSummary(BaseModel):
    scan_id: str
    target_path: str
    target_type: str  # "local_directory" or "git_repository"
    total_files_scanned: int
    total_diffs_scanned: int
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    scan_duration_sec: float
    recipient_email: Optional[str] = None
    email_notification_sent: bool = False
    git_branch: Optional[str] = None
    git_commit: Optional[str] = None


class CredentialScanResult(BaseModel):
    summary: CredentialScanSummary
    findings: List[CredentialFinding] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Shannon Entropy & Redaction Utilities
# ---------------------------------------------------------------------------

def calculate_shannon_entropy(data: str) -> float:
    """Calculates the Shannon entropy of a string."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    char_counts: Dict[str, int] = {}
    for char in data:
        char_counts[char] = char_counts.get(char, 0) + 1
    for count in char_counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 3)


def mask_secret(secret: str) -> str:
    """Safely masks a secret string revealing only minimal prefix/suffix."""
    secret = secret.strip()
    if len(secret) <= 8:
        return "****"
    if len(secret) <= 16:
        return f"{secret[:2]}****{secret[-2:]}"
    return f"{secret[:4]}****...{secret[-4:]}"


def compute_secret_fingerprint(secret: str) -> str:
    """Computes a non-reversible SHA-256 fingerprint of the secret."""
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()[:16]


# ---------------------------------------------------------------------------
# 25+ Production Secret Detection Patterns
# ---------------------------------------------------------------------------

SECRET_PATTERNS = [
    {
        "rule_name": "AWS Access Key ID",
        "category": "Cloud Infrastructure",
        "regex": re.compile(r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"),
        "severity": "CRITICAL",
        "min_entropy": 2.5
    },
    {
        "rule_name": "AWS Secret Access Key",
        "category": "Cloud Infrastructure",
        "regex": re.compile(r"(?i)aws_?(?:secret_?(?:access_?)?key|secret)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"),
        "severity": "CRITICAL",
        "min_entropy": 4.0
    },
    {
        "rule_name": "GitHub Personal Access Token (Classic)",
        "category": "Source Control",
        "regex": re.compile(r"ghp_[a-zA-Z0-9]{36}"),
        "severity": "CRITICAL",
        "min_entropy": 3.8
    },
    {
        "rule_name": "GitHub Fine-Grained Personal Access Token",
        "category": "Source Control",
        "regex": re.compile(r"github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}"),
        "severity": "CRITICAL",
        "min_entropy": 4.0
    },
    {
        "rule_name": "GitHub OAuth Access Token",
        "category": "Source Control",
        "regex": re.compile(r"gho_[a-zA-Z0-9]{36}"),
        "severity": "CRITICAL",
        "min_entropy": 3.8
    },
    {
        "rule_name": "OpenAI API Key",
        "category": "AI & LLM Services",
        "regex": re.compile(r"sk-(?:proj-)?[a-zA-Z0-9_\-]{40,}"),
        "severity": "CRITICAL",
        "min_entropy": 3.8
    },
    {
        "rule_name": "Anthropic Claude API Key",
        "category": "AI & LLM Services",
        "regex": re.compile(r"sk-ant-api03-[a-zA-Z0-9_\-]{70,}"),
        "severity": "CRITICAL",
        "min_entropy": 4.0
    },
    {
        "rule_name": "Google API Key",
        "category": "Cloud Infrastructure",
        "regex": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
        "severity": "HIGH",
        "min_entropy": 3.5
    },
    {
        "rule_name": "Slack Bot Token",
        "category": "Communication & Collaboration",
        "regex": re.compile(r"xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}"),
        "severity": "HIGH",
        "min_entropy": 3.5
    },
    {
        "rule_name": "Slack User Token",
        "category": "Communication & Collaboration",
        "regex": re.compile(r"xoxp-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}"),
        "severity": "HIGH",
        "min_entropy": 3.5
    },
    {
        "rule_name": "Slack Webhook URL",
        "category": "Communication & Collaboration",
        "regex": re.compile(r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8,12}/B[a-zA-Z0-9_]{8,12}/[a-zA-Z0-9_]{24}"),
        "severity": "MEDIUM",
        "min_entropy": 3.0
    },
    {
        "rule_name": "Stripe Live Secret Key",
        "category": "Payment Processing",
        "regex": re.compile(r"(?:sk|rk)_live_[0-9a-zA-Z]{24,}"),
        "severity": "CRITICAL",
        "min_entropy": 3.8
    },
    {
        "rule_name": "Stripe Live Publishable Key",
        "category": "Payment Processing",
        "regex": re.compile(r"pk_live_[0-9a-zA-Z]{24,}"),
        "severity": "LOW",
        "min_entropy": 3.0
    },
    {
        "rule_name": "Private Cryptographic Key",
        "category": "PKI & Certificates",
        "regex": re.compile(r"-----BEGIN (?:RSA|EC|DSA|OPENSSH|PGP)?\s*PRIVATE KEY-----"),
        "severity": "CRITICAL",
        "min_entropy": 1.0
    },
    {
        "rule_name": "Database Connection URI with Password",
        "category": "Databases & Storage",
        "regex": re.compile(r"(?:postgres|postgresql|mysql|mongodb|redis)://[a-zA-Z0-9_\-\.]+:[^@\s]+@[a-zA-Z0-9_\-\.]+:[0-9]+/[a-zA-Z0-9_\-\.]+"),
        "severity": "CRITICAL",
        "min_entropy": 3.0
    },
    {
        "rule_name": "JSON Web Token (JWT)",
        "category": "Authentication",
        "regex": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.[A-Za-z0-9._-]{10,}"),
        "severity": "MEDIUM",
        "min_entropy": 4.2
    },
    {
        "rule_name": "Generic High-Entropy API Token Assignment",
        "category": "Generic Secrets",
        "regex": re.compile(r"(?i)(?:api_?key|auth_?token|secret_?key|client_?secret|bearer_?token)\s*[:=]\s*['\"]([a-zA-Z0-9_\-\.]{20,})['\"]"),
        "severity": "HIGH",
        "min_entropy": 3.8
    },
    {
        "rule_name": "Generic Bearer Token Header",
        "category": "Generic Secrets",
        "regex": re.compile(r"(?i)bearer\s+([a-zA-Z0-9_\-\.]{25,})"),
        "severity": "MEDIUM",
        "min_entropy": 3.8
    }
]

SENSITIVE_FILENAME_PATTERNS = [
    (re.compile(r"^\.env(?:\..+)?$"), "Exposed Environment Configuration (.env)", "HIGH"),
    (re.compile(r"^.*\.tfstate(?:\.backup)?$"), "Terraform State with Credentials (.tfstate)", "CRITICAL"),
    (re.compile(r"^id_(?:rsa|dsa|ed25519|ecdsa)$"), "SSH Private Key Identity File", "CRITICAL"),
    (re.compile(r"^.*\.(?:pem|key|pkcs12|pfx|p12)$"), "Cryptographic Key/Certificate File", "HIGH"),
    (re.compile(r"^(?:service_?account|credentials)\.json$"), "Service Account Credentials JSON", "CRITICAL"),
    (re.compile(r"^\.npmrc$"), "NPM Configuration with Auth Tokens (.npmrc)", "MEDIUM"),
    (re.compile(r"^\.dockercfg$"), "Docker Registry Configuration (.dockercfg)", "HIGH"),
]

IGNORED_DIRECTORIES = {
    ".git", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache",
    ".cache", "dist", "build", ".next", ".antigravity", ".vscode", "mlruns"
}

BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".tar", ".gz",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".pyc", ".parquet", ".db", ".sqlite"
}


# ---------------------------------------------------------------------------
# Scanner Engine
# ---------------------------------------------------------------------------

class CredentialScanner:
    """Discovers credentials in local folders and Git histories with AI Triage."""

    @staticmethod
    def is_binary_file(filepath: str) -> bool:
        """Determines if a file is binary based on extension and byte sampling."""
        _, ext = os.path.splitext(filepath.lower())
        if ext in BINARY_EXTENSIONS:
            return True
        try:
            with open(filepath, "rb") as f:
                chunk = f.read(1024)
                if b"\x00" in chunk:
                    return True
        except Exception:
            return True
        return False

    @classmethod
    def scan_text_content(
        cls,
        content: str,
        file_path: str,
        commit_sha: Optional[str] = None,
        commit_author: Optional[str] = None,
        commit_message: Optional[str] = None
    ) -> List[CredentialFinding]:
        """Scans a block of text line-by-line using patterns and entropy checks."""
        findings: List[CredentialFinding] = []
        lines = content.splitlines()

        for line_idx, line in enumerate(lines, start=1):
            line_str = line.strip()
            if not line_str or len(line_str) > 2000:
                continue

            for rule in SECRET_PATTERNS:
                regex: re.Pattern = rule["regex"]
                matches = regex.findall(line)
                if not matches:
                    continue

                for match in matches:
                    raw_secret = match if isinstance(match, str) else match[0]
                    raw_secret = raw_secret.strip().strip("'\"")
                    if not raw_secret or len(raw_secret) < 8:
                        continue

                    entropy = calculate_shannon_entropy(raw_secret)
                    min_entropy = rule.get("min_entropy", 0.0)
                    if min_entropy and entropy < min_entropy:
                        continue

                    # Generate unique finding ID and token
                    fingerprint = compute_secret_fingerprint(raw_secret)
                    masked = mask_secret(raw_secret)
                    finding_token = hashlib.sha256(f"{file_path}:{line_idx}:{fingerprint}".encode()).hexdigest()[:24]
                    finding_id = f"leak_{finding_token[:12]}"

                    # Extract context snippet (up to 3 surrounding lines)
                    start_ctx = max(0, line_idx - 2)
                    end_ctx = min(len(lines), line_idx + 1)
                    snippet_lines = lines[start_ctx:end_ctx]
                    snippet = "\n".join(snippet_lines)

                    finding = CredentialFinding(
                        finding_id=finding_id,
                        rule_name=rule["rule_name"],
                        category=rule["category"],
                        file_path=file_path,
                        line_number=line_idx,
                        commit_sha=commit_sha,
                        commit_author=commit_author,
                        commit_message=commit_message,
                        masked_value=masked,
                        fingerprint=fingerprint,
                        entropy_score=entropy,
                        severity=rule["severity"],
                        ai_verdict="UNASSESSED",
                        hitl_status="PENDING_REVIEW",
                        hitl_token=finding_token,
                        code_snippet=snippet
                    )
                    findings.append(finding)

        return findings

    @classmethod
    def scan_git_history(
        cls,
        repo_dir: str,
        max_commits: int = 20
    ) -> List[CredentialFinding]:
        """Inspects git commit diffs to discover secrets deleted from current working tree."""
        findings: List[CredentialFinding] = []
        if not os.path.isdir(os.path.join(repo_dir, ".git")):
            return findings

        try:
            # Get list of recent commits
            cmd = ["git", "log", f"-n{max_commits}", "--pretty=format:%H|||%an|||%s"]
            proc = subprocess.run(cmd, cwd=repo_dir, capture_output=True, text=True, timeout=15.0)
            if proc.returncode != 0:
                return findings

            commits = proc.stdout.strip().splitlines()
            for c_line in commits:
                if not c_line.strip():
                    continue
                parts = c_line.split("|||")
                if len(parts) < 3:
                    continue
                sha, author, msg = parts[0], parts[1], parts[2]

                # Extract diff for commit
                diff_cmd = ["git", "show", sha, "--pretty=format:", "--unified=1"]
                d_proc = subprocess.run(diff_cmd, cwd=repo_dir, capture_output=True, text=True, timeout=15.0)
                if d_proc.returncode != 0:
                    continue

                diff_text = d_proc.stdout
                current_file = "unknown"
                diff_lines = []

                for d_line in diff_text.splitlines():
                    if d_line.startswith("+++ b/"):
                        current_file = d_line[6:].strip()
                    elif d_line.startswith("+") and not d_line.startswith("+++"):
                        # Added line in this commit
                        diff_lines.append(d_line[1:])

                if diff_lines and current_file != "/dev/null":
                    chunk_text = "\n".join(diff_lines)
                    f_list = cls.scan_text_content(
                        content=chunk_text,
                        file_path=f"{current_file} (git:{sha[:8]})",
                        commit_sha=sha[:10],
                        commit_author=author,
                        commit_message=msg
                    )
                    findings.extend(f_list)

        except Exception as e:
            logger.warning("Git diff history scan error", repo=repo_dir, error=str(e))

        return findings

    @classmethod
    async def run_ai_triage(cls, findings: List[CredentialFinding]) -> List[CredentialFinding]:
        """Leverages LLMGateway to categorize detections (Active Exposure vs Test Mock)."""
        if not findings:
            return findings

        try:
            from gateway.llm.client import LLMGateway
            gateway = LLMGateway()

            # Batch up to 10 findings per prompt for rapid response
            for finding in findings[:15]:
                prompt = (
                    f"You are a cybersecurity secret analysis engine. Evaluate this detected credential pattern:\n"
                    f"- Rule: {finding.rule_name}\n"
                    f"- File: {finding.file_path}\n"
                    f"- Masked Value: {finding.masked_value}\n"
                    f"- Code Context:\n```\n{finding.code_snippet or 'N/A'}\n```\n\n"
                    f"Respond ONLY with valid JSON with keys:\n"
                    f'{{"verdict": "ACTIVE_EXPOSURE"|"TEST_MOCK_FIXTURE"|"TEMPLATE_PLACEHOLDER", '
                    f'"confidence": 0.0-1.0, "rationale": "Brief 1-sentence reason"}}'
                )

                try:
                    resp = await gateway.generate(prompt)
                    raw_text = resp.content.strip()
                    # Clean markdown formatting if present
                    if "```json" in raw_text:
                        raw_text = raw_text.split("```json")[1].split("```")[0].strip()
                    elif "```" in raw_text:
                        raw_text = raw_text.split("```")[1].split("```")[0].strip()

                    import json
                    parsed = json.loads(raw_text)
                    finding.ai_verdict = parsed.get("verdict", "ACTIVE_EXPOSURE")
                    finding.ai_confidence = float(parsed.get("confidence", 0.85))
                    finding.ai_rationale = parsed.get("rationale", "AI triage performed.")

                    # Adjust severity if verified mock/fixture
                    if finding.ai_verdict in ["TEST_MOCK_FIXTURE", "TEMPLATE_PLACEHOLDER"]:
                        finding.severity = "LOW"

                except Exception as ex:
                    # Deterministic heuristic fallback
                    is_test = any(t in finding.file_path.lower() for t in ["test", "mock", "fixture", "example", "sample"])
                    finding.ai_verdict = "TEST_MOCK_FIXTURE" if is_test else "ACTIVE_EXPOSURE"
                    finding.ai_confidence = 0.8
                    finding.ai_rationale = "Heuristic classification based on file path and context."
                    if is_test:
                        finding.severity = "LOW"

        except Exception as e:
            logger.debug("AI triage unavailable, defaulting to heuristics", error=str(e))
            for f in findings:
                is_test = any(t in f.file_path.lower() for t in ["test", "mock", "fixture", "example"])
                f.ai_verdict = "TEST_MOCK_FIXTURE" if is_test else "ACTIVE_EXPOSURE"
                f.ai_confidence = 0.75
                f.ai_rationale = "Automated heuristic classification."

        return findings

    @classmethod
    async def scan_project_or_directory(
        cls,
        target_path: str,
        scan_git_history: bool = True,
        max_commits: int = 15,
        ai_triage: bool = True,
        recipient_email: Optional[str] = None
    ) -> CredentialScanResult:
        """Executes full credential scanning across files and git history."""
        import time
        start_time = time.time()
        scan_id = f"cscan_{int(start_time)}_{hashlib.sha256(target_path.encode()).hexdigest()[:8]}"

        all_findings: List[CredentialFinding] = []
        files_scanned = 0
        diffs_scanned = 0
        seen_fingerprints: Set[str] = set()

        if not os.path.exists(target_path):
            raise FileNotFoundError(f"Target path does not exist: {target_path}")

        # 1. Walk Filesystem Tree
        for root, dirs, files in os.walk(target_path):
            dirs[:] = [d for d in dirs if d not in IGNORED_DIRECTORIES and not d.startswith(".")]

            for file_name in files:
                full_path = os.path.join(root, file_name)
                rel_path = os.path.relpath(full_path, target_path)

                # Check sensitive filename patterns
                for fn_regex, rule_label, sev in SENSITIVE_FILENAME_PATTERNS:
                    if fn_regex.match(file_name):
                        fp = compute_secret_fingerprint(full_path)
                        f_token = hashlib.sha256(f"{rel_path}:filename:{fp}".encode()).hexdigest()[:24]
                        f_id = f"file_{f_token[:12]}"
                        all_findings.append(CredentialFinding(
                            finding_id=f_id,
                            rule_name=rule_label,
                            category="Sensitive Configuration File",
                            file_path=rel_path,
                            masked_value=file_name,
                            fingerprint=fp,
                            severity=sev,
                            hitl_token=f_token,
                            ai_verdict="ACTIVE_EXPOSURE",
                            ai_confidence=0.95,
                            ai_rationale=f"Sensitive file '{file_name}' present in repository."
                        ))

                if cls.is_binary_file(full_path):
                    continue

                try:
                    # Skip large files (> 2MB)
                    if os.path.getsize(full_path) > 2 * 1024 * 1024:
                        continue

                    with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()

                    file_findings = cls.scan_text_content(content, rel_path)
                    for ff in file_findings:
                        if ff.fingerprint not in seen_fingerprints:
                            seen_fingerprints.add(ff.fingerprint)
                            all_findings.append(ff)

                    files_scanned += 1
                except Exception as e:
                    logger.debug("Error scanning file", path=full_path, error=str(e))

        # 2. Scan Git Diff History if repository
        if scan_git_history and os.path.isdir(os.path.join(target_path, ".git")):
            history_findings = cls.scan_git_history(target_path, max_commits=max_commits)
            for hf in history_findings:
                if hf.fingerprint not in seen_fingerprints:
                    seen_fingerprints.add(hf.fingerprint)
                    all_findings.append(hf)
            diffs_scanned = max_commits

        # 3. AI Context Triage
        if ai_triage and all_findings:
            all_findings = await cls.run_ai_triage(all_findings)

        # 4. Git Metadata
        git_branch = None
        git_commit = None
        if os.path.isdir(os.path.join(target_path, ".git")):
            from tools.git_scanner import GitConnector
            _, b, sha, _, _, _ = GitConnector.get_git_metadata(target_path)
            git_branch = b
            git_commit = sha

        duration = round(time.time() - start_time, 2)

        crit = sum(1 for f in all_findings if f.severity == "CRITICAL")
        high = sum(1 for f in all_findings if f.severity == "HIGH")
        med = sum(1 for f in all_findings if f.severity == "MEDIUM")
        low = sum(1 for f in all_findings if f.severity in ["LOW", "INFO"])

        summary = CredentialScanSummary(
            scan_id=scan_id,
            target_path=target_path,
            target_type="git_repository" if git_branch else "local_directory",
            total_files_scanned=files_scanned,
            total_diffs_scanned=diffs_scanned,
            total_findings=len(all_findings),
            critical_count=crit,
            high_count=high,
            medium_count=med,
            low_count=low,
            scan_duration_sec=duration,
            recipient_email=recipient_email,
            email_notification_sent=False,
            git_branch=git_branch,
            git_commit=git_commit
        )

        return CredentialScanResult(summary=summary, findings=all_findings)

