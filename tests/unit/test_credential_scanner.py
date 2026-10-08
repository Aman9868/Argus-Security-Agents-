"""Unit tests for the Credential Leaks Scanner engine and Email Service."""

import pytest
import os
import tempfile
from tools.credential_scanner import (
    calculate_shannon_entropy,
    mask_secret,
    compute_secret_fingerprint,
    CredentialScanner
)
from services.email_service import EmailService


def test_shannon_entropy():
    # Constant string has 0 entropy
    assert calculate_shannon_entropy("aaaaaaaaaa") == 0.0
    # Low entropy repeated string
    assert calculate_shannon_entropy("ababababab") <= 1.0
    # High entropy base64 string
    high_ent = calculate_shannon_entropy("dGhpcyBpcyBhIHJhbmRvbSBzZWNyZXQga2V5")
    assert high_ent > 3.0


def test_secret_masking():
    raw_secret = "ghp_1234567890abcdef1234567890abcdef"
    masked = mask_secret(raw_secret)
    # Never expose full secret
    assert masked != raw_secret
    assert "****" in masked
    assert masked.startswith("ghp_")
    assert masked.endswith("cdef")


def test_secret_fingerprint():
    raw_secret = "sk-proj-supersecretkey123456789012345"
    fp1 = compute_secret_fingerprint(raw_secret)
    fp2 = compute_secret_fingerprint(raw_secret)
    assert fp1 == fp2
    assert len(fp1) == 16
    assert compute_secret_fingerprint("different_secret") != fp1


def test_scan_text_content_detectors():
    sample_text = """
    # Configuration
    AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
    GITHUB_TOKEN = "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz1234567890"
    OPENAI_API_KEY = "sk-proj-1234567890abcdefghijklmnopqrstuvwxyz1234567890"
    DATABASE_URL = "postgres://admin:supersecretpw123@db.internal.net:5432/proddb"
    """
    findings = CredentialScanner.scan_text_content(sample_text, "config.py")
    rule_names = [f.rule_name for f in findings]

    assert any("AWS Access Key" in r for r in rule_names)
    assert any("GitHub" in r for r in rule_names)
    assert any("OpenAI" in r for r in rule_names)
    assert any("Database" in r for r in rule_names)

    # Ensure all findings have HITL tokens and masked values
    for f in findings:
        assert f.hitl_token is not None
        assert "****" in f.masked_value
        assert f.hitl_status == "PENDING_REVIEW"


@pytest.mark.asyncio
async def test_scan_directory_with_sensitive_files():
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create a sensitive .env file
        env_file = os.path.join(tmpdir, ".env")
        with open(env_file, "w") as f:
            f.write("SECRET_KEY=ghp_dummytokenforunittestonly12345678\n")

        # Create a normal file with an API key
        app_file = os.path.join(tmpdir, "app.py")
        with open(app_file, "w") as f:
            f.write('OPENAI_KEY = "sk-proj-fakekeyfortesting1234567890abcdef12345678"\n')

        res = await CredentialScanner.scan_project_or_directory(
            target_path=tmpdir,
            scan_git_history=False,
            ai_triage=False
        )

        assert res.summary.total_findings >= 2
        rule_names = [f.rule_name for f in res.findings]
        assert any("Exposed Environment Configuration" in r for r in rule_names)
        assert any("OpenAI API Key" in r for r in rule_names)


def test_email_html_generation():
    findings = [{
        "finding_id": "leak_test123",
        "rule_name": "AWS Access Key ID",
        "category": "Cloud Infrastructure",
        "file_path": "deploy/terraform.tf",
        "line_number": 42,
        "masked_value": "AKIA****MPLE",
        "severity": "CRITICAL",
        "ai_verdict": "ACTIVE_EXPOSURE",
        "hitl_token": "token_abc_123_xyz"
    }]

    html = EmailService.generate_html_alert(
        recipient_email="sec-ops@company.com",
        scan_id="scan_unit_001",
        target_path="/projects/my-app",
        target_type="local_directory",
        total_findings=1,
        critical_count=1,
        high_count=0,
        medium_count=0,
        low_count=0,
        findings=findings
    )

    assert "CYBER SENTINEL XDR" in html
    assert "token_abc_123_xyz" in html
    assert "AKIA****MPLE" in html
    assert "Remediate" in html
    assert "Accept" in html

