"""Unit tests for Autonomous Quishing & Advanced Phishing Forensic Engine."""

import pytest
from tools.quishing_engine import QuishingForensicEngine
from storage.db import (
    save_phishing_investigation,
    get_phishing_investigation,
    get_all_phishing_investigations
)

def test_list_samples():
    """Verify available pre-configured phishing/quishing samples."""
    samples = QuishingForensicEngine.list_samples()
    assert len(samples) >= 3
    sample_ids = [s["sample_id"] for s in samples]
    assert "sample_quishing_m365" in sample_ids
    assert "sample_quishing_payroll" in sample_ids
    assert "sample_docusign_invoice" in sample_ids

def test_analyze_m365_quishing_sample():
    """Verify in-depth forensic analysis of M365 MFA Quishing sample."""
    analysis = QuishingForensicEngine.analyze_sample("sample_quishing_m365")

    assert analysis["sample_id"] == "sample_quishing_m365"
    assert "analysis_id" in analysis
    assert analysis["risk_score"] >= 90
    assert "CRITICAL" in analysis["verdict"]

    # Verify Email Header & Envelope Details
    assert "admin-notice" in analysis["sender"] or "IT Support Desk" in analysis["sender"]
    assert "URGENT" in analysis["subject"].upper()
    headers = analysis["headers"]
    assert headers["spf"]["status"] == "FAIL"
    assert headers["dkim"]["status"] == "FAIL"
    assert headers["dmarc"]["policy"] == "reject"

    # Verify Homoglyph detection
    assert headers["homograph_detected"] is True
    assert "mіcrosoft" in headers["homograph_details"]

    # Verify Optical QR Code extraction
    assert analysis["has_qr_code"] is True
    qr_data = analysis["qr_data"]
    assert qr_data is not None
    assert "google.com/url?q=" in qr_data["raw_encoded_payload"]
    assert qr_data["format"] == "QR_CODE_MATRIX_2D"

    # Verify multi-hop redirect unrolling
    chain = analysis["redirect_chain"]
    assert len(chain) >= 3
    assert any("Redirector" in hop["evasion_technique"] or "Google" in hop["evasion_technique"] for hop in chain)
    assert any("Evilginx" in hop["evasion_technique"] or "Reverse Proxy" in hop["evasion_technique"] for hop in chain)

    # Verify Landing page / Harvester Fingerprinting
    landing = analysis["landing_page_analysis"]
    assert "Microsoft 365" in landing["spoofed_brand"]
    assert any("Password" in field for field in landing["harvested_fields"])
    assert any("TOTP" in field or "MFA" in field for field in landing["harvested_fields"])

    # Verify Remediation Playbook
    playbook = analysis["remediation_playbook"]
    assert len(playbook) >= 3
    assert any("HardDelete" in item["command"] for item in playbook)
    assert any("New-TenantAllowBlockListItems" in item["command"] for item in playbook)

def test_analyze_payroll_quishing_sample():
    """Verify Quishing analysis for ADP payroll lure."""
    analysis = QuishingForensicEngine.analyze_sample("sample_quishing_payroll")

    assert analysis["risk_score"] >= 80
    assert "Payroll" in analysis["subject"]
    assert analysis["has_qr_code"] is True
    assert any("bit.ly" in hop["url"] for hop in analysis["redirect_chain"])

def test_analyze_custom_email_envelope():
    """Verify custom raw email string parsing."""
    raw_email = (
        "From: admin@attacker-homoglyph-bank.com\n"
        "To: victim@company.internal\n"
        "Subject: Urgent Password Reset Required\n"
        "Date: Sun, 06 Sep 2026 12:00:00 GMT\n"
        "\n"
        "Please click https://login.bank-verify.ru/token=123"
    )
    analysis = QuishingForensicEngine.analyze_sample("custom_test", custom_text=raw_email)

    assert analysis["sample_id"] == "custom_test"
    assert "custom_test" in analysis["subject"] or "custom_test" in analysis["sample_id"]
    assert analysis["risk_score"] > 50

def test_execute_fleet_purge():
    """Verify enterprise fleet mailbox search-and-purge execution."""
    analysis = QuishingForensicEngine.analyze_sample("sample_quishing_m365")
    analysis_id = analysis["analysis_id"]

    purge_result = QuishingForensicEngine.execute_fleet_purge(analysis_id)

    assert purge_result["status"] == "COMPLETED"
    assert purge_result["analysis_id"] == analysis_id
    assert purge_result["mailboxes_scanned"] == 1420
    assert purge_result["mailboxes_purged"] > 0
    assert purge_result["threat_neutralized"] is True
    assert "TABL-" in purge_result["quarantine_rule_id"]

def test_phishing_db_persistence():
    """Verify SQLite storage and retrieval for phishing investigations."""
    analysis = QuishingForensicEngine.analyze_sample("sample_docusign_invoice")
    analysis_id = analysis["analysis_id"]

    # Save to DB
    save_phishing_investigation(analysis)

    # Retrieve by ID
    retrieved = get_phishing_investigation(analysis_id)
    assert retrieved is not None
    assert retrieved["analysis_id"] == analysis_id
    assert retrieved["sample_id"] == "sample_docusign_invoice"
    assert retrieved["verdict"] == analysis["verdict"]
    assert retrieved["risk_score"] == analysis["risk_score"]

    # Retrieve all
    history = get_all_phishing_investigations()
    assert len(history) >= 1
    assert any(item["analysis_id"] == analysis_id for item in history)
