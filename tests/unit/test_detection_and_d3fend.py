"""Unit tests for Detection Engineering (Sigma, YARA, STIX 2.1) & MITRE D3FEND."""

import pytest
import yaml
from tools.detection import generate_sigma_rule, generate_yara_rule, export_stix21_bundle
from tools.mitre import map_to_mitre, map_to_d3fend


def test_generate_sigma_rule():
    """Verifies Sigma rule YAML generation adheres to specification."""
    res = generate_sigma_rule(
        title="Test C2 Detection",
        ioc_type="IP",
        ioc_value="185.220.101.45",
        threat_description="Cobalt Strike C2",
        mitre_technique="T1071.001"
    )
    assert res.success is True
    assert "sigma_yaml" in res.data
    parsed = yaml.safe_load(res.data["sigma_yaml"])
    assert parsed["detection"]["selection"]["DestinationIp"] == "185.220.101.45"
    assert "attack.t1071_001" in parsed["tags"]


def test_generate_yara_rule():
    """Verifies YARA rule syntax and strings."""
    res = generate_yara_rule(
        rule_name="cobalt_strike_185",
        ioc_value="185.220.101.45",
        threat_family="CobaltStrike"
    )
    assert res.success is True
    assert "rule rule_cobalt_strike_185" in res.data["yara_code"]
    assert '185.220.101.45' in res.data["yara_code"]
    assert "$magic_header at 0" in res.data["yara_code"]


def test_export_stix21_bundle():
    """Verifies STIX 2.1 JSON bundle structure and relationships."""
    res = export_stix21_bundle(
        investigation_id="INV-999",
        seed_ioc="185.220.101.45",
        ioc_type="IP",
        verdict="CONFIRMED_MALICIOUS",
        mitre_technique="T1071.001"
    )
    assert res.success is True
    bundle = res.data["stix_bundle"]
    assert bundle["type"] == "bundle"
    assert bundle["spec_version"] == "2.1"
    assert len(bundle["objects"]) >= 4

    types = {obj["type"] for obj in bundle["objects"]}
    assert "threat-actor" in types
    assert "indicator" in types
    assert "infrastructure" in types
    assert "relationship" in types


def test_mitre_d3fend_countermeasures():
    """Verifies mapping from offensive ATT&CK technique to defensive D3FEND."""
    mitre_res = map_to_mitre("c2 cobalt strike")
    assert mitre_res.success is True
    assert "T1071" in mitre_res.data["primary_technique"]

    d3fend = mitre_res.data["d3fend_countermeasures"]
    assert len(d3fend) >= 1
    assert any("D3-NPA" in d["id"] or "D3-ITF" in d["id"] or "D3-OTF" in d["id"] for d in d3fend)

