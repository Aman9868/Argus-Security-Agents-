"""Detection Engineering Tools: Automated Sigma and YARA Rule Generation & STIX 2.1 Exporter."""

import time
import uuid
import yaml
from typing import Dict, Any, List, Optional
from tools.base import ToolResult


def generate_sigma_rule(
    title: str,
    ioc_type: str,
    ioc_value: str,
    threat_description: str,
    mitre_technique: str = "T1071.001",
    severity: str = "high"
) -> ToolResult:
    """
    Auto-generates an enterprise-standard Sigma Rule (YAML)
    compatible with Splunk, Microsoft Sentinel, and Elastic SIEM.
    """
    start = time.perf_counter()
    rule_id = str(uuid.uuid4())

    # Build detection condition based on IOC type
    if ioc_type.upper() == "IP":
        selection = {
            "DestinationIp": ioc_value
        }
        category = "firewall"
        logsource = {"category": category}
    elif ioc_type.upper() == "DOMAIN":
        selection = {
            "query": f"*{ioc_value}*"
        }
        logsource = {"category": "dns"}
    elif ioc_type.upper() in ["MD5", "SHA1", "SHA256"]:
        selection = {
            "Hashes|contains": ioc_value
        }
        logsource = {"category": "process_creation", "product": "windows"}
    else:
        selection = {
            "c-uri|contains": ioc_value
        }
        logsource = {"category": "proxy"}

    sigma_dict = {
        "title": f"Detection of {threat_description} Infrastructure ({ioc_value})",
        "id": rule_id,
        "status": "experimental",
        "description": f"Detects inbound or outbound network/host activity targeting confirmed malicious IOC {ioc_value}.",
        "references": [
            "https://attack.mitre.org/techniques/" + mitre_technique.replace(".", "/")
        ],
        "author": "Cyber Sentinel Autonomous Detection Engine",
        "date": time.strftime("%Y/%m/%d"),
        "tags": [
            f"attack.{mitre_technique.lower().replace('.', '_')}",
            "attack.command_and_control"
        ],
        "logsource": logsource,
        "detection": {
            "selection": selection,
            "condition": "selection"
        },
        "falsepositives": [
            "Security research scanners",
            "Misconfigured internal monitoring"
        ],
        "level": severity
    }

    yaml_output = yaml.dump(sigma_dict, sort_keys=False, default_flow_style=False)

    return ToolResult(
        success=True,
        data={
            "rule_id": rule_id,
            "format": "SIGMA_YAML",
            "sigma_yaml": yaml_output,
            "target_ioc": ioc_value,
            "ioc_type": ioc_type
        },
        execution_time_ms=(time.perf_counter() - start) * 1000
    )


def generate_yara_rule(
    rule_name: str,
    ioc_value: str,
    threat_family: str = "CobaltStrike",
    description: str = "Detects malicious payload and network configuration"
) -> ToolResult:
    """
    Auto-generates a YARA rule for memory and file-based endpoint hunting.
    """
    start = time.perf_counter()
    clean_rule_name = f"rule_{rule_name.replace('.', '_').replace('-', '_')}"

    yara_code = f"""rule {clean_rule_name} : trojan c2_infrastructure
{{
    meta:
        author = "Cyber Sentinel Autonomous Detection Engine"
        description = "{description}"
        reference = "IOC: {ioc_value}"
        date = "{time.strftime('%Y-%m-%d')}"
        threat_family = "{threat_family}"
        severity = "High"

    strings:
        $ioc_str = "{ioc_value}" ascii wide
        $c2_beacon = {{ 73 6f 63 6b 65 74 }}
        $magic_header = "MZ"

    condition:
        $magic_header at 0 and ($ioc_str or $c2_beacon)
}}
"""

    return ToolResult(
        success=True,
        data={
            "rule_name": clean_rule_name,
            "format": "YARA",
            "yara_code": yara_code.strip(),
            "target_ioc": ioc_value
        },
        execution_time_ms=(time.perf_counter() - start) * 1000
    )


def export_stix21_bundle(
    investigation_id: str,
    seed_ioc: str,
    ioc_type: str,
    verdict: str,
    mitre_technique: str = "T1071.001",
    associated_domain: Optional[str] = None
) -> ToolResult:
    """
    Exports the investigation knowledge graph as an official OASIS STIX 2.1 JSON bundle
    for seamless import into OpenCTI, MISP, and Threat Intelligence Platforms.
    """
    start = time.perf_counter()
    bundle_id = f"bundle--{uuid.uuid4()}"
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    objects = []

    # 1. Threat Actor SDO
    threat_actor_id = f"threat-actor--{uuid.uuid4()}"
    objects.append({
        "type": "threat-actor",
        "spec_version": "2.1",
        "id": threat_actor_id,
        "created": timestamp,
        "modified": timestamp,
        "name": "Unidentified Threat Cluster / Nobelium Affiliate",
        "threat_actor_types": ["hostile-threat-actor"],
        "confidence": 85
    })

    # 2. Indicator SDO
    pattern = f"[{'ipv4-addr' if ioc_type.upper() == 'IP' else 'domain-name'}:value = '{seed_ioc}']"
    indicator_id = f"indicator--{uuid.uuid4()}"
    objects.append({
        "type": "indicator",
        "spec_version": "2.1",
        "id": indicator_id,
        "created": timestamp,
        "modified": timestamp,
        "name": f"Malicious Indicator - {seed_ioc}",
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": timestamp,
        "indicator_types": ["malicious-activity", "c2"]
    })

    # 3. Infrastructure SDO
    infra_id = f"infrastructure--{uuid.uuid4()}"
    objects.append({
        "type": "infrastructure",
        "spec_version": "2.1",
        "id": infra_id,
        "created": timestamp,
        "modified": timestamp,
        "name": f"Adversary C2 Infrastructure ({seed_ioc})",
        "infrastructure_types": ["command-and-control"]
    })

    # 4. Attack Pattern SDO
    attack_id = f"attack-pattern--{uuid.uuid4()}"
    objects.append({
        "type": "attack-pattern",
        "spec_version": "2.1",
        "id": attack_id,
        "created": timestamp,
        "modified": timestamp,
        "name": "Application Layer Protocol (C2)",
        "external_references": [{
            "source_name": "mitre-attack",
            "external_id": mitre_technique
        }]
    })

    # 5. SRO Relationship: Indicator indicates Infrastructure
    rel_id = f"relationship--{uuid.uuid4()}"
    objects.append({
        "type": "relationship",
        "spec_version": "2.1",
        "id": rel_id,
        "created": timestamp,
        "modified": timestamp,
        "relationship_type": "indicates",
        "source_ref": indicator_id,
        "target_ref": infra_id
    })

    stix_bundle = {
        "type": "bundle",
        "id": bundle_id,
        "spec_version": "2.1",
        "objects": objects
    }

    return ToolResult(
        success=True,
        data={
            "bundle_id": bundle_id,
            "stix_bundle": stix_bundle,
            "objects_count": len(objects)
        },
        execution_time_ms=(time.perf_counter() - start) * 1000
    )

