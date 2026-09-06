"""MITRE ATT&CK (Offensive) and MITRE D3FEND (Defensive Countermeasures) Engine."""

import time
from typing import Dict, Any, List
from tools.base import ToolResult

MITRE_DATABASE = {
    "c2": {
        "id": "T1071",
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "description": "Adversaries may communicate using application layer protocols to avoid detection/network filtering."
    },
    "cobalt strike": {
        "id": "T1071.001",
        "name": "Web Protocols",
        "tactic": "Command and Control",
        "description": "Adversaries may use HTTP/HTTPS web protocols to establish C2 beacons."
    },
    "phishing": {
        "id": "T1566",
        "name": "Phishing",
        "tactic": "Initial Access",
        "description": "Adversaries may send phishing messages with malicious attachments or links to gain initial access."
    },
    "spearphishing link": {
        "id": "T1566.002",
        "name": "Spearphishing Link",
        "tactic": "Initial Access",
        "description": "Adversaries may send emails containing malicious links to lure victims into credential harvest or malware download."
    },
    "lookalike": {
        "id": "T1583.001",
        "name": "Domains",
        "tactic": "Resource Development",
        "description": "Adversaries may acquire lookalike domains that mimic trusted brands to support deceptive operations."
    },
    "credential harvesting": {
        "id": "T1056",
        "name": "Input Capture",
        "tactic": "Credential Access",
        "description": "Adversaries may use fake login interfaces to steal user credentials."
    },
    "exploit public facing": {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Adversaries may take advantage of software vulnerabilities in Internet-facing programs."
    }
}

# MITRE D3FEND Countermeasures Mapping Matrix
D3FEND_DATABASE = {
    "T1071": [
        {"id": "D3-NPA", "name": "Network Traffic Analysis", "tactic": "Model", "description": "Analyzing network communication protocol metadata to detect unauthorized beaconing."},
        {"id": "D3-ITF", "name": "Inbound Traffic Filtering", "tactic": "Isolate", "description": "Filtering incoming external network packets based on reputation and threat intelligence."}
    ],
    "T1071.001": [
        {"id": "D3-NPA", "name": "Network Traffic Analysis", "tactic": "Model", "description": "Deep packet and TLS inspection to identify malleable C2 profiles."},
        {"id": "D3-OTF", "name": "Outbound Traffic Filtering", "tactic": "Isolate", "description": "Blocking egress HTTP/HTTPS requests to untrusted, unclassified IP addresses."}
    ],
    "T1566": [
        {"id": "D3-EIA", "name": "Email Inbound Authentication", "tactic": "Verify", "description": "Enforcing strict SPF, DKIM, and DMARC alignment validation on inbound MX gateways."},
        {"id": "D3-MFA", "name": "Multi-Factor Authentication", "tactic": "Harden", "description": "Preventing single-factor credential misuse resulting from successful phishing."}
    ],
    "T1566.002": [
        {"id": "D3-URLR", "name": "URL Reputation Analysis", "tactic": "Detect", "description": "Real-time automated scanning and neutralization of links in email bodies."},
        {"id": "D3-DQ", "name": "DNS Query Analysis", "tactic": "Detect", "description": "Monitoring DNS requests for newly registered domains and homoglyphs."}
    ],
    "T1583.001": [
        {"id": "D3-SINK", "name": "DNS Sinkholing", "tactic": "Deceive", "description": "Redirecting lookalike and typosquatted domain resolution to a controlled SOC sinkhole."},
        {"id": "D3-DNSR", "name": "Domain Name Reputation", "tactic": "Detect", "description": "Continuous monitoring of certificate transparency logs for brand impersonation."}
    ],
    "T1190": [
        {"id": "D3-WAF", "name": "Web Application Firewall", "tactic": "Isolate", "description": "Intercepting SQLi, RCE, and deserialization payloads before reaching application sinks."},
        {"id": "D3-PV", "name": "Patch Verification", "tactic": "Harden", "description": "Automated verification that public-facing CVE vulnerabilities have official vendor patches applied."}
    ]
}


def map_to_mitre(query_or_tag: str) -> ToolResult:
    """Maps security observations, tags, or behaviors to MITRE ATT&CK techniques."""
    start = time.perf_counter()
    query_lower = query_or_tag.lower().strip()

    matches: List[Dict[str, Any]] = []
    for key, technique in MITRE_DATABASE.items():
        if key in query_lower or query_lower in key or technique["id"].lower() in query_lower:
            matches.append(technique)

    if not matches:
        matches.append(MITRE_DATABASE["c2"])

    primary_id = matches[0]["id"]
    countermeasures = map_to_d3fend(primary_id)

    return ToolResult(
        success=True,
        data={
            "query": query_or_tag,
            "matched_techniques": matches,
            "primary_technique": primary_id,
            "primary_name": matches[0]["name"],
            "primary_tactic": matches[0]["tactic"],
            "d3fend_countermeasures": countermeasures
        },
        execution_time_ms=(time.perf_counter() - start) * 1000
    )


def map_to_d3fend(attack_technique_id: str) -> List[Dict[str, Any]]:
    """Maps an offensive MITRE ATT&CK ID to official MITRE D3FEND defensive countermeasures."""
    clean_id = attack_technique_id.strip().upper()
    if clean_id in D3FEND_DATABASE:
        return D3FEND_DATABASE[clean_id]

    base_id = clean_id.split(".")[0]
    return D3FEND_DATABASE.get(base_id, [
        {"id": "D3-NPA", "name": "Network Traffic Analysis", "tactic": "Model", "description": "Baseline monitoring of network traffic anomalies."},
        {"id": "D3-ITF", "name": "Inbound Traffic Filtering", "tactic": "Isolate", "description": "Boundary packet inspection and blocking."}
    ])
