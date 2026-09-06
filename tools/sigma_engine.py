"""
Universal Sigma Detection as Code Engine (pySigma-inspired pure Python implementation).
Generates standardized Sigma YAML rules from threat intelligence indicators and MITRE ATT&CK techniques,
and compiles them into enterprise SIEM queries:
- Splunk SPL
- Elastic KQL (Kibana Query Language)
- Microsoft Sentinel KQL (Log Analytics)
- Linux Firewall Containment (iptables & nftables)
"""

import time
import uuid
import yaml
from typing import Dict, List, Any, Optional
from tools.base import ToolResult


class SigmaRuleEngine:
    """Enterprise-grade Sigma rule builder and multi-SIEM transpiler."""

    LOGSOURCE_MAP = {
        "IP": {"category": "firewall", "product": "network"},
        "DOMAIN": {"category": "dns", "product": "network"},
        "URL": {"category": "proxy", "product": "web"},
        "MD5": {"category": "process_creation", "product": "windows"},
        "SHA1": {"category": "process_creation", "product": "windows"},
        "SHA256": {"category": "process_creation", "product": "windows"},
        "PROCESS": {"category": "process_creation", "product": "windows"},
        "COMMAND_LINE": {"category": "process_creation", "product": "windows"},
    }

    @classmethod
    def build_sigma_rule(
        cls,
        title: str,
        ioc_type: str,
        ioc_value: str,
        threat_description: Optional[str] = None,
        mitre_technique: str = "T1071.001",
        severity: str = "high",
        author: str = "Cyber Sentinel Detection Engine"
    ) -> Dict[str, Any]:
        """Builds a structured Sigma rule dictionary and YAML."""
        rule_id = str(uuid.uuid4())
        normalized_type = ioc_type.upper().strip()
        threat_desc = threat_description or f"Identified {normalized_type} threat activity"

        logsource = cls.LOGSOURCE_MAP.get(normalized_type, {"category": "network_traffic"})

        # Build detection selection block
        if normalized_type == "IP":
            selection = {"DestinationIp": ioc_value}
        elif normalized_type == "DOMAIN":
            selection = {"query|contains": ioc_value}
        elif normalized_type == "URL":
            selection = {"c-uri|contains": ioc_value}
        elif normalized_type in ["MD5", "SHA1", "SHA256"]:
            selection = {"Hashes|contains": ioc_value}
        elif normalized_type in ["PROCESS", "COMMAND_LINE"]:
            selection = {"CommandLine|contains": ioc_value}
        else:
            selection = {"DestinationIp": ioc_value}

        clean_technique_tag = mitre_technique.lower().replace(".", "_")
        tags = [
            f"attack.{clean_technique_tag}",
            "attack.command_and_control" if "1071" in mitre_technique else "attack.execution"
        ]

        sigma_dict = {
            "title": title or f"Detection of {threat_desc} ({ioc_value})",
            "id": rule_id,
            "status": "stable",
            "description": f"Detects inbound or outbound activity matching confirmed threat indicator '{ioc_value}' affiliated with {threat_desc}.",
            "references": [
                f"https://attack.mitre.org/techniques/{mitre_technique.replace('.', '/')}"
            ],
            "author": author,
            "date": time.strftime("%Y/%m/%d"),
            "tags": tags,
            "logsource": logsource,
            "detection": {
                "selection": selection,
                "condition": "selection"
            },
            "falsepositives": [
                "Authorized security scanning infrastructure",
                "Internal connectivity testing and lab simulation"
            ],
            "level": severity.lower()
        }

        yaml_content = yaml.dump(sigma_dict, sort_keys=False, default_flow_style=False)
        return {
            "rule_id": rule_id,
            "sigma_dict": sigma_dict,
            "sigma_yaml": yaml_content
        }

    @classmethod
    def to_splunk_spl(cls, ioc_type: str, ioc_value: str) -> str:
        """Transpiles indicator condition to Splunk Search Processing Language (SPL)."""
        t = ioc_type.upper().strip()
        if t == "IP":
            return f'index=* (DestinationIp="{ioc_value}" OR src_ip="{ioc_value}" OR dest_ip="{ioc_value}") | stats count, values(user) as users, values(host) as hosts by DestinationIp, action'
        elif t == "DOMAIN":
            return f'index=* sourcetype="*dns*" (query="*{ioc_value}*" OR dest_host="*{ioc_value}*") | table _time, host, src_ip, query, answer'
        elif t == "URL":
            return f'index=* sourcetype="*proxy*" url="*{ioc_value}*" | stats count by src, host, http_method, status'
        elif t in ["MD5", "SHA1", "SHA256"]:
            return f'index=* sourcetype="*sysmon*" (ProcessHash="*{ioc_value}*" OR TargetFilename="*{ioc_value}*") | table _time, host, Image, CommandLine, ProcessId'
        else:
            return f'index=* CommandLine="*{ioc_value}*" | table _time, host, User, Image, CommandLine'

    @classmethod
    def to_elastic_kql(cls, ioc_type: str, ioc_value: str) -> str:
        """Transpiles indicator condition to Elastic / Kibana Query Language (KQL)."""
        t = ioc_type.upper().strip()
        if t == "IP":
            return f'(destination.ip: "{ioc_value}" or source.ip: "{ioc_value}") and not network.direction: "internal"'
        elif t == "DOMAIN":
            return f'dns.question.name: "*{ioc_value}*" or url.domain: "*{ioc_value}*"'
        elif t == "URL":
            return f'url.original: "*{ioc_value}*" or http.request.body.content: "*{ioc_value}*"'
        elif t in ["MD5", "SHA1", "SHA256"]:
            return f'file.hash.sha256: "{ioc_value}" or file.hash.md5: "{ioc_value}" or process.hash.sha256: "{ioc_value}"'
        else:
            return f'process.command_line: "*{ioc_value}*"'

    @classmethod
    def to_sentinel_kql(cls, ioc_type: str, ioc_value: str) -> str:
        """Transpiles indicator condition to Microsoft Sentinel Kusto Query Language (KQL)."""
        t = ioc_type.upper().strip()
        if t == "IP":
            return (
                "DeviceNetworkEvents\n"
                f'| where RemoteIP == "{ioc_value}" or LocalIP == "{ioc_value}"\n'
                "| project TimeGenerated, DeviceName, ActionType, LocalIP, RemoteIP, RemotePort, InitiatingProcessFileName"
            )
        elif t in ["DOMAIN", "URL"]:
            return (
                "DeviceNetworkEvents\n"
                f'| where RemoteUrl has "{ioc_value}"\n'
                "| project TimeGenerated, DeviceName, RemoteUrl, RemoteIP, InitiatingProcessCommandLine"
            )
        elif t in ["MD5", "SHA1", "SHA256"]:
            return (
                "DeviceProcessEvents\n"
                f'| where SHA256 == "{ioc_value}" or MD5 == "{ioc_value}"\n'
                "| project TimeGenerated, DeviceName, FileName, FolderPath, ProcessCommandLine, AccountName"
            )
        else:
            return (
                "DeviceProcessEvents\n"
                f'| where ProcessCommandLine has "{ioc_value}"\n'
                "| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, AccountName"
            )

    @classmethod
    def to_firewall_rules(cls, ioc_type: str, ioc_value: str) -> Dict[str, str]:
        """Generates defensive perimeter containment firewall commands for iptables & nftables."""
        t = ioc_type.upper().strip()
        if t == "IP":
            nft = (
                "nft add table inet filter\n"
                "nft add chain inet filter output { type filter hook output priority 0; policy accept; }\n"
                f'nft add rule inet filter output ip daddr {ioc_value} log prefix "[SENTINEL-C2-BLOCKED]: " drop'
            )
            iptables = f"iptables -A OUTPUT -d {ioc_value} -m comment --comment 'CyberSentinel C2 Drop' -j DROP"
        elif t == "DOMAIN":
            nft = f'# DNS Sinkhole rule for {ioc_value}\necho "127.0.0.1 {ioc_value}" >> /etc/hosts'
            iptables = f"# Domain level blocking requires SWG/DNS; sinkhole: iptables -A OUTPUT -p udp --dport 53 -m string --string '{ioc_value}' --algo bm -j DROP"
        else:
            nft = f"# Hash/Payload based containment: use EDR hash ban for {ioc_value}"
            iptables = f"# Hash/Payload based containment: use EDR hash ban for {ioc_value}"

        return {
            "nftables": nft,
            "iptables": iptables
        }

    @classmethod
    def compile_full_detection_suite(
        cls,
        title: str,
        ioc_type: str,
        ioc_value: str,
        threat_description: Optional[str] = None,
        mitre_technique: str = "T1071.001",
        severity: str = "high"
    ) -> ToolResult:
        """
        Creates complete Detection-as-Code artifact comprising:
        Sigma YAML + Splunk SPL + Elastic KQL + Sentinel KQL + Firewall Rules.
        """
        start = time.perf_counter()
        sigma_res = cls.build_sigma_rule(
            title=title,
            ioc_type=ioc_type,
            ioc_value=ioc_value,
            threat_description=threat_description,
            mitre_technique=mitre_technique,
            severity=severity
        )

        splunk = cls.to_splunk_spl(ioc_type, ioc_value)
        elastic = cls.to_elastic_kql(ioc_type, ioc_value)
        sentinel = cls.to_sentinel_kql(ioc_type, ioc_value)
        fw = cls.to_firewall_rules(ioc_type, ioc_value)

        return ToolResult(
            success=True,
            data={
                "rule_id": sigma_res["rule_id"],
                "title": sigma_res["sigma_dict"]["title"],
                "target_ioc": ioc_value,
                "ioc_type": ioc_type.upper(),
                "mitre_technique": mitre_technique,
                "severity": severity.upper(),
                "sigma_yaml": sigma_res["sigma_yaml"],
                "siem_targets": {
                    "splunk_spl": splunk,
                    "elastic_kql": elastic,
                    "microsoft_sentinel_kql": sentinel,
                    "firewall_containment": fw
                }
            },
            execution_time_ms=(time.perf_counter() - start) * 1000
        )

