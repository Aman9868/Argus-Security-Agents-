"""Agent Identity and Tool Permission Engine (RBAC).

Enforces strict least-privilege access control across specialized cybersecurity agents.
"""

from typing import Set, Dict
from enum import Enum


class AgentRole(str, Enum):
    SUPERVISOR = "supervisor"
    THREAT_HUNTER = "threat_hunter"
    OSINT_ANALYST = "osint_analyst"
    PHISHING_ANALYST = "phishing_analyst"
    VULN_ANALYST = "vuln_analyst"
    INCIDENT_RESPONDER = "incident_responder"


class ToolPermissionDeniedError(Exception):
    """Raised when an agent attempts to execute a tool outside its allowed boundaries."""
    pass


# Strict Least-Privilege Permission Matrix
AGENT_TOOL_PERMISSIONS: Dict[AgentRole, Set[str]] = {
    AgentRole.SUPERVISOR: {
        "check_virustotal",
        "check_otx",
        "check_abusech",
        "map_to_mitre",
        "check_crtsh",
        "check_dnstwist",
        "check_sherlock",
        "check_geoip",
        "check_rdap",
        "scan_ports",
        "parse_email_headers",
        "extract_email_urls",
        "check_nvd_cve",
        "check_cisa_kev",
        "generate_sigma_rule",
        "generate_yara_rule",
        "export_stix21_bundle",
        "get_knowledge_graph",
        "block_ip",
        "quarantine_domain"
    },
    AgentRole.THREAT_HUNTER: {
        "check_virustotal",
        "check_otx",
        "check_abusech",
        "map_to_mitre",
        "check_geoip",
        "check_rdap",
        "scan_ports",
        "generate_sigma_rule",
        "generate_yara_rule",
        "export_stix21_bundle",
        "get_knowledge_graph",
    },
    AgentRole.OSINT_ANALYST: {
        "check_crtsh",
        "check_dnstwist",
        "check_sherlock",
        "check_virustotal",
        "check_geoip",
        "check_rdap",
        "get_knowledge_graph",
    },
    AgentRole.PHISHING_ANALYST: {
        "parse_email_headers",
        "extract_email_urls",
        "check_virustotal",
        "check_dnstwist",
        "map_to_mitre",
        "get_knowledge_graph",
    },
    AgentRole.VULN_ANALYST: {
        "check_nvd_cve",
        "check_cisa_kev",
        "map_to_mitre",
        "get_knowledge_graph",
    },
    AgentRole.INCIDENT_RESPONDER: {
        "block_ip",
        "quarantine_domain",
        "get_knowledge_graph",
    }
}


def authorize_tool_execution(agent_role: str, tool_name: str) -> bool:
    """
    Validates if an agent role has permission to execute a target tool.
    Raises ToolPermissionDeniedError if unauthorized.
    """
    try:
        role_enum = AgentRole(agent_role)
    except ValueError:
        raise ToolPermissionDeniedError(f"Unrecognized agent role: '{agent_role}'. Access denied.")

    allowed_tools = AGENT_TOOL_PERMISSIONS.get(role_enum, set())
    if tool_name not in allowed_tools:
        raise ToolPermissionDeniedError(
            f"Agent '{agent_role}' is not authorized to execute tool '{tool_name}'. "
            f"Allowed tools: {sorted(list(allowed_tools))}"
        )
    return True

