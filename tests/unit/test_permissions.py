"""Unit tests for Tool Gateway RBAC Permissions Engine."""

import pytest
from gateway.tool_gateway.permissions import (
    authorize_tool_execution,
    ToolPermissionDeniedError,
    AgentRole,
    AGENT_TOOL_PERMISSIONS
)


def test_threat_hunter_authorized_tools():
    """Verifies Threat Hunter can execute allowed intelligence tools."""
    assert authorize_tool_execution("threat_hunter", "check_virustotal") is True
    assert authorize_tool_execution("threat_hunter", "check_otx") is True
    assert authorize_tool_execution("threat_hunter", "map_to_mitre") is True


def test_threat_hunter_denied_containment_tool():
    """Verifies Threat Hunter CANNOT execute active containment actions."""
    with pytest.raises(ToolPermissionDeniedError) as exc_info:
        authorize_tool_execution("threat_hunter", "block_ip")
    assert "not authorized" in str(exc_info.value).lower()


def test_osint_analyst_denied_vulnerability_tool():
    """Verifies OSINT Analyst cannot query NVD CVE tool."""
    with pytest.raises(ToolPermissionDeniedError):
        authorize_tool_execution("osint_analyst", "check_nvd_cve")


def test_incident_responder_authorized_containment():
    """Verifies Incident Responder has containment capability."""
    assert authorize_tool_execution("incident_responder", "block_ip") is True
    assert authorize_tool_execution("incident_responder", "quarantine_domain") is True


def test_invalid_agent_role():
    """Verifies unknown agent role is denied access."""
    with pytest.raises(ToolPermissionDeniedError) as exc_info:
        authorize_tool_execution("unauthorized_guest_agent", "check_virustotal")
    assert "unrecognized agent role" in str(exc_info.value).lower()

