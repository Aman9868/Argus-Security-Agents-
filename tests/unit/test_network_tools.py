"""Unit tests for Network Intelligence Tools (GeoIP, RDAP, Port Scanning)."""

import pytest
from tools.network import check_geoip, check_rdap, scan_ports
from gateway.tool_gateway.gateway import tool_gateway


@pytest.mark.asyncio
async def test_check_geoip_enrichment():
    """Verifies GeoIP extracts Country, ASN, and ISP."""
    res = await check_geoip("185.220.101.45")
    assert res.success is True
    assert res.data["country"] == "Netherlands"
    assert "AS49981" in res.data["asn"]
    assert res.data["is_bulletproof_hosting"] is True


@pytest.mark.asyncio
async def test_check_rdap_whois():
    """Verifies RDAP returns registrar and flags newly registered domains."""
    res = await check_rdap("update-microsoft-security.com")
    assert res.success is True
    assert res.data["registrar"] == "NameCheap, Inc."
    assert res.data["is_newly_registered_domain"] is True
    assert res.data["domain_age_days"] < 30


@pytest.mark.asyncio
async def test_scan_ports_passive_and_safety_gate():
    """Verifies port scanning identifies C2 listeners and refuses internal IP targets."""
    # 1. Valid public IP
    res = await scan_ports("185.220.101.45", mode="active")
    assert res.success is True
    assert res.data["has_c2_listeners"] is True
    assert any(p["port"] == 50050 for p in res.data["ports"])

    # 2. Private IP safety block
    blocked_res = await scan_ports("192.168.1.1", mode="active")
    assert blocked_res.success is False
    assert "safety policy violation" in blocked_res.error.lower()


@pytest.mark.asyncio
async def test_tool_gateway_network_tools_execution():
    """Verifies network tools execute smoothly through the ToolGateway under RBAC."""
    geo_res = await tool_gateway.execute_tool(
        agent_role="threat_hunter",
        tool_name="check_geoip",
        parameters={"ioc": "185.220.101.45"}
    )
    assert geo_res.success is True
    assert geo_res.data["country_code"] == "NL"

    rdap_res = await tool_gateway.execute_tool(
        agent_role="osint_analyst",
        tool_name="check_rdap",
        parameters={"target": "update-microsoft-security.com"}
    )
    assert rdap_res.success is True
    assert rdap_res.data["is_newly_registered_domain"] is True


@pytest.mark.asyncio
async def test_hunt_correlator_resilience_to_int_ports():
    """Verifies hunt_correlator_node handles both raw int ports and dict ports without subscript errors."""
    from agents.threat_hunt.subgraph import hunt_correlator_node

    state = {
        "seed_ioc": "185.220.101.45",
        "evidence": [
            {
                "source": "Port Enumeration",
                "raw_data": {
                    "ports": [80, 443, 50050]  # Raw integers as returned by Shodan InternetDB
                }
            },
            {
                "source": "GeoIP & ASN Intelligence",
                "raw_data": {
                    "country": "Netherlands",
                    "asn": "AS49981 WorldStream B.V."
                }
            }
        ],
        "knowledge_graph": {},
        "hypotheses": [{"hypothesis": "Test", "confidence": 0.5}],
        "pivot_queue": []
    }

    result = await hunt_correlator_node(state)
    assert "knowledge_graph" in result
    kg_nodes = {n["id"]: n for n in result["knowledge_graph"]["nodes"]}
    assert "PORT:80/TCP" in kg_nodes
    assert "PORT:50050/TCP" in kg_nodes
    assert kg_nodes["PORT:50050/TCP"]["is_malicious"] is True
    assert "ASN:AS49981" in kg_nodes


