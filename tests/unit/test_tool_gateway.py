"""Unit tests for Central Tool Gateway execution and caching."""

import pytest
from gateway.tool_gateway.gateway import tool_gateway
from gateway.tool_gateway.permissions import ToolPermissionDeniedError
from gateway.tool_gateway.idempotency import idempotency_manager


@pytest.mark.asyncio
async def test_tool_gateway_execution_and_caching():
    """Verifies that ToolGateway executes tools and caches intelligence results."""
    ioc = "45.154.255.88"
    idempotency_manager._cache.clear()

    # 1. First invocation (uncached)
    res1 = await tool_gateway.execute_tool(
        agent_role="threat_hunter",
        tool_name="check_virustotal",
        parameters={"ioc": ioc}
    )
    assert res1.success is True
    assert res1.data is not None
    assert res1.data.get("ioc") == ioc
    assert res1.cached is False

    # 2. Second invocation (should hit cache to protect rate limits)
    res2 = await tool_gateway.execute_tool(
        agent_role="threat_hunter",
        tool_name="check_virustotal",
        parameters={"ioc": ioc}
    )
    assert res2.success is True
    assert res2.cached is True


@pytest.mark.asyncio
async def test_tool_gateway_enforces_rbac():
    """Verifies ToolGateway intercepts unauthorized execution."""
    with pytest.raises(ToolPermissionDeniedError):
        await tool_gateway.execute_tool(
            agent_role="osint_analyst",
            tool_name="block_ip",
            parameters={"ip": "185.220.101.45"}
        )


@pytest.mark.asyncio
async def test_tool_gateway_mitre_mapping():
    """Verifies MITRE ATT&CK mapper capability through gateway."""
    res = await tool_gateway.execute_tool(
        agent_role="threat_hunter",
        tool_name="map_to_mitre",
        parameters={"technique_hint": "c2 cobalt strike"}
    )
    assert res.success is True
    assert "T1071" in res.data.get("primary_technique")
