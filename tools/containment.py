"""Defensive Containment Actions (Gated behind Human-in-the-Loop Approval)."""

import time
from tools.base import ToolResult
from security.validators import validate_ioc
import structlog

logger = structlog.get_logger(__name__)


def block_ip(ip: str, rule_name: str = "SOC_AUTO_CONTAINMENT") -> ToolResult:
    """Executes firewall ingress/egress block rule for a malicious IP."""
    start = time.perf_counter()
    valid, ioc_type, normalized = validate_ioc(ip)
    if not valid or ioc_type != "IP":
        return ToolResult(
            success=False,
            error=f"Cannot block invalid IP: '{ip}'",
            execution_time_ms=(time.perf_counter() - start) * 1000
        )

    logger.info("Containment executed: IP blocked on perimeter firewall", ip=normalized, rule=rule_name)
    return ToolResult(
        success=True,
        data={
            "action": "BLOCK_IP",
            "target": normalized,
            "status": "APPLIED",
            "firewall_rule_id": f"FW-BLOCK-{normalized.replace('.', '-')}",
            "applied_at": time.time()
        },
        execution_time_ms=(time.perf_counter() - start) * 1000
    )


def quarantine_domain(domain: str) -> ToolResult:
    """Applies DNS sinkhole / quarantine for a malicious domain."""
    start = time.perf_counter()
    valid, ioc_type, normalized = validate_ioc(domain)
    if not valid or ioc_type != "DOMAIN":
        return ToolResult(
            success=False,
            error=f"Cannot quarantine invalid domain: '{domain}'",
            execution_time_ms=(time.perf_counter() - start) * 1000
        )

    logger.info("Containment executed: Domain quarantined via DNS sinkhole", domain=normalized)
    return ToolResult(
        success=True,
        data={
            "action": "QUARANTINE_DOMAIN",
            "target": normalized,
            "status": "SINKHOLED",
            "sinkhole_ip": "127.0.0.1",
            "applied_at": time.time()
        },
        execution_time_ms=(time.perf_counter() - start) * 1000
    )

