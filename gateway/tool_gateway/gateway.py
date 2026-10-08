"""Central Tool Gateway enforcing RBAC, Idempotency, and Audit Logging across all cybersecurity capabilities."""

import time
from typing import Dict, Any, Optional
from gateway.tool_gateway.permissions import authorize_tool_execution
from gateway.tool_gateway.idempotency import idempotency_manager
from tools.base import ToolResult
from tools.threat_intel import check_virustotal, check_otx, check_abusech
from tools.mitre import map_to_mitre
from tools.osint import check_crtsh, check_dnstwist, check_sherlock
from tools.phishing import parse_email_headers, extract_email_urls
from tools.vuln import check_nvd_cve, check_cisa_kev
from tools.containment import block_ip, quarantine_domain
from tools.network import check_geoip, check_rdap, scan_ports
from tools.detection import generate_sigma_rule, generate_yara_rule, export_stix21_bundle
from tools.sbom import SBOMGenerator, AIBOMAsset, SlopsquatDetector
from tools.reachability import ReachabilityEngine, ReachabilityAnalysisResult
from tools.vex import VEXSynthesizer
from tools.remediation import RemediationEngine
import structlog

logger = structlog.get_logger(__name__)


class ToolGateway:
    """Enterprise Tool Gateway orchestrating safe, audited, rate-limited tool calls."""

    async def execute_tool(
        self,
        agent_role: str,
        tool_name: str,
        parameters: Dict[str, Any],
        correlation_id: Optional[str] = None
    ) -> ToolResult:
        """
        Executes a cybersecurity tool under strict enterprise governance:
        1. Agent identity RBAC authorization
        2. External API cache check (prevents exceeding free-tier limits like VT 4/min)
        3. Dispatch to authorized capability
        4. Structured audit logging
        """
        start_time = time.perf_counter()

        # 1. Authorize agent identity against RBAC policy
        authorize_tool_execution(agent_role, tool_name)

        # 2. Check cache for read-only intelligence queries
        cache_key = None
        target_entity = parameters.get("ioc") or parameters.get("domain") or parameters.get("cve_id") or parameters.get("username")
        if target_entity and tool_name not in ["block_ip", "quarantine_domain"]:
            cache_key = f"{tool_name}:{str(target_entity).lower().strip()}"
            cached_data = await idempotency_manager.get_result(cache_key)
            if cached_data:
                logger.info("ToolGateway: Cache hit", tool=tool_name, key=cache_key)
                return ToolResult(
                    success=True,
                    data=cached_data.get("result"),
                    cached=True,
                    execution_time_ms=(time.perf_counter() - start_time) * 1000
                )

        # 3. Dispatch to authorized tool implementation
        result: ToolResult
        try:
            # Threat Intel Tools
            if tool_name == "check_virustotal":
                result = await check_virustotal(parameters.get("ioc", ""))
            elif tool_name == "check_otx":
                result = await check_otx(parameters.get("ioc", ""))
            elif tool_name == "check_abusech":
                result = await check_abusech(parameters.get("ioc", ""))
            elif tool_name == "map_to_mitre":
                result = map_to_mitre(parameters.get("technique_hint") or parameters.get("query", ""))

            # OSINT Tools
            elif tool_name == "check_crtsh":
                result = await check_crtsh(parameters.get("domain", ""))
            elif tool_name == "check_dnstwist":
                result = check_dnstwist(parameters.get("domain", ""))
            elif tool_name == "check_sherlock":
                result = check_sherlock(parameters.get("username", ""))

            # Network Intelligence & Port Scanning Tools
            elif tool_name == "check_geoip":
                result = await check_geoip(parameters.get("ip") or parameters.get("ioc", ""))
            elif tool_name == "check_rdap":
                result = await check_rdap(parameters.get("target") or parameters.get("domain") or parameters.get("ioc", ""))
            elif tool_name == "scan_ports":
                result = await scan_ports(parameters.get("ip") or parameters.get("ioc", ""), mode=parameters.get("mode", "passive"))

            # Phishing Tools
            elif tool_name == "parse_email_headers":
                result = parse_email_headers(parameters.get("raw_email", ""))
            elif tool_name == "extract_email_urls":
                result = extract_email_urls(parameters.get("raw_email_or_body", ""))

            # Vulnerability Tools
            elif tool_name == "check_nvd_cve":
                result = await check_nvd_cve(parameters.get("cve_id", ""))
            elif tool_name == "check_cisa_kev":
                result = check_cisa_kev(parameters.get("cve_id", ""))

            # Containment Actions (Gated)
            elif tool_name == "block_ip":
                result = block_ip(parameters.get("ip", ""), parameters.get("rule_name", "SOC_CONTAINMENT"))
            elif tool_name == "quarantine_domain":
                result = quarantine_domain(parameters.get("domain", ""))

            # Detection Engineering & CTI Standards
            elif tool_name == "generate_sigma_rule":
                result = generate_sigma_rule(
                    title=parameters.get("title", "Adversary Infrastructure"),
                    ioc_type=parameters.get("ioc_type", "IP"),
                    ioc_value=parameters.get("ioc_value", ""),
                    threat_description=parameters.get("threat_description", "C2 Beaconing"),
                    mitre_technique=parameters.get("mitre_technique", "T1071.001"),
                    severity=parameters.get("severity", "high")
                )
            elif tool_name == "generate_yara_rule":
                result = generate_yara_rule(
                    rule_name=parameters.get("rule_name", "ioc_signature"),
                    ioc_value=parameters.get("ioc_value", ""),
                    threat_family=parameters.get("threat_family", "CobaltStrike"),
                    description=parameters.get("description", "Auto-generated threat rule")
                )
            elif tool_name == "export_stix21_bundle":
                result = export_stix21_bundle(
                    investigation_id=parameters.get("investigation_id", "INV-DEFAULT"),
                    seed_ioc=parameters.get("seed_ioc", ""),
                    ioc_type=parameters.get("ioc_type", "IP"),
                    verdict=parameters.get("verdict", "MALICIOUS"),
                    mitre_technique=parameters.get("mitre_technique", "T1071.001"),
                    associated_domain=parameters.get("associated_domain")
                )

            # Supply Chain & SBOM Tools
            elif tool_name == "generate_sbom":
                manifest = parameters.get("manifest", "")
                proj_name = parameters.get("project_name", "SupplyChainTarget")
                proj_ver = parameters.get("project_version", "1.0.0")
                raw_ai = parameters.get("ai_assets", [])
                ai_assets = [AIBOMAsset(**a) if isinstance(a, dict) else a for a in raw_ai]
                components = SBOMGenerator.parse_requirements_txt(manifest)
                bom = SBOMGenerator.build_cyclonedx_bom(proj_name, proj_ver, components, ai_assets)
                result = ToolResult(
                    success=True,
                    data={"bom": bom, "total_components": len(components), "total_ai_assets": len(ai_assets)},
                    execution_time_ms=(time.perf_counter() - start_time) * 1000
                )

            elif tool_name == "analyze_reachability":
                manifest_pkgs = parameters.get("manifest_packages", {})
                source_files = parameters.get("source_files", {})
                reach_results = ReachabilityEngine.analyze_repository(manifest_pkgs, source_files)
                result = ToolResult(
                    success=True,
                    data={"results": [r.model_dump() for r in reach_results]},
                    execution_time_ms=(time.perf_counter() - start_time) * 1000
                )

            elif tool_name == "generate_vex_document":
                proj_name = parameters.get("project_name", "SupplyChainTarget")
                proj_ver = parameters.get("project_version", "1.0.0")
                raw_results = parameters.get("reachability_results", [])
                reach_objs = [ReachabilityAnalysisResult(**r) if isinstance(r, dict) else r for r in raw_results]
                triage = VEXSynthesizer.synthesize_triage_summary(proj_name, proj_ver, reach_objs)
                result = ToolResult(
                    success=True,
                    data=triage.model_dump(),
                    execution_time_ms=(time.perf_counter() - start_time) * 1000
                )

            elif tool_name == "generate_remediation_patch":
                raw_result = parameters.get("reachability_result", {})
                reach_obj = ReachabilityAnalysisResult(**raw_result) if isinstance(raw_result, dict) else raw_result
                manifest_text = parameters.get("manifest_text", "")
                source_files = parameters.get("source_files", {})
                plan = RemediationEngine.create_remediation_plan(reach_obj, manifest_text, source_files)
                result = ToolResult(
                    success=True,
                    data=plan.model_dump(),
                    execution_time_ms=(time.perf_counter() - start_time) * 1000
                )

            elif tool_name == "detect_slopsquatting":
                packages = parameters.get("packages", [])
                findings = SlopsquatDetector.scan_manifest(packages)
                result = ToolResult(
                    success=True,
                    data={"findings": [f.model_dump() for f in findings], "total_findings": len(findings)},
                    execution_time_ms=(time.perf_counter() - start_time) * 1000
                )

            elif tool_name == "scan_credentials":
                from tools.credential_scanner import CredentialScanner
                target_path = parameters.get("target_path", "")
                scan_git_history = parameters.get("scan_git_history", True)
                max_commits = parameters.get("max_commits", 15)
                ai_triage = parameters.get("ai_triage", True)
                recipient_email = parameters.get("recipient_email")

                scan_res = await CredentialScanner.scan_project_or_directory(
                    target_path=target_path,
                    scan_git_history=scan_git_history,
                    max_commits=max_commits,
                    ai_triage=ai_triage,
                    recipient_email=recipient_email
                )
                result = ToolResult(
                    success=True,
                    data={
                        "summary": scan_res.summary.model_dump(),
                        "findings": [f.model_dump() for f in scan_res.findings]
                    },
                    execution_time_ms=(time.perf_counter() - start_time) * 1000
                )

            elif tool_name == "send_credential_hitl_email":
                from services.email_service import EmailService
                recipient_email = parameters.get("recipient_email", "")
                scan_id = parameters.get("scan_id", "")
                target_path = parameters.get("target_path", "")
                target_type = parameters.get("target_type", "local_directory")
                total_findings = parameters.get("total_findings", 0)
                critical_count = parameters.get("critical_count", 0)
                high_count = parameters.get("high_count", 0)
                medium_count = parameters.get("medium_count", 0)
                low_count = parameters.get("low_count", 0)
                findings = parameters.get("findings", [])
                git_branch = parameters.get("git_branch")
                git_commit = parameters.get("git_commit")

                email_res = await EmailService.send_alert_email(
                    recipient_email=recipient_email,
                    scan_id=scan_id,
                    target_path=target_path,
                    target_type=target_type,
                    total_findings=total_findings,
                    critical_count=critical_count,
                    high_count=high_count,
                    medium_count=medium_count,
                    low_count=low_count,
                    findings=findings,
                    git_branch=git_branch,
                    git_commit=git_commit
                )
                result = ToolResult(
                    success=True,
                    data=email_res,
                    execution_time_ms=(time.perf_counter() - start_time) * 1000
                )

            else:
                result = ToolResult(
                    success=False,
                    error=f"Unrecognized tool capability: '{tool_name}'",
                    execution_time_ms=(time.perf_counter() - start_time) * 1000
                )

        except Exception as exc:
            logger.error("Tool execution failed", tool=tool_name, error=str(exc))
            result = ToolResult(
                success=False,
                error=f"Internal tool error: {str(exc)}",
                execution_time_ms=(time.perf_counter() - start_time) * 1000
            )

        # 4. Populate cache on successful intelligence retrieval
        if result.success and cache_key:
            await idempotency_manager.set_result(cache_key, result.data, ttl=3600)

        # 5. Audit log
        logger.info(
            "ToolGateway: Execution complete",
            agent=agent_role,
            tool=tool_name,
            success=result.success,
            cached=result.cached,
            duration_ms=result.execution_time_ms,
            correlation_id=correlation_id
        )

        return result


tool_gateway = ToolGateway()

