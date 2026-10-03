"""Unit tests for SBOM, AI-BOM, AST Reachability, OpenVEX, and Remediation Engines."""

import pytest
from tools.sbom import SBOMGenerator, AIBOMAsset, SlopsquatDetector
from tools.reachability import ReachabilityEngine, ReachabilityAnalysisResult, KNOWN_ADVISORIES
from tools.vex import VEXSynthesizer, VEXTriageSummary
from tools.remediation import RemediationEngine
from gateway.tool_gateway.permissions import authorize_tool_execution, ToolPermissionDeniedError, AgentRole
from gateway.tool_gateway.gateway import tool_gateway


def test_sbom_cyclonedx_generation():
    manifest = """fastapi==0.111.0\nurllib3==1.26.15\ntorch==2.3.0\n"""
    components = SBOMGenerator.parse_requirements_txt(manifest)
    assert len(components) == 3
    assert components[0].name == "fastapi"
    assert components[0].purl == "pkg:pypi/fastapi@0.111.0"
    assert "SHA-256" in components[0].hashes

    ai_asset = AIBOMAsset(
        asset_id="model_mistral",
        asset_type="foundation-model",
        name="mistral-7b",
        version_or_tag="v0.3",
        source_uri="hf://mistralai/Mistral-7B",
        serialization_format="safetensors"
    )

    bom = SBOMGenerator.build_cyclonedx_bom("TestApp", "1.0.0", components, [ai_asset])
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.6"
    assert len(bom["components"]) == 4
    
    # Check that AI model asset is tagged properly
    ml_models = [c for c in bom["components"] if c["type"] == "machine-learning-model"]
    assert len(ml_models) == 1
    assert ml_models[0]["name"] == "mistral-7b"


def test_slopsquatting_detector():
    packages = ["fastapi", "reqeusts", "torch", "langchain-core-ai", "pydantic"]
    findings = SlopsquatDetector.scan_manifest(packages)
    
    # Expect 2 findings: reqeusts (typosquat) and langchain-core-ai (hallucinated)
    assert len(findings) == 2
    pkg_names = [f.package_name for f in findings]
    assert "reqeusts" in pkg_names
    assert "langchain-core-ai" in pkg_names
    
    req_finding = next(f for f in findings if f.package_name == "reqeusts")
    assert req_finding.suspected_target == "requests"
    assert req_finding.risk_level == "HIGH"


def test_ast_reachability_engine_reachable():
    manifest_pkgs = {"pyyaml": "5.3.1", "urllib3": "1.26.15"}
    source_files = {
        "app.py": """import yaml\n\ndef load_data(text):\n    return yaml.load(text, Loader=yaml.Loader)\n"""
    }

    results = ReachabilityEngine.analyze_repository(manifest_pkgs, source_files)
    assert len(results) == 2

    yaml_res = next(r for r in results if r.package_name == "pyyaml")
    assert yaml_res.reachability_verdict == "REACHABLE"
    assert yaml_res.vex_status == "affected"
    assert len(yaml_res.traces) == 1
    assert yaml_res.traces[0].line_number == 4
    assert "yaml.load" in yaml_res.traces[0].called_symbol


def test_ast_reachability_engine_mitigated_and_unreachable():
    manifest_pkgs = {"pyyaml": "5.3.1", "urllib3": "1.26.15"}
    source_files = {
        "app.py": """import yaml\nimport urllib3\n\ndef load_data(text):\n    return yaml.safe_load(text)\n"""
    }

    results = ReachabilityEngine.analyze_repository(manifest_pkgs, source_files)
    yaml_res = next(r for r in results if r.package_name == "pyyaml")
    assert yaml_res.reachability_verdict == "MITIGATED_INLINE"
    assert yaml_res.vex_status == "not_affected"
    assert yaml_res.vex_justification == "inline_mitigations_exist"

    urllib_res = next(r for r in results if r.package_name == "urllib3")
    assert urllib_res.reachability_verdict == "DIRECT_IMPORT_ONLY"
    assert urllib_res.vex_status == "not_affected"
    assert urllib_res.vex_justification == "code_not_reachable"


def test_openvex_and_csaf_synthesis():
    manifest_pkgs = {"pyyaml": "5.3.1", "urllib3": "1.26.15"}
    source_files = {
        "app.py": """import yaml\n\ndef load_data(text):\n    return yaml.safe_load(text)\n"""
    }
    results = ReachabilityEngine.analyze_repository(manifest_pkgs, source_files)
    triage = VEXSynthesizer.synthesize_triage_summary("DemoService", "1.0.0", results)

    assert triage.total_vulnerabilities == 2
    assert triage.not_affected_count == 2
    assert triage.affected_count == 0
    assert triage.noise_reduction_percentage == 100.0
    assert triage.estimated_triage_hours_saved == 7.0

    openvex = triage.openvex_document
    assert openvex["@context"] == "https://openvex.dev/ns/v0.2.0"
    assert len(openvex["statements"]) == 2
    assert openvex["statements"][0]["status"] == "not_affected"

    csaf = triage.csaf_document
    assert csaf["document"]["category"] == "csaf_vex"
    assert len(csaf["vulnerabilities"]) == 2


def test_autonomous_remediation_engine():
    manifest = "pyyaml==5.3.1\nrequests==2.28.1\n"
    source_files = {
        "server.py": "import yaml\ndef parse_cfg(val):\n    return yaml.load(val, Loader=yaml.Loader)\n"
    }
    reach_res = ReachabilityAnalysisResult(
        package_name="pyyaml",
        installed_version="5.3.1",
        cve_id="CVE-2020-14343",
        cvss_score=9.8,
        severity="CRITICAL",
        epss_score=0.942,
        cisa_kev_active=True,
        reachability_verdict="REACHABLE",
        vex_status="affected",
        vex_justification="requires_immediate_patch",
        exploitability_index=0.98,
        traces=[],
        impact_statement="yaml.load called",
        recommended_action="Upgrade to pyyaml>=6.0.1"
    )

    plan = RemediationEngine.create_remediation_plan(reach_res, manifest, source_files)
    assert plan.package_name == "pyyaml"
    assert plan.recommended_safe_version == "6.0.1"
    assert "pyyaml==6.0.1" in plan.file_patches[0].patched_content
    assert plan.verification_status == "SYNTAX_VERIFIED"
    
    # Check that caller code was refactored from yaml.load to yaml.safe_load
    code_patch = next(p for p in plan.file_patches if p.file_path == "server.py")
    assert "yaml.safe_load(val)" in code_patch.patched_content


@pytest.mark.asyncio
async def test_tool_gateway_supply_chain_analyst_permissions():
    # Supply chain analyst is authorized for generate_sbom
    assert authorize_tool_execution(AgentRole.SUPPLY_CHAIN_ANALYST.value, "generate_sbom") is True
    assert authorize_tool_execution(AgentRole.SUPPLY_CHAIN_ANALYST.value, "analyze_reachability") is True

    # Unauthorized tool should raise exception
    with pytest.raises(ToolPermissionDeniedError):
        authorize_tool_execution(AgentRole.SUPPLY_CHAIN_ANALYST.value, "block_ip")

    # Gateway execution test
    res = await tool_gateway.execute_tool(
        "supply_chain_analyst",
        "detect_slopsquatting",
        {"packages": ["reqeusts", "fastapi"]}
    )
    assert res.success is True
    assert res.data["total_findings"] == 1
