"""FastAPI Router for SBOM, AI-BOM, AST Reachability, and OpenVEX Triage."""

import os
import json
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, HTTPException, status, Response
from pydantic import BaseModel, Field
import structlog

from tools.sbom import (
    SBOMGenerator,
    AIBOMAsset,
    SlopsquatDetector
)
from tools.reachability import ReachabilityEngine, ReachabilityAnalysisResult
from tools.vex import VEXSynthesizer, VEXTriageSummary
from tools.remediation import RemediationEngine, RemediationPlan
from tools.git_scanner import GitConnector, GitProjectMeta, GitScanResult
from tools.pdf_generator import SBOMPDFGenerator

logger = structlog.get_logger(__name__)
router = APIRouter(prefix="/sbom", tags=["SBOM & AI-BOM Sentinel"])


# ---------------------------------------------------------------------------
# Request Schemas
# ---------------------------------------------------------------------------

class GitScanRequest(BaseModel):
    repo_path_or_url: str = Field(..., description="Local workspace folder name, absolute path, or remote Git clone URL")
    branch: Optional[str] = Field(None, description="Optional Git branch to scan")


class GitExportRequest(BaseModel):
    report_markdown: str


class PDFExportRequest(BaseModel):
    project_name: Optional[str] = "Project"
    git_meta: Optional[Dict[str, Any]] = Field(default_factory=dict)
    components: Optional[List[Dict[str, Any]]] = Field(default_factory=list)
    triage_summary: Optional[Dict[str, Any]] = Field(default_factory=dict)
    reachability_results: Optional[List[Dict[str, Any]]] = Field(default_factory=list)
    ai_assets: Optional[List[Dict[str, Any]]] = Field(default_factory=list)
    slopsquat_findings: Optional[List[Dict[str, Any]]] = Field(default_factory=list)
    remediation_plans: Optional[List[Dict[str, Any]]] = Field(default_factory=list)

class GenerateSBOMRequest(BaseModel):
    project_name: str = Field(default="MyApplication")
    project_version: str = Field(default="1.0.0")
    manifest: str = Field(..., description="Raw requirements.txt or dependencies list")
    ai_assets: Optional[List[Dict[str, Any]]] = Field(default_factory=list)


class AnalyzeSBOMRequest(BaseModel):
    project_name: Optional[str] = Field(default="MyApplication")
    project_version: Optional[str] = Field(default="1.0.0")
    manifest: Optional[str] = None
    source_files: Optional[Dict[str, str]] = None
    ai_assets: Optional[List[Dict[str, Any]]] = None


class SlopsquatCheckRequest(BaseModel):
    packages: List[str] = Field(..., description="List of package names to inspect for hallucinations/typosquats")


class RemediationRequest(BaseModel):
    reachability_result: Dict[str, Any]
    manifest_text: str
    source_files: Dict[str, str]


# ---------------------------------------------------------------------------
# API Endpoints
# ---------------------------------------------------------------------------


@router.post("/generate", status_code=status.HTTP_200_OK)
async def generate_sbom(req: GenerateSBOMRequest):
    """Generates CycloneDX 1.6 compliant SBOM and AI-BOM asset inventory."""
    try:
        components = SBOMGenerator.parse_requirements_txt(req.manifest)
        ai_objs = [AIBOMAsset(**a) for a in (req.ai_assets or [])]
        bom = SBOMGenerator.build_cyclonedx_bom(req.project_name, req.project_version, components, ai_objs)
        return {
            "success": True,
            "bom": bom,
            "total_components": len(components),
            "total_ai_assets": len(ai_objs)
        }
    except Exception as e:
        logger.error("Failed to generate SBOM", error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to generate SBOM: {str(e)}")


@router.post("/analyze", status_code=status.HTTP_200_OK)
async def analyze_supply_chain(req: AnalyzeSBOMRequest):
    """
    Performs end-to-end multi-agent supply chain analysis:
    1. Ingestion & CycloneDX 1.6 / AI-BOM generation
    2. AST call-graph reachability triage
    3. OpenVEX v0.2.0 and CSAF 2.0 document synthesis
    4. Slopsquatting / AI package hallucination scan
    5. Autonomous remediation plan synthesis
    """
    try:
        # Direct real inputs
        project_name = req.project_name or "Project"
        project_version = req.project_version or "1.0.0"
        manifest = req.manifest or ""
        source_files = req.source_files or {}
        raw_ai = req.ai_assets or []

        # 1. Parse packages and build SBOM
        components = SBOMGenerator.parse_requirements_txt(manifest)
        ai_assets = [AIBOMAsset(**a) for a in raw_ai]
        bom = SBOMGenerator.build_cyclonedx_bom(project_name, project_version, components, ai_assets)

        # 2. Extract package versions dict
        manifest_pkgs = {c.name: c.version for c in components}

        # 3. Execute AST Reachability Triage
        reachability_results = ReachabilityEngine.analyze_repository(manifest_pkgs, source_files)

        # 4. Synthesize OpenVEX and CSAF documents
        triage_summary = VEXSynthesizer.synthesize_triage_summary(
            project_name, project_version, reachability_results
        )

        # 5. Scan for Slopsquatting & Package Hallucinations
        slopsquat_findings = SlopsquatDetector.scan_manifest(list(manifest_pkgs.keys()))

        # 6. Generate Autonomous Remediation Plans for reachable CVEs
        remediation_plans = []
        for r in reachability_results:
            if r.vex_status == "affected":
                plan = RemediationEngine.create_remediation_plan(r, manifest, source_files)
                remediation_plans.append(plan.model_dump())

        return {
            "success": True,
            "project_name": project_name,
            "project_version": project_version,
            "cyclonedx_bom": bom,
            "ai_assets": [a.model_dump() for a in ai_assets],
            "reachability_results": [r.model_dump() for r in reachability_results],
            "triage_summary": triage_summary.model_dump(),
            "slopsquat_findings": [f.model_dump() for f in slopsquat_findings],
            "remediation_plans": remediation_plans
        }

    except Exception as e:
        logger.error("Failed to analyze supply chain", error=str(e))
        raise HTTPException(status_code=500, detail=f"Supply chain analysis failed: {str(e)}")


@router.post("/remediate", status_code=status.HTTP_200_OK)
async def generate_remediation_plan(req: RemediationRequest):
    """Generates code refactoring diffs, manifest bumps, and sandbox verification."""
    try:
        reach_obj = ReachabilityAnalysisResult(**req.reachability_result)
        plan = RemediationEngine.create_remediation_plan(
            reach_obj, req.manifest_text, req.source_files
        )
        return {"success": True, "remediation_plan": plan.model_dump()}
    except Exception as e:
        logger.error("Failed to generate remediation plan", error=str(e))
        raise HTTPException(status_code=500, detail=f"Remediation generation failed: {str(e)}")


@router.post("/slopsquat-check", status_code=status.HTTP_200_OK)
async def check_slopsquatting(req: SlopsquatCheckRequest):
    """Detects AI hallucinations, typosquatting, and malicious package lures."""
    try:
        findings = SlopsquatDetector.scan_manifest(req.packages)
        return {
            "success": True,
            "total_inspected": len(req.packages),
            "findings_count": len(findings),
            "findings": [f.model_dump() for f in findings]
        }
    except Exception as e:
        logger.error("Failed slopsquatting scan", error=str(e))
        raise HTTPException(status_code=500, detail=f"Slopsquatting scan failed: {str(e)}")


@router.get("/stats")
async def get_sbom_stats():
    """Returns platform-wide aggregate SBOM and supply chain protection metrics computed from live workspace projects."""
    try:
        projects = GitConnector.list_workspace_projects()
        total_projects = len(projects)
        total_manifests = sum(1 for p in projects if p.has_manifest)
        total_git = sum(1 for p in projects if p.is_git)
        
        return {
            "total_repositories_monitored": total_projects,
            "total_manifests_detected": total_manifests,
            "projects_with_git": total_git,
            "supported_standards": ["CycloneDX 1.6", "SPDX 2.3", "OpenVEX v0.2.0", "CSAF 2.0"],
            "ast_reachability_engine": "active"
        }
    except Exception as e:
        logger.error("Failed to compute sbom stats", error=str(e))
        return {
            "total_repositories_monitored": 0,
            "total_manifests_detected": 0,
            "projects_with_git": 0,
            "supported_standards": ["CycloneDX 1.6", "SPDX 2.3", "OpenVEX v0.2.0", "CSAF 2.0"],
            "ast_reachability_engine": "active"
        }


# ---------------------------------------------------------------------------
# Git Workspace & Remote Repository Scanning Endpoints
# ---------------------------------------------------------------------------

@router.get("/git/projects")
async def list_workspace_git_projects():
    """Discovers all local workspace Git projects ready for one-click SBOM analysis."""
    try:
        projects = GitConnector.list_workspace_projects()
        return {
            "success": True,
            "total_projects": len(projects),
            "projects": [p.model_dump() for p in projects]
        }
    except Exception as e:
        logger.error("Failed to discover workspace projects", error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to discover projects: {str(e)}")


@router.post("/git/scan", status_code=status.HTTP_200_OK)
async def scan_git_repository(req: GitScanRequest):
    """
    Connects to a Git repository (local workspace project or remote clone URL),
    extracts manifests and source files, and executes the complete SBOM + VEX pipeline.
    """
    try:
        # 1. Extract project from Git
        scan_meta = GitConnector.inspect_and_extract_project(req.repo_path_or_url, req.branch)

        # 2. Parse dependencies & build CycloneDX 1.6 + AI-BOM
        components = SBOMGenerator.parse_requirements_txt(scan_meta.manifest_content)
        ai_objs = [AIBOMAsset(**a) for a in scan_meta.ai_assets]
        bom = SBOMGenerator.build_cyclonedx_bom(
            scan_meta.project_name, scan_meta.project_version, components, ai_objs
        )

        manifest_pkgs = {c.name: c.version for c in components}

        # 3. Execute AST Reachability Triage
        reachability_results = ReachabilityEngine.analyze_repository(manifest_pkgs, scan_meta.source_files)

        # 4. Synthesize OpenVEX and CSAF documents
        triage_summary = VEXSynthesizer.synthesize_triage_summary(
            scan_meta.project_name, scan_meta.project_version, reachability_results
        )

        # 5. Scan for Slopsquatting & AI Hallucinations
        slopsquat_findings = SlopsquatDetector.scan_manifest(list(manifest_pkgs.keys()))

        # 6. Generate Self-Healing Remediation Plans for reachable CVEs
        remediation_plans = []
        for r in reachability_results:
            if r.vex_status == "affected":
                plan = RemediationEngine.create_remediation_plan(
                    r, scan_meta.manifest_content, scan_meta.source_files
                )
                remediation_plans.append(plan.model_dump())

        # 7. Generate Executive Markdown Audit Report
        exec_report = GitConnector.generate_executive_audit_report(
            scan_meta,
            triage_summary.model_dump(),
            [r.model_dump() for r in reachability_results],
            [f.model_dump() for f in slopsquat_findings],
            remediation_plans
        )

        return {
            "success": True,
            "project_name": scan_meta.project_name,
            "project_version": scan_meta.project_version,
            "git_meta": scan_meta.git_meta.model_dump(),
            "total_python_files_scanned": scan_meta.total_python_files,
            "cyclonedx_bom": bom,
            "ai_assets": [a.model_dump() for a in ai_objs],
            "reachability_results": [r.model_dump() for r in reachability_results],
            "triage_summary": triage_summary.model_dump(),
            "slopsquat_findings": [f.model_dump() for f in slopsquat_findings],
            "remediation_plans": remediation_plans,
            "executive_report_markdown": exec_report
        }

    except Exception as e:
        logger.error("Git repository scan failed", repo=req.repo_path_or_url, error=str(e))
        raise HTTPException(status_code=500, detail=f"Git scan failed: {str(e)}")


@router.post("/export-pdf")
async def export_sbom_pdf(req: PDFExportRequest):
    """
    Generates and downloads an executive, multi-page Code Scoring / CycloneDX
    style PDF report matching the enterprise SBOM standard.
    """
    try:
        project_name = req.project_name or "TargetProject"
        components = req.components or []
        git_meta = req.git_meta or {}
        triage_summary = req.triage_summary or {}
        reachability_results = req.reachability_results or []
        ai_assets = req.ai_assets or []
        slopsquat_findings = req.slopsquat_findings or []
        remediation_plans = req.remediation_plans or []

        pdf_bytes = SBOMPDFGenerator.generate(
            project_name=project_name,
            git_meta=git_meta,
            components=components,
            triage_summary=triage_summary,
            reachability_results=reachability_results,
            ai_assets=ai_assets,
            slopsquat_findings=slopsquat_findings,
            remediation_plans=remediation_plans
        )

        clean_filename = f"Argus_SBOM_Report_{project_name.replace('/', '_')}.pdf"
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=\"{clean_filename}\""}
        )

    except Exception as e:
        logger.error("PDF generation failed", error=str(e))
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {str(e)}")
