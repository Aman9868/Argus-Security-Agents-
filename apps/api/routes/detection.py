"""FastAPI Routes for Detection Engineering (Sigma Detection-as-Code & YARA Generator)."""

from typing import Optional, Dict, Any
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
import structlog
from tools.sigma_engine import SigmaRuleEngine
from tools.detection import generate_yara_rule, export_stix21_bundle
from security.validators import validate_ioc

logger = structlog.get_logger(__name__)
router = APIRouter(prefix="/detection", tags=["Detection Engineering"])


class GenerateSigmaRequest(BaseModel):
    title: Optional[str] = Field(None, description="Descriptive detection rule title")
    ioc_type: str = Field(..., description="Indicator type: 'IP', 'DOMAIN', 'URL', 'SHA256', 'MD5', or 'PROCESS'")
    ioc_value: str = Field(..., description="Indicator value or process command line")
    threat_description: Optional[str] = Field(None, description="Contextual threat narrative or campaign name")
    mitre_technique: Optional[str] = Field("T1071.001", description="Associated MITRE ATT&CK technique code")
    severity: Optional[str] = Field("high", description="Rule severity: low, medium, high, or critical")


class GenerateYaraRequest(BaseModel):
    rule_name: str = Field(..., description="Alphanumeric identifier for the YARA rule")
    ioc_value: str = Field(..., description="Hash, string, or pattern signature")
    threat_family: Optional[str] = Field("CobaltStrike", description="Malware family classification")
    description: Optional[str] = Field("Detects malicious payload and network configuration", description="Rule metadata description")


class ExportSTIXRequest(BaseModel):
    investigation_id: str = Field(..., description="Active investigation identifier")
    seed_ioc: str = Field(..., description="Pivot indicator")
    ioc_type: str = Field(..., description="IP, DOMAIN, or SHA256")
    verdict: str = Field("MALICIOUS", description="Analysis verdict")
    mitre_technique: Optional[str] = Field("T1071.001", description="MITRE technique")
    associated_domain: Optional[str] = Field(None, description="Linked domain name")


@router.post("/sigma/generate", status_code=status.HTTP_200_OK)
async def generate_sigma_detection(req: GenerateSigmaRequest):
    """
    Generates enterprise Sigma YAML rule and compiles it into:
    - Splunk SPL
    - Elastic KQL
    - Microsoft Sentinel KQL
    - Linux Firewall (iptables & nftables)
    """
    try:
        res = SigmaRuleEngine.compile_full_detection_suite(
            title=req.title or f"Detection of Suspicious {req.ioc_type} ({req.ioc_value})",
            ioc_type=req.ioc_type,
            ioc_value=req.ioc_value,
            threat_description=req.threat_description,
            mitre_technique=req.mitre_technique or "T1071.001",
            severity=req.severity or "high"
        )
        return res.data
    except Exception as e:
        logger.error("Failed to compile Sigma rule suite", error=str(e))
        raise HTTPException(status_code=500, detail=f"Sigma generation failed: {str(e)}")


@router.post("/yara/generate", status_code=status.HTTP_200_OK)
async def generate_yara_detection(req: GenerateYaraRequest):
    """Generates hunting YARA signature targeting file and memory payloads."""
    try:
        res = generate_yara_rule(
            rule_name=req.rule_name,
            ioc_value=req.ioc_value,
            threat_family=req.threat_family or "CobaltStrike",
            description=req.description or "Automated hunting rule"
        )
        return res.data
    except Exception as e:
        logger.error("Failed to generate YARA rule", error=str(e))
        raise HTTPException(status_code=500, detail=f"YARA generation failed: {str(e)}")


@router.post("/stix/export", status_code=status.HTTP_200_OK)
async def export_stix_bundle(req: ExportSTIXRequest):
    """Exports investigation knowledge graph as OASIS STIX 2.1 JSON bundle."""
    try:
        res = export_stix21_bundle(
            investigation_id=req.investigation_id,
            seed_ioc=req.seed_ioc,
            ioc_type=req.ioc_type,
            verdict=req.verdict,
            mitre_technique=req.mitre_technique or "T1071.001",
            associated_domain=req.associated_domain
        )
        return res.data
    except Exception as e:
        logger.error("Failed to export STIX 2.1 bundle", error=str(e))
        raise HTTPException(status_code=500, detail=f"STIX bundle export failed: {str(e)}")

