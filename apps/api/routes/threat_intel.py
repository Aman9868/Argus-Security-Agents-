"""FastAPI Routes for Threat Intelligence Providers (AbuseIPDB, VirusTotal, AlienVault OTX, abuse.ch)."""

import asyncio
from typing import Optional, Dict, Any, List
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
import structlog
from tools.threat_intel import check_virustotal, check_otx, check_abusech, check_abuseipdb
from security.validators import validate_ioc

logger = structlog.get_logger(__name__)
router = APIRouter(prefix="/intel", tags=["Threat Intelligence"])


class ReputationQueryRequest(BaseModel):
    ioc: str = Field(..., description="Target indicator of compromise (IP, domain, or hash)")
    provider: Optional[str] = Field("all", description="Provider filter: 'abuseipdb', 'virustotal', 'otx', 'abusech', or 'all'")


@router.post("/reputation", status_code=status.HTTP_200_OK)
async def query_threat_reputation(req: ReputationQueryRequest):
    """
    Queries multi-source threat intelligence feeds (AbuseIPDB, VirusTotal, OTX, abuse.ch)
    and aggregates confidence scoring, ISP telemetry, and threat telemetry.
    """
    valid, ioc_type, normalized = validate_ioc(req.ioc)
    if not valid:
        raise HTTPException(status_code=400, detail=f"Invalid indicator format: '{req.ioc}'")

    provider = (req.provider or "all").lower().strip()

    try:
        if provider == "abuseipdb":
            if ioc_type != "IP":
                raise HTTPException(status_code=400, detail="AbuseIPDB only accepts IP addresses.")
            res = await check_abuseipdb(normalized)
            return {"success": res.success, "ioc": normalized, "type": ioc_type, "results": {"abuseipdb": res.data}}

        elif provider == "virustotal":
            res = await check_virustotal(normalized)
            return {"success": res.success, "ioc": normalized, "type": ioc_type, "results": {"virustotal": res.data}}

        elif provider == "otx":
            res = await check_otx(normalized)
            return {"success": res.success, "ioc": normalized, "type": ioc_type, "results": {"otx": res.data}}

        elif provider == "abusech":
            res = await check_abusech(normalized)
            return {"success": res.success, "ioc": normalized, "type": ioc_type, "results": {"abusech": res.data}}

        else:
            # Query all applicable providers concurrently
            tasks = [
                check_virustotal(normalized),
                check_otx(normalized),
                check_abusech(normalized)
            ]
            if ioc_type == "IP":
                tasks.append(check_abuseipdb(normalized))

            results_list = await asyncio.gather(*tasks, return_exceptions=True)
            results_map = {}

            # VirusTotal
            if isinstance(results_list[0], Exception) or not results_list[0].success:
                results_map["virustotal"] = {"error": str(results_list[0])}
            else:
                results_map["virustotal"] = results_list[0].data

            # OTX
            if isinstance(results_list[1], Exception) or not results_list[1].success:
                results_map["otx"] = {"error": str(results_list[1])}
            else:
                results_map["otx"] = results_list[1].data

            # abuse.ch
            if isinstance(results_list[2], Exception) or not results_list[2].success:
                results_map["abusech"] = {"error": str(results_list[2])}
            else:
                results_map["abusech"] = results_list[2].data

            # AbuseIPDB (for IP)
            if ioc_type == "IP" and len(results_list) > 3:
                if isinstance(results_list[3], Exception) or not results_list[3].success:
                    results_map["abuseipdb"] = {"error": str(results_list[3])}
                else:
                    results_map["abuseipdb"] = results_list[3].data

            # Calculate unified threat level
            is_malicious = False
            malicious_signals = []

            vt_data = results_map.get("virustotal", {})
            if vt_data.get("malicious_votes", 0) > 0 or vt_data.get("verdict") == "MALICIOUS":
                is_malicious = True
                malicious_signals.append(f"VirusTotal detected {vt_data.get('malicious_votes')} positive vendor detections")

            otx_data = results_map.get("otx", {})
            if otx_data.get("pulse_count", 0) > 0:
                is_malicious = True
                malicious_signals.append(f"AlienVault OTX identified {otx_data.get('pulse_count')} threat pulses")

            abuseipdb_data = results_map.get("abuseipdb", {})
            if abuseipdb_data.get("abuse_confidence_score", 0) >= 50:
                is_malicious = True
                malicious_signals.append(f"AbuseIPDB confidence score is {abuseipdb_data.get('abuse_confidence_score')}%")

            unified_verdict = "MALICIOUS" if is_malicious else "BENIGN"

            return {
                "success": True,
                "ioc": normalized,
                "type": ioc_type,
                "unified_verdict": unified_verdict,
                "signals": malicious_signals,
                "telemetry": results_map
            }

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Threat intel reputation lookup failed", ioc=normalized, error=str(e))
        raise HTTPException(status_code=500, detail=f"Threat intelligence lookup failed: {str(e)}")


@router.get("/abuseipdb/{ip}")
async def get_abuseipdb_reputation(ip: str):
    """Direct lookup endpoint for AbuseIPDB IP reputation and telemetry."""
    res = await check_abuseipdb(ip)
    if not res.success:
        raise HTTPException(status_code=400, detail=res.error)
    return res.data

