"""Pydantic request and response schemas for Cybersecurity API."""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class InvestigationRequest(BaseModel):
    ioc: str = Field(..., description="Target Indicator of Compromise (IP, domain, hash, CVE, or raw email)")
    investigation_id: Optional[str] = Field(None, description="Unique investigation identifier")


class InvestigationResponse(BaseModel):
    investigation_id: str
    seed_ioc: str
    verdict: str
    confidence_score: float
    analyst_summary: str
    total_entities_discovered: int
    total_infrastructure_links: int
    mitre_attck_mappings: List[str]
    d3fend_countermeasures: List[Dict[str, Any]] = []
    sigma_rule: Optional[str] = None
    yara_rule: Optional[str] = None
    stix_bundle: Optional[Dict[str, Any]] = None
    pending_containment_actions: List[Dict[str, Any]]
    knowledge_graph_elements: List[Dict[str, Any]]


class ChatRequest(BaseModel):
    message: str = Field(..., description="Analyst command or query")
    investigation_id: Optional[str] = None


class ChatResponse(BaseModel):
    response: str
    safe: bool = True
    active_agent: str = "supervisor"
    knowledge_graph_elements: List[Dict[str, Any]] = []


class HITLApprovalRequest(BaseModel):
    task_id: str
    approved: bool = True
    target: Optional[str] = None
    action_type: Optional[str] = "BLOCK_IP"
    analyst_notes: Optional[str] = None


class HITLApprovalResponse(BaseModel):
    task_id: str
    status: str
    action_result: Optional[Dict[str, Any]] = None

