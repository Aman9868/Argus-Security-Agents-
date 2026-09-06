"""Global LangGraph State definitions for Multi-Agent Cybersecurity Platform."""

from typing import List, Dict, Any, Optional, Annotated
from typing_extensions import TypedDict
import operator
from langchain_core.messages import BaseMessage


class Hypothesis(TypedDict, total=False):
    hypothesis: str
    mitre_technique: str
    status: str  # UNTESTED, CONFIRMED, REFUTED
    confidence: float
    corroboration_count: int


class Evidence(TypedDict, total=False):
    source: str
    claim: str
    raw_data: Any
    confidence: float
    timestamp: float


class PendingAction(TypedDict, total=False):
    action: str  # BLOCK_IP, QUARANTINE_DOMAIN, ISOLATE_HOST
    target: str
    confidence: float
    policy_reason: str
    status: str  # PENDING_APPROVAL, APPROVED, REJECTED
    task_id: str


class CyberSessionState(TypedDict):
    """Unified session state passed between Supervisor and Domain Subgraphs."""
    # Chronological message trail
    messages: Annotated[List[BaseMessage], operator.add]

    # Investigation metadata
    investigation_id: str
    seed_ioc: str
    active_agent: str
    iteration_count: int

    # Hypotheses and Corroborated Evidence
    hypotheses: List[Hypothesis]
    evidence: List[Evidence]

    # Interconnected Entity Knowledge Graph
    knowledge_graph: Dict[str, Any]

    # Cross-subgraph pivot queue for newly discovered entities
    pivot_queue: List[Dict[str, Any]]

    # Information gain metric across iterations
    info_gain_history: List[float]

    # Human-in-the-Loop containment gating
    pending_actions: List[PendingAction]
    hitl_status: str  # NONE, PENDING, APPROVED, REJECTED

    # Synthesis & Deliverables
    final_report: Optional[Dict[str, Any]]
    analyst_summary: Optional[str]

