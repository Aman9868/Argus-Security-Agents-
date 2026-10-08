"""AI Red-Teaming & AI-SPM (AI Security Posture Management) Module.

Provides automated adversarial benchmarking, OWASP LLM Top 10 compliance audits,
LOTA (Living off the Agent) tool security verification, and RAG poisoning scanning.
"""

from tools.ai_redteam.models import (
    OwaspLlmCategory,
    AttackTechnique,
    RiskSeverity,
    BenchmarkProbe,
    ProbeEvaluationResult,
    RedTeamAuditReport,
    RagScanResult,
    ToolCallAuditRequest,
    ToolCallAuditResult,
    CrescendoTurn,
    CrescendoAuditResult
)
from tools.ai_redteam.benchmark_suites import get_standard_benchmark_suite
from tools.ai_redteam.rag_scanner import RagDocumentScanner, rag_scanner
from tools.ai_redteam.evaluator import AiRedTeamEvaluator, ai_redteam_evaluator

__all__ = [
    "OwaspLlmCategory",
    "AttackTechnique",
    "RiskSeverity",
    "BenchmarkProbe",
    "ProbeEvaluationResult",
    "RedTeamAuditReport",
    "RagScanResult",
    "ToolCallAuditRequest",
    "ToolCallAuditResult",
    "CrescendoTurn",
    "CrescendoAuditResult",
    "get_standard_benchmark_suite",
    "RagDocumentScanner",
    "rag_scanner",
    "AiRedTeamEvaluator",
    "ai_redteam_evaluator",
]
