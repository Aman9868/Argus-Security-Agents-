"""Human-in-the-Loop (HITL) Safety and Containment Policy Engine."""

from typing import Dict, Any, Tuple
import os

raw_threshold = os.getenv("CONTAINMENT_HITL_THRESHOLD", "0.75")
try:
    DEFAULT_CONTAINMENT_THRESHOLD = float(raw_threshold) if raw_threshold and raw_threshold.strip() else 0.75
except (ValueError, TypeError):
    DEFAULT_CONTAINMENT_THRESHOLD = 0.75



class ContainmentPolicy:
    """Enforces safety guardrails before executing active defensive containment."""

    @staticmethod
    def evaluate_containment_request(
        action: str,
        target: str,
        confidence: float,
        is_known_critical_infrastructure: bool = False
    ) -> Tuple[bool, str]:
        """
        Determines whether a containment action requires mandatory Human Approval.
        Returns (requires_human_approval: bool, policy_reason: str).
        """
        # Critical infrastructure safety gate
        if is_known_critical_infrastructure:
            return True, "Target is classified as Critical Infrastructure. Automated block prohibited without SOC Lead approval."

        # High-impact actions always require human confirmation
        if action in ["BLOCK_IP", "QUARANTINE_DOMAIN", "ISOLATE_HOST"]:
            if confidence >= DEFAULT_CONTAINMENT_THRESHOLD:
                return True, f"Confidence {confidence:.2f} meets containment threshold ({DEFAULT_CONTAINMENT_THRESHOLD:.2f}). Awaiting SOC analyst confirmation."
            else:
                return True, f"Confidence {confidence:.2f} is below automated threshold. Human review mandatory."

        return False, "Low-risk passive intelligence action. No approval required."

