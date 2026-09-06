"""Chat Endpoint with Guardrails AI and Multi-Agent Routing."""

import time
from fastapi import APIRouter
from apps.api.schemas.investigation import ChatRequest, ChatResponse
from security.guardrails_engine import enterprise_guardrails
from security.pii import sanitize_cyber_pii
from gateway.llm.client import llm_gateway
from langchain_core.messages import HumanMessage, SystemMessage
import structlog

logger = structlog.get_logger(__name__)
router = APIRouter(prefix="/chat", tags=["Chat"])


@router.post("", response_model=ChatResponse)
@router.post("/message", response_model=ChatResponse)
async def chat_interaction(request: ChatRequest):
    """
    Direct SOC conversational endpoint protected by Guardrails AI:
    - Blocks prompt injection, jailbreak instructions, and secret submissions.
    - Sanitizes assistant output to avoid leaking internal IPs and sensitive tokens.
    """
    user_msg = request.message

    # 1. Guardrails AI Input Validation
    is_safe, violation_reason = enterprise_guardrails.validate_input(user_msg)
    if not is_safe:
        return ChatResponse(
            response=f"Security Guardrail Interception: {violation_reason}",
            safe=False,
            active_agent="guardrail_sentinel"
        )

    # 2. Invoke LLM Gateway
    system_prompt = (
        "You are Cyber Sentinel, an expert autonomous SOC analyst and threat hunting AI. "
        "Assist the security analyst with threat intelligence inquiries, IOC triage, "
        "MITRE ATT&CK technique lookups, and incident response procedures."
    )
    messages = [
        SystemMessage(content=system_prompt),
        HumanMessage(content=user_msg)
    ]
    resp = await llm_gateway.invoke(messages, model_tier="reasoning")

    # 3. Guardrails AI Output Sanitization
    safe_output = enterprise_guardrails.sanitize_output(resp.content)
    safe_output = sanitize_cyber_pii(safe_output)

    return ChatResponse(
        response=safe_output,
        safe=True,
        active_agent="cyber_sentinel"
    )

