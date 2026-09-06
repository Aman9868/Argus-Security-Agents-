"""Enterprise Guardrails AI Engine for Cybersecurity Investigation Safety.

Built on the official guardrails-ai library with zero outbound telemetry
and robust deterministic regex fallback.
"""

import os
import re
from typing import Tuple, Optional
import warnings

# Disable outbound telemetry for enterprise data privacy compliance
os.environ["GUARDRAILS_DISABLE_TELEMETRY"] = "true"
os.environ["GUARDRAILS_TELEMETRY"] = "false"
os.environ["OTEL_SDK_DISABLED"] = "true"

warnings.filterwarnings("ignore", message="Could not obtain an event loop", category=UserWarning)
warnings.filterwarnings("ignore", message=".*model_dump.*", category=DeprecationWarning)

from guardrails import Guard
from guardrails.validator_base import Validator, register_validator, PassResult, FailResult
from guardrails.errors import ValidationError
from security.pii import sanitize_cyber_pii
import structlog

logger = structlog.get_logger(__name__)

# Adversarial Prompt Injection & Jailbreak patterns
INJECTION_PATTERNS = [
    r"ignore\s+(?:all\s+)?(?:previous\s+)?instructions",
    r"disregard\s+(?:all\s+)?(?:prior\s+)?rules",
    r"you\s+are\s+now\s+(?:in\s+)?(?:dan|unrestricted|god)\s+mode",
    r"system\s+prompt\s+override",
    r"(?:print|reveal|show|dump)\s+(?:your\s+)?(?:system\s+prompt|initial\s+instructions|internal\s+rules|credentials|tool\s+credentials)",
    r"sudo\s+block",
    r"sudo\s+execute",
    r"act\s+as\s+(?:an?\s+)?unaligned\s+ai",
    r"bypass\s+(?:all\s+)?security\s+(?:checks|rules)",
    r"developer\s+mode\s+enabled"
]

# Prohibited Secret & Credential Patterns
SECRETS_PATTERNS = [
    r"(?:sk-[A-Za-z0-9]{20,})",
    r"(?:ghp_[A-Za-z0-9]{36,})",
    r"(?:AKIA[0-9A-Z]{16})",
    r"(?:bearer\s+[A-Za-z0-9\-\._~\+\/]+=*)",
    r"(?:password\s*[:=]\s*['\"][^'\"]+['\"])"
]


@register_validator(name="cyber_prompt_injection", data_type="string")
class CyberPromptInjectionValidator(Validator):
    """Guardrails AI validator that intercepts jailbreaks and adversarial injections."""

    def validate(self, value: str, metadata: Optional[dict] = None):
        text_lower = value.lower()
        for pattern in INJECTION_PATTERNS:
            if re.search(pattern, text_lower):
                return FailResult(
                    error_message=f"Prompt injection policy violation detected: '{pattern}'"
                )
        return PassResult()


@register_validator(name="cyber_secrets_detector", data_type="string")
class CyberSecretsDetectorValidator(Validator):
    """Guardrails AI validator that prevents submission of credentials and API keys."""

    def validate(self, value: str, metadata: Optional[dict] = None):
        for pattern in SECRETS_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                return FailResult(
                    error_message="Prohibited submission of credentials or secret keys detected."
                )
        return PassResult()


@register_validator(name="cyber_pii_anonymizer", data_type="string")
class CyberPIIAnonymizerValidator(Validator):
    """Guardrails AI output validator that automatically masks sensitive internal IPs and PII."""

    def validate(self, value: str, metadata: Optional[dict] = None):
        cleaned = sanitize_cyber_pii(value)
        if cleaned != value:
            return FailResult(
                error_message="Sensitive data detected in output.",
                fix_value=cleaned
            )
        return PassResult()


class EnterpriseGuardrails:
    """Enterprise-grade Input and Output safety engine powered by Guardrails AI."""

    def __init__(self):
        # 1. Initialize Input Guard (Prompt Injection + Secrets)
        self.input_guard = Guard().use(
            CyberPromptInjectionValidator(on_fail="exception"),
            CyberSecretsDetectorValidator(on_fail="exception")
        )

        # 2. Initialize Output Guard (PII & Secret Sanitization)
        self.output_guard = Guard().use(
            CyberPIIAnonymizerValidator(on_fail="fix")
        )

    def validate_input(self, user_message: str) -> Tuple[bool, Optional[str]]:
        """
        Validates user input using Guardrails AI Input Guard.
        Returns (is_safe: bool, reason: Optional[str]).
        """
        if not user_message or not user_message.strip():
            return False, "Input message cannot be empty."

        if len(user_message) > 4000:
            return False, "Input message exceeds maximum allowed length of 4,000 characters."

        try:
            res = self.input_guard.validate(user_message)
            if res.validation_passed:
                return True, None
            return False, "Input failed Guardrails AI validation checks."
        except ValidationError as val_err:
            logger.warn("Guardrails AI intercepted unsafe input", error=str(val_err))
            return False, str(val_err)
        except Exception as exc:
            # Resilient fallback to local regex engine
            logger.warn("Guardrails AI fallback triggered", error=str(exc))
            for pattern in INJECTION_PATTERNS:
                if re.search(pattern, user_message.lower()):
                    return False, f"Input failed security policy: '{pattern}'"
            return True, None

    def sanitize_output(self, assistant_message: str) -> str:
        """
        Sanitizes assistant responses using Output Guard and PII/IP masking.
        """
        if not assistant_message:
            return ""

        try:
            res = self.output_guard.validate(assistant_message)
            return res.validated_output or sanitize_cyber_pii(assistant_message)
        except Exception as exc:
            logger.warn("Guardrails AI output validation fallback triggered", error=str(exc))
            return sanitize_cyber_pii(assistant_message)

    def validate_lota_tool_call(self, tool_name: str, tool_args: dict) -> Tuple[bool, Optional[str]]:
        """
        Second-Order Immune Guardrail ("Living off the Agent" Defense).
        Inspects inter-agent tool calls and parameters for indirect prompt injection
        hijacking attempts before executing destructive or sensitive operations.
        """
        # Dangerous shell / traversal substrings
        dangerous_tokens = [
            ";", "&&", "||", "`", "$(", "rm -rf", "mkfs", "dd if=",
            "/etc/shadow", "/etc/passwd", "DROP TABLE", "SELECT * FROM users",
            "curl -s", "wget http", "| sh", "| bash"
        ]

        # Check all string arguments
        args_str = " ".join(str(v) for v in tool_args.values())
        for token in dangerous_tokens:
            if token.lower() in args_str.lower():
                logger.error("LOTA Defense Interception: Dangerous tool payload rejected", tool=tool_name, token=token)
                return False, f"LOTA Immune Guard: Prohibited payload pattern '{token}' detected in tool '{tool_name}'."

        for pattern in INJECTION_PATTERNS:
            if re.search(pattern, args_str, re.IGNORECASE):
                logger.error("LOTA Defense Interception: Indirect prompt injection rejected", tool=tool_name, pattern=pattern)
                return False, f"LOTA Immune Guard: Indirect injection pattern '{pattern}' detected in tool '{tool_name}'."

        return True, None


# Singleton enterprise guardrails instance
enterprise_guardrails = EnterpriseGuardrails()

