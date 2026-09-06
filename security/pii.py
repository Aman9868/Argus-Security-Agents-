"""Cybersecurity PII and Sensitive Network Telemetry Masking Module."""

import re

# Regex patterns for sensitive infrastructure, credentials, and identity data
INTERNAL_IP_PATTERN = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b"
)
API_KEY_PATTERN = re.compile(
    r"\b(?:sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{36,}|AKIA[0-9A-Z]{16}|lsv2_pt_[A-Za-z0-9_]{32,}|gsk_[A-Za-z0-9]{30,})\b"
)
BEARER_TOKEN_PATTERN = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9\-\._~\+\/]+=*", re.IGNORECASE)
EMAIL_PATTERN = re.compile(r"([a-zA-Z0-9_.+-]{1,3})[a-zA-Z0-9_.+-]*@([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)")
PHONE_PATTERN = re.compile(r"\b(?:\+?\d{1,3}[- ]?)?(\d{2,3})\d{4,6}(\d{2,4})\b")
PASSWORD_PATTERN = re.compile(r"(?i)(password|secret|api_key|token)\s*[:=]\s*['\"][^'\"]+['\"]")


def mask_internal_ip(text: str) -> str:
    """Mask private RFC 1918 IPs to prevent internal topology leakage."""
    return INTERNAL_IP_PATTERN.sub("[REDACTED_INTERNAL_IP]", text)


def mask_api_keys(text: str) -> str:
    """Mask sensitive cloud and service API keys."""
    return API_KEY_PATTERN.sub("[REDACTED_API_KEY]", text)


def mask_bearer_tokens(text: str) -> str:
    """Mask bearer authorization tokens."""
    return BEARER_TOKEN_PATTERN.sub("Bearer [REDACTED_TOKEN]", text)


def mask_email(text: str) -> str:
    """Mask email addresses to a***@domain.com."""
    return EMAIL_PATTERN.sub(r"\1***@\2", text)


def mask_phone(text: str) -> str:
    """Mask phone numbers preserving prefix and last 2 digits."""
    return PHONE_PATTERN.sub(r"\1******\2", text)


def mask_passwords(text: str) -> str:
    """Mask cleartext password assignments."""
    return PASSWORD_PATTERN.sub(r"\1='[REDACTED_CREDENTIAL]'", text)


def sanitize_cyber_pii(text: str) -> str:
    """
    Apply comprehensive sanitization for cybersecurity reports, logs, and UI display:
    Redacts internal IP addresses, API keys, credentials, and PII.
    """
    if not isinstance(text, str):
        return text
    masked = mask_internal_ip(text)
    masked = mask_api_keys(masked)
    masked = mask_bearer_tokens(masked)
    masked = mask_passwords(masked)
    masked = mask_email(masked)
    masked = mask_phone(masked)
    return masked

