"""Strict Input Validation and Sanitization for Cybersecurity IOCs."""

import re
from typing import Tuple, Optional

# Standard IOC validation regular expressions
IPV4_PATTERN = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)
IPV6_PATTERN = re.compile(r"^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$")
DOMAIN_PATTERN = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)
MD5_PATTERN = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_PATTERN = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_PATTERN = re.compile(r"^[a-fA-F0-9]{64}$")
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)
URL_PATTERN = re.compile(r"^https?://[^\s/$.?#].[^\s]*$", re.IGNORECASE)


def validate_ioc(ioc: str) -> Tuple[bool, str, Optional[str]]:
    """
    Validates and classifies an Indicator of Compromise (IOC).
    Returns (is_valid: bool, ioc_type: str, normalized_value: Optional[str]).
    """
    if not ioc or not isinstance(ioc, str):
        return False, "UNKNOWN", None

    cleaned = ioc.strip()

    # IPv4
    if IPV4_PATTERN.match(cleaned):
        return True, "IP", cleaned

    # MD5, SHA1, SHA256
    if SHA256_PATTERN.match(cleaned):
        return True, "SHA256", cleaned.lower()
    if MD5_PATTERN.match(cleaned):
        return True, "MD5", cleaned.lower()
    if SHA1_PATTERN.match(cleaned):
        return True, "SHA1", cleaned.lower()

    # CVE
    if CVE_PATTERN.match(cleaned):
        return True, "CVE", cleaned.upper()

    # URL
    if URL_PATTERN.match(cleaned):
        return True, "URL", cleaned

    # Domain / FQDN
    if DOMAIN_PATTERN.match(cleaned):
        return True, "DOMAIN", cleaned.lower()

    return False, "UNKNOWN", None


def sanitize_ioc_input(ioc: str) -> str:
    """Strip malicious shell characters and control bytes from IOC strings."""
    if not isinstance(ioc, str):
        return ""
    # Strip non-printable and shell injection characters
    return re.sub(r"[^\w\.\-/:?#@]", "", ioc.strip())

