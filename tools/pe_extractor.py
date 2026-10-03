"""
Argus Security Agents — Real PE Feature Extractor
Extracts static structural features, Shannon entropy, and Win32 API calls from Portable Executable (PE) binaries.
Compatible with EMBER / BODMAS feature schemas for LightGBM & PySpark classification pipelines.
"""

import math
import os
import hashlib
from typing import Dict, Any, List, Optional
import structlog

logger = structlog.get_logger("argus.tools.pe_extractor")

# High-risk Win32 API symbols commonly abused by Malware / Ransomware / Rootkits
SUSPICIOUS_WIN32_APIS = {
    # Process Injection & Memory Manipulation
    "VirtualAlloc": "injection",
    "VirtualAllocEx": "injection",
    "VirtualProtect": "injection",
    "VirtualProtectEx": "injection",
    "WriteProcessMemory": "injection",
    "ReadProcessMemory": "injection",
    "CreateRemoteThread": "injection",
    "QueueUserAPC": "injection",
    "NtWriteVirtualMemory": "injection",
    "NtQueueApcThread": "injection",
    # Evasion & Anti-Analysis
    "IsDebuggerPresent": "anti_debug",
    "CheckRemoteDebuggerPresent": "anti_debug",
    "NtQueryInformationProcess": "anti_debug",
    "OutputDebugStringA": "anti_debug",
    "Sleep": "timing_evasion",
    "SleepEx": "timing_evasion",
    "timeSetEvent": "timing_evasion",
    # Persistence & Privilege
    "RegOpenKeyExA": "persistence",
    "RegOpenKeyExW": "persistence",
    "RegSetValueExA": "persistence",
    "RegSetValueExW": "persistence",
    "AdjustTokenPrivileges": "privilege_escalation",
    "OpenProcessToken": "privilege_escalation",
    "LookupPrivilegeValueA": "privilege_escalation",
    # Network & C2 Exfiltration
    "InternetOpenA": "networking",
    "InternetOpenW": "networking",
    "InternetOpenUrlA": "networking",
    "InternetConnectA": "networking",
    "HttpOpenRequestA": "networking",
    "HttpSendRequestA": "networking",
    "URLDownloadToFileA": "networking",
    "WSAStartup": "networking",
    "connect": "networking",
    "send": "networking",
    # Crypto / Ransomware Activity
    "CryptEncrypt": "ransomware_crypto",
    "CryptDecrypt": "ransomware_crypto",
    "CryptAcquireContextA": "ransomware_crypto",
    "CryptGenKey": "ransomware_crypto",
}

FEATURE_COLUMNS = [
    "file_size",
    "overall_entropy",
    "num_sections",
    "mean_section_entropy",
    "max_section_entropy",
    "min_section_entropy",
    "num_suspicious_sections",
    "num_imported_dlls",
    "num_imported_functions",
    "num_suspicious_apis",
    "api_density",
    "injection_api_count",
    "anti_debug_api_count",
    "persistence_api_count",
    "networking_api_count",
    "crypto_api_count",
    "has_debug_stripped",
    "has_tls",
    "has_relocations",
    "is_packed_heuristic",
    "entrypoint_section_entropy",
]


def calculate_entropy(data: bytes) -> float:
    """Calculates Shannon entropy: H = -sum(p_i * log2(p_i)) over byte distribution [0.0 - 8.0]."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    occurrences = [0] * 256
    for byte in data:
        occurrences[byte] += 1

    for count in occurrences:
        if count > 0:
            p_x = float(count) / length
            entropy -= p_x * math.log2(p_x)

    return round(entropy, 4)


def extract_pe_features(file_path: str) -> Dict[str, Any]:
    """
    Extracts comprehensive static structural and behavioral features from a PE file.
    Works with pefile if installed, with a reliable byte-level fallback if not a standard PE.
    """
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"Target binary not found: {file_path}")

    file_size = os.path.getsize(file_path)
    with open(file_path, "rb") as f:
        content = f.read()

    overall_entropy = calculate_entropy(content)
    sha256 = hashlib.sha256(content).hexdigest()
    md5 = hashlib.md5(content).hexdigest()

    # Default baseline feature dictionary
    features = {
        "sha256": sha256,
        "md5": md5,
        "file_size": file_size,
        "overall_entropy": overall_entropy,
        "num_sections": 0,
        "mean_section_entropy": overall_entropy,
        "max_section_entropy": overall_entropy,
        "min_section_entropy": overall_entropy,
        "num_suspicious_sections": 0,
        "num_imported_dlls": 0,
        "num_imported_functions": 0,
        "num_suspicious_apis": 0,
        "api_density": 0.0,
        "injection_api_count": 0,
        "anti_debug_api_count": 0,
        "persistence_api_count": 0,
        "networking_api_count": 0,
        "crypto_api_count": 0,
        "has_debug_stripped": 0,
        "has_tls": 0,
        "has_relocations": 0,
        "is_packed_heuristic": 1 if overall_entropy > 7.1 else 0,
        "entrypoint_section_entropy": overall_entropy,
        "sections": [],
        "matched_suspicious_apis": [],
    }

    try:
        import pefile
        pe = pefile.PE(data=content, fast_load=True)
        pe.parse_data_directories()

        # 1. Sections and Entropy
        section_entropies = []
        sections_data = []
        for s in pe.sections:
            try:
                name = s.Name.decode('utf-8', errors='ignore').strip('\x00')
            except Exception:
                name = "unknown"
            s_entropy = s.get_entropy()
            section_entropies.append(s_entropy)
            is_suspicious = (s_entropy > 7.2) or (name.lower() in [".upx", ".themida", ".vmp", "packer", "aspack"])
            sections_data.append({
                "name": name,
                "virtual_size": s.Misc_VirtualSize,
                "raw_size": s.SizeOfRawData,
                "entropy": round(s_entropy, 3),
                "is_suspicious": is_suspicious,
            })

        features["sections"] = sections_data
        features["num_sections"] = len(sections_data)
        if section_entropies:
            features["mean_section_entropy"] = round(sum(section_entropies) / len(section_entropies), 4)
            features["max_section_entropy"] = round(max(section_entropies), 4)
            features["min_section_entropy"] = round(min(section_entropies), 4)
            features["num_suspicious_sections"] = sum(1 for e in section_entropies if e > 7.2)
            features["entrypoint_section_entropy"] = round(section_entropies[0], 4)

        # 2. Imports & Suspicious APIs
        dll_count = 0
        fn_count = 0
        matched_apis = []
        injection_count = 0
        anti_debug_count = 0
        persistence_count = 0
        networking_count = 0
        crypto_count = 0

        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            dll_count = len(pe.DIRECTORY_ENTRY_IMPORT)
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        fn_name = imp.name.decode('utf-8', errors='ignore')
                        fn_count += 1
                        if fn_name in SUSPICIOUS_WIN32_APIS:
                            category = SUSPICIOUS_WIN32_APIS[fn_name]
                            matched_apis.append({"api": fn_name, "category": category})
                            if category == "injection":
                                injection_count += 1
                            elif category == "anti_debug":
                                anti_debug_count += 1
                            elif category == "persistence":
                                persistence_count += 1
                            elif category == "networking":
                                networking_count += 1
                            elif category == "ransomware_crypto":
                                crypto_count += 1

        features["num_imported_dlls"] = dll_count
        features["num_imported_functions"] = fn_count
        features["num_suspicious_apis"] = len(matched_apis)
        features["api_density"] = round(len(matched_apis) / max(fn_count, 1), 4)
        features["injection_api_count"] = injection_count
        features["anti_debug_api_count"] = anti_debug_count
        features["persistence_api_count"] = persistence_count
        features["networking_api_count"] = networking_count
        features["crypto_api_count"] = crypto_count
        features["matched_suspicious_apis"] = matched_apis

        # 3. Header flags
        features["has_tls"] = 1 if hasattr(pe, 'DIRECTORY_ENTRY_TLS') else 0
        features["has_debug_stripped"] = 1 if not hasattr(pe, 'DIRECTORY_ENTRY_DEBUG') else 0
        features["has_relocations"] = 1 if hasattr(pe, 'DIRECTORY_ENTRY_BASERELOC') else 0
        features["is_packed_heuristic"] = 1 if (features["max_section_entropy"] > 7.4 or features["num_imported_functions"] < 5) else 0

        pe.close()
    except Exception as e:
        logger.warning("pefile_parsing_fallback", error=str(e), file_path=file_path)
        # Fallback heuristic: byte scan for suspicious API strings
        matched_apis = []
        for api, cat in SUSPICIOUS_WIN32_APIS.items():
            if api.encode('ascii') in content:
                matched_apis.append({"api": api, "category": cat})
        features["matched_suspicious_apis"] = matched_apis
        features["num_suspicious_apis"] = len(matched_apis)

    return features


def extract_feature_vector(file_path: str) -> List[float]:
    """Returns the ordered numerical feature vector matching the model's training schema."""
    data = extract_pe_features(file_path)
    return [float(data.get(col, 0.0)) for col in FEATURE_COLUMNS]

