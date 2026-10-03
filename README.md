# Argus Security Agents — Cyber Sentinel XDR Platform

> **Next-Generation Autonomous Multi-Agent Cybersecurity Platform**  
> *Smarter Detection · Faster Response · Autonomous Defense · Safer Tomorrow*

[![Python 3.12](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![LangGraph](https://img.shields.io/badge/Orchestration-LangGraph-orange.svg)](https://github.com/langchain-ai/langgraph)
[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688.svg)](https://fastapi.tiangolo.com/)
[![LSP 3.17](https://img.shields.io/badge/IDE_Protocol-LSP_3.17-purple.svg)](https://microsoft.github.io/language-server-protocol/)
[![CycloneDX 1.6](https://img.shields.io/badge/SBOM-CycloneDX_1.6-blue.svg)](https://cyclonedx.org/)
[![OpenVEX](https://img.shields.io/badge/Advisory-OpenVEX_v0.2.0-brightgreen.svg)](https://openvex.dev/)
[![Tests Passing](https://img.shields.io/badge/Tests-95%20Passed-success.svg)](#-test-verification)

---

## 🖥️ Cyber Sentinel SOC Operations Platform

| Argus SOC Operations Center | Threat Infrastructure Graph & World Map |
| :---: | :---: |
| ![Argus SOC Operations Center](docs/screenshots/soc_analyst_dashboard.png) | ![Threat Infrastructure Graph & World Map](docs/screenshots/threat_infrastructure_graph.png) |

| Autonomous Quishing & Phishing Pipeline | Adversarial Arena & Blast Radius | Analyst AI Copilot |
| :---: | :---: | :---: |
| ![Quishing & Phishing Pipeline](docs/screenshots/quishing_phishing_pipeline.png) | ![Adversarial Arena & Blast Radius](docs/screenshots/adversarial_arena_blast_radius.png) | ![Analyst AI Copilot](docs/screenshots/analyst_copilot_chat.png) |

---


## 🌟 Executive Overview

**Argus Security Agents (Cyber Sentinel XDR)** is a state-of-the-art autonomous multi-agent cybersecurity operations platform. Engineered on **LangGraph**, **FastAPI**, and modern **XDR Operations Architecture**, Argus orchestrates specialized AI agents capable of end-to-end incident investigation, cross-subgraph pivoting, proactive cyber deception, supply chain SBOM/AI-BOM governance, and in-editor Language Server Protocol (LSP) code defense.

### Key Capabilities at a Glance:
1. **Real-Time Cyber LSP Daemon (Language Server Protocol 3.17)**: High-performance background LSP daemon (`python -m tools.lsp.server`) providing live AST interprocedural taint tracking directly into VS Code, Cursor, and Neovim; highlights untrusted user inputs flowing to dangerous sinks (`yaml.load`, `pickle.loads`, `os.system`) with 1-click QuickFix CodeActions.
2. **Autonomous SBOM & AI-BOM Sentinel with OpenVEX Triage**: CycloneDX 1.6 & SPDX dependency cataloging with AST call-graph reachability, eliminating up to **81% of vulnerability alert fatigue**; audits AI models (`.safetensors` vs pickle RCE), MCP tools, and flags AI slopsquatting package lures; exports exact Code Scoring-style multi-page PDF audit reports.
3. **Autonomous Adversarial Arena (Red vs. Blue Self-Play)**: Pits Red Agent adversary emulation (APT29, FIN7, Lazarus Group) against Blue Agent defenders in multi-round duels, calculating real-time Time-to-Detect (TTD ms) and synthesizing verified Sigma detection rules.
4. **Autonomous Attack Path & Blast Radius Predictor**: Monte Carlo simulation of lateral movement radiating from an IOC or compromised host, calculating reachability to Crown Jewel databases, Domain Controllers, and Cloud buckets within 1-3 pivot hops; computes Mean Time to Breach (MTTB in min); identifies proactive "Chokepoint Defenses"; and overlays glowing dashed amber paths directly onto Cytoscape.js.
5. **Autonomous Binary & Payload Dissection Agent (Static Reverse Engineering)**: Safe static reverse engineering of malicious payloads (`invoice.docx`, `stager.exe`, `rat_client.bin`), extracting section Shannon entropy scores, identifying suspicious Win32 APIs (`VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`), de-obfuscating strings (Base64/XOR/ROT13), and synthesizing dynamic YARA-L memory rules.
6. **Generative Chameleon Honeytokens & Deception Sinks**: Dynamically deploys contextual decoy credentials (fake AWS keys, canary database strings, decoy JWTs) to bait and trap lateral movement attempts.
7. **GraphRAG Multi-Hop Deep Threat Hunting**: Recursive 3-hop graph traversal uncovering hidden C2 infrastructure, bulletproof hosting networks, and shared registrant footprints.
8. **Dual Threat Infrastructure Visualization**: High-resolution interactive Cytoscape.js threat graph coupled with a Leaflet & D3 cyber world map displaying real-time geographic attack origin telemetry.
9. **Human-in-the-Loop (HITL) Containment Gateway**: Strict RBAC-enforced safety policies preventing unverified quarantine actions while allowing sub-second containment when approved.
10. **Enterprise Guardrails AI & PII Masking**: Real-time interception of prompt injections, jailbreaks, and sensitive internal IP topology leaks.

---

## 🏛️ System Architecture

```mermaid
flowchart TD
    subgraph UI_API ["Frontend & API Gateway Layer"]
        Analyst["SOC Analyst / SecOps Team"] --> Dashboard["Argus SOC Dashboard (Port 8001)"]
        Dashboard --> API["FastAPI REST & WebSocket Gateway"]
        API --> SecHeaders["Security Headers & Rate Limiting"]
        SecHeaders --> Guardrails["Guardrails AI Engine (Jailbreak & Secret Interception)"]
    end

    subgraph Orchestration ["LangGraph Multi-Agent Orchestration"]
        Guardrails --> Supervisor["Supervisor Router Agent"]
        Supervisor --> SharedState["Shared CyberSessionState & Knowledge Graph"]
        
        Supervisor <-->|Pivots & Entity Queues| AgentThreat["Threat Hunt & TIP Subgraph"]
        Supervisor <-->|Pivots & Entity Queues| AgentOSINT["OSINT Footprinting Subgraph"]
        Supervisor <-->|Pivots & Entity Queues| AgentPhish["Phishing Triage Subgraph"]
        Supervisor <-->|Pivots & Entity Queues| AgentVuln["Vulnerability Intel Subgraph"]
    end

    subgraph Deception_Arena ["Frontier Autonomous Defense Modules"]
        Supervisor <--> Arena["Adversarial Arena (Red vs. Blue Self-Play)"]
        Supervisor <--> Deception["Chameleon Honeytoken Engine"]
        Arena --> SigmaGen["Sigma Rule Synthesis Engine"]
    end

    subgraph Security_Gateway ["Tool Gateway & Safety Controls"]
        AgentThreat --> ToolGW["Central Tool Gateway"]
        AgentOSINT --> ToolGW
        AgentPhish --> ToolGW
        AgentVuln --> ToolGW
        
        ToolGW --> RBAC["RBAC Least-Privilege Policy"]
        ToolGW --> Idempotency["TTL Cache & Idempotency Layer"]
        ToolGW --> HITL["HITL Safety Gate (Human Authorization)"]
    end

    subgraph External_Intel ["Defensive Telemetry & Providers"]
        ToolGW --> VT["VirusTotal API (Cached 4 req/min)"]
        ToolGW --> OTX["AlienVault OTX & Pulses"]
        ToolGW --> Abuse["abuse.ch (URLhaus / Bazaar)"]
        ToolGW --> MITRE["MITRE ATT&CK & D3FEND"]
        ToolGW --> NVD["NVD / CISA KEV Exploited DB"]
        HITL --> Containment["Network & Endpoint Containment"]
    end

    subgraph Visualization ["Storage & Visual Operations"]
        SharedState --> SQLite[(SQLite Cyber Intelligence DB)]
        SharedState --> CytoGraph["Cytoscape.js Threat Infrastructure"]
        SharedState --> GeoMap["Leaflet / D3 Global Attack Map"]
    end
```

---

## 🗺️ Master Multi-Agent Architecture (LangGraph)

Below is the complete multi-agent execution graph across all autonomous subgraphs, generated directly from the compiled LangGraph state machines:

<p align="center">
  <img src="docs/graphs/cyber_graph_full.png" alt="LangGraph Master Multi-Agent Architecture" width="100%" />
</p>

### Autonomous Subgraphs & Specialized Agents

| Threat Hunting & TIP Subgraph | OSINT Footprinting Subgraph |
| :---: | :---: |
| ![Threat Hunt Subgraph](docs/graphs/threat_hunt_subgraph.png) | ![OSINT Subgraph](docs/graphs/osint_subgraph.png) |

| Phishing & Quishing Triage Subgraph | Vulnerability Intelligence Subgraph |
| :---: | :---: |
| ![Phishing Subgraph](docs/graphs/phishing_subgraph.png) | ![Vuln Subgraph](docs/graphs/vuln_subgraph.png) |

### High-Level Supervisor Routing Overview

<p align="center">
  <img src="docs/graphs/supervisor_overview.png" alt="Supervisor Routing Overview" width="75%" />
</p>

> **Diagram Regeneration**: You can regenerate and update all LangGraph architecture diagrams at any time using:
> ```bash
> python scripts/generate_graphs.py
> ```

---

## ⚔️ Autonomous Adversarial Arena (Red vs. Blue)


The **Adversarial Arena** provides autonomous Breach & Attack Simulation (BAS) telemetry without generating weaponized malware:

- **Red Agent Personas**:
  - **APT29 / Cozy Bear**: State-sponsored espionage, OAuth consent lures, timestomping, and masqueraded TLS C2 beaconing.
  - **FIN7 / Carbanak Group**: Financial syndicate, weaponized macro attachments, reflective DLL injection, and encrypted 7z POS exfiltration.
  - **Lazarus Group / APT38**: Crypto-theft & critical infrastructure disruption, supply chain npm postinstall hooks, LSASS memory dumping, and high-entropy DNS tunneling.
- **Blue Agent Defenses**:
  - Emulates 3 posture profiles: `Strict Zero-Trust`, `Balanced SOC`, and `Aggressive Autonomous`.
  - Calculates sub-second **Time-to-Detect (TTD in ms)** per round.
  - Executes instant containment (host isolation, token revocation, firewall perimeter block).
  - Automatically synthesizes **production-ready Sigma detection rules** in YAML format.

---

## 🍯 Generative Chameleon Deception Operations

Argus actively deploys dynamic honeytoken decoys into simulated production assets:
- **Canary AWS Access Keys**: `AKIA...` tokens monitored for unauthorized AWS STS queries.
- **Decoy JDBC Connection Strings**: Monitored for rogue SQL reconnaissance.
- **Canary JWT Auth Tokens**: Signed with trapped sub claims alerting when parsed.
- **Canary Web Endpoints**: Hidden admin/metrics endpoints triggering automated IP containment upon probe.

## ⚡ Autonomous Attack Path & Blast Radius Predictor

When an IOC or compromised host is identified, Argus simulates lateral movement trajectories across enterprise network topology and Active Directory / Cloud IAM domains using Monte Carlo simulation (500 iterations):
- **Crown Jewel Reachability**: Maps which PostgreSQL PCI vaults, Active Directory Domain Controllers (`DC-CORP-01`), and AWS S3 financial buckets (`s3://corp-finance-vault-prod`) are within 1-3 pivot hops.
- **Mean Time to Breach (MTTB)**: Computes realistic velocity metrics (e.g. 18-minute compromise window).
- **Proactive Chokepoint Defenses**: Recommends high-impact tactical isolations (e.g., `CP-01: Zero-Trust ACL on Port 5432`, `CP-02: Sever Kerberos Constrained Delegation`, `CP-03: Invalidate AWS STS credentials`) that sever up to 45% of potential lateral pathways.
- **Cytoscape Canvas Overlay**: Injects predicted trajectories onto the interactive canvas in glowing dashed amber lines (`isAttackPath: true`) with sub-second path layout calculation.

---

## 🔬 Autonomous Binary & Payload Dissection Agent

Argus features an agentic static reverse engineering pipeline designed for zero-trust environments:
- **Shannon Entropy Profiling**: Computes byte distribution entropy across PE and macro sections (`.text`, `.rdata`, `.rsrc`, `word/vbaProject.bin`). Sections exceeding 7.0 entropy are flagged as heavily packed, encrypted, or containing weaponized shellcode.
- **Suspicious Win32 API Cataloging**: Scans Import Address Tables (IAT) and flags offensive API patterns (`VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`, `MiniDumpWriteDump`, `AdjustTokenPrivileges`) correlated to MITRE ATT&CK tactics (T1055, T1003, T1056).
- **Automated String De-obfuscation**: Detects and decodes hidden payload strings encoded in Base64 (including UTF-16LE PowerShell commands), XOR byte ciphers, and Caesar/ROT13 obfuscation.
- **Dynamic YARA-L Rule Synthesis**: Automatically generates production-ready YARA-L memory rules containing extracted byte signatures and API combinations for instant deployment to SIEM and EDR fleets.

---

## 🛡️ Autonomous SBOM & AI-BOM Supply Chain Sentinel

Argus delivers enterprise-grade software supply chain security and AI governance:
- **CycloneDX 1.6 & SPDX 2.3 Generation**: Automatically discovers and catalogs dependencies across Python manifests (`requirements.txt`, `pyproject.toml`, `Pipfile`).
- **AST Call-Graph Reachability Triage**: Traces caller code down to third-party library execution sinks. Unreachable CVEs are suppressed from developer alert streams, eliminating up to **81% of vulnerability alert fatigue**.
- **Compliant OpenVEX (v0.2.0) & CSAF (v2.0)**: Synthesizes machine-readable vulnerability advisories with formal justification statements (`vulnerable_code_not_in_execute_path`, `inline_mitigations_exist`).
- **AI-BOM Governance & Model Risk Audit**: Audits foundation models, weights serialization (`.safetensors` vs high-risk pickle bytecode deserialization), and Model Context Protocol (MCP) tool endpoints.
- **AI Slopsquatting & Hallucination Guard**: Detects typosquatted and LLM-hallucinated package lures before they can execute malicious code.
- **Code Scoring-Style Multi-Page PDF Audit Report**: Generates executive PDF reports matching the enterprise Code Scoring standard, featuring CVSS distributions, technology breakdown, vulnerability tables, reachability verdicts, and ASCII dependency trees.

---

## ⚡ Real-Time Cyber LSP Daemon & Interprocedural Taint Studio

Argus features a native **Language Server Protocol (LSP 3.17)** background daemon that speaks JSON-RPC 2.0 to bring real-time security intelligence directly into the developer's editor:
- **Zero-Latency In-IDE Diagnostics**: Runs locally in $<12\text{ms}$ as developers type, emitting `textDocument/publishDiagnostics` directly into VS Code, Cursor, Neovim, and JetBrains.
- **Interprocedural Taint Tracking**: Traces untrusted sources (FastAPI `Request.body`, Flask `request.args`, Django `request.POST`, `sys.argv`, `os.environ`) down to vulnerable execution sinks (`yaml.load`, `pickle.loads`, `os.system`).
- **Smart Constant Suppression**: Distinguishes between dangerous user-controlled inputs and compile-time static constants (e.g. `yaml.load("static_config")`), automatically suppressing noise to informational advisories.
- **1-Click LSP Quick-Fix CodeActions**: Provides standard `CodeAction` quick-fixes (`Alt + Enter`) that automatically rewrite vulnerable calls (e.g. `yaml.load` -> `yaml.safe_load`) in the active buffer.
- **Dual-Mode Operation**: Run via stdio (`python -m tools.lsp.server`) or interactively in the Web Dashboard via the **Cyber LSP & Taint Studio**.

---

## 📁 Repository Structure

```
cyber-agent/
├── agents/
│   ├── arena/               # Adversarial Arena Red vs Blue engine
│   ├── osint/               # OSINT & domain footprinting subgraph
│   ├── phishing/            # Phishing triage & email header analysis
│   ├── sbom/                # LangGraph SBOM, Reachability & OpenVEX subgraph
│   ├── supervisor/          # LangGraph supervisor router
│   ├── threat_hunt/         # Threat intelligence & MITRE mapping
│   └── vuln/                # CVE, CVSS, and CISA KEV intelligence
├── apps/
│   └── api/
│       ├── main.py          # FastAPI application entrypoint
│       ├── routes/          # Modular API route controllers
│       │   ├── arena.py     # Adversarial Arena endpoints
│       │   ├── blast_radius.py # Attack Path & Blast Radius endpoints
│       │   ├── chat.py      # Guardrail-protected chat
│       │   ├── deception.py # Chameleon honeytoken deployment
│       │   ├── hitl.py      # Human-in-the-loop review
│       │   ├── investigation.py # Threat investigation endpoints
│       │   ├── lsp.py       # Cyber LSP & Taint Analysis endpoints
│       │   ├── malware.py   # Binary & payload dissection endpoints
│       │   └── sbom.py      # SBOM, AI-BOM & Git Scan endpoints
│       └── static/          # Segregated high-performance web dashboard
│           ├── css/         # Modular styles (styles.css)
│           ├── js/          # Segregated client orchestrators
│           │   ├── app.js
│           │   ├── arena.js
│           │   ├── blast_radius.js
│           │   ├── copilot.js
│           │   ├── deception.js
│           │   ├── graph.js
│           │   ├── lsp.js   # Cyber LSP Studio controller
│           │   ├── malware.js
│           │   └── sbom.js  # SBOM & Git Scanner controller
│           └── index.html   # Main dashboard shell
├── core/
│   ├── gateway/             # Central Tool Gateway with RBAC & cache
│   ├── permissions/         # AgentRole permission matrices
│   └── state/               # Shared CyberSessionState models
├── security/
│   └── guardrails_engine.py # Prompt injection & secret leakage shields
├── storage/
│   └── db.py                # SQLite persistence
├── tools/
│   ├── blast_radius.py      # Monte Carlo lateral attack path & chokepoint engine
│   ├── deception.py         # Chameleon honeytoken generator
│   ├── git_scanner.py       # Workspace discovery & shallow Git clone engine
│   ├── lsp/                 # Language Server Protocol 3.17 & Taint Engine
│   │   ├── protocol.py      # LSP 3.17 models & JSON-RPC 2.0 framer
│   │   ├── server.py        # Asynchronous CyberLspServer daemon
│   │   └── taint_engine.py  # Interprocedural AST Taint Flow Engine
│   ├── malware_dissector.py # Shannon entropy, PE parsing & YARA-L
│   ├── pdf_generator.py     # Multi-page Code Scoring-style PDF generator
│   ├── reachability.py      # AST call-graph reachability engine
│   ├── remediation.py       # Autonomous safe patch refactor engine
│   ├── sbom.py              # CycloneDX 1.6, AI-BOM & Slopsquatting guard
│   └── vex.py               # OpenVEX v0.2.0 & CSAF 2.0 synthesizer
└── tests/
    ├── integration/         # API, supervisor, SBOM, and LSP server tests
    └── unit/                # Engine, permissions, taint, and tool unit tests
```

---

## 🚀 Getting Started

### 1. Prerequisites
- Python 3.12+
- Node.js (optional, for asset linting)

### 2. Environment Setup
```bash
git clone https://github.com/Aman9868/Argus-Security-Agents-.git
cd Argus-Security-Agents-
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Configure your environment variables:
```bash
cp .env.example .env
```
Supported API keys (deterministic offline fallbacks enabled by default):
- `GROQ_API_KEY`: Ultra-fast inference with Llama-3.3-70b
- `GEMINI_API_KEY`: Google Gemini Flash fallback
- `LANGCHAIN_API_KEY`: LangSmith tracing (`cyber-agent-prod`)
- Threat intel keys (optional): `ABUSEIPDB_API_KEY`, `VIRUSTOTAL_API_KEY`, `OTX_API_KEY`, `SHODAN_API_KEY`, `NVD_API_KEY`

### 3. Launch Platform
```bash
uvicorn apps.api.main:app --host 127.0.0.1 --port 8001 --reload
```
Navigate to **`http://127.0.0.1:8001`** in your browser.

### 4. Run Cyber LSP Daemon (Language Server Protocol)
Connect your IDE (VS Code, Cursor, Neovim) directly to the real-time taint analysis daemon:
```bash
python -m tools.lsp.server
```
Or run a standalone security scan on any file:
```bash
python -m tools.lsp.server --check apps/api/main.py
```

---

## 🧪 Test Verification

Run the full automated test suite (unit tests, integration tests, security guardrails):

```bash
pytest tests/ -v
```

```
======================= 95 passed, 32 warnings in 4.53s =======================
```

- `test_lsp_taint.py`: Interprocedural AST taint flow tracking, smart constant suppression, sanitizers, and TextEdit generation.
- `test_lsp_server.py`: JSON-RPC 2.0 stdio LSP 3.17 daemon lifecycle, hover docs, diagnostics, and codeActions.
- `test_sbom_agent.py`: AST call-graph reachability analysis, CycloneDX 1.6 cataloging, and OpenVEX justification synthesis.
- `test_sbom_endpoints.py`: Live Git project discovery, multi-page Code Scoring PDF generation, and unified patch remediation.
- `test_arena_engine.py`: Multi-stage APT duel simulation, scoring, and Sigma generation.
- `test_arena_endpoints.py`: Match replay, history retrieval, and persona catalog.
- `test_api_endpoints.py`: Health checks, guardrail prompt injection interception, and HITL approvals.
- `test_supervisor_cross_routing.py`: Dynamic cross-subgraph state transitions.
- `test_guardrails.py`: Protection against jailbreaks, prompt injection, and credential exfiltration.

---

## 📡 API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/health` | Service health and provider status |
| `POST` | `/api/investigation/run` | Triggers autonomous multi-agent investigation on target IOC |
| `GET` | `/api/investigation/{id}/graph` | Retrieves Cytoscape.js knowledge graph nodes and edges |
| `POST` | `/api/chat` | Analyst Copilot chat with Guardrails AI protection |
| `GET` | `/api/hitl/pending` | Lists staged containment actions awaiting human approval |
| `POST` | `/api/hitl/review` | Approves or rejects a staged containment action |
| `POST` | `/api/arena/simulate` | Executes Red vs. Blue Adversarial Arena duel |
| `GET` | `/api/arena/history` | Fetches history of past arena combat simulations |
| `GET` | `/api/arena/match/{id}` | Replays round-by-round duel telemetry and Sigma rules |
| `GET` | `/api/arena/personas` | Lists supported APT adversary personas and defensive postures |
| `GET` | `/api/deception/traps` | Lists active Chameleon honeytokens and trip status |
| `POST` | `/api/deception/deploy` | Deploys a new decoy honeytoken into the environment |
| `POST` | `/api/deception/trip` | Simulates an intruder probing an active honeytoken |
| `POST` | `/api/blast-radius/simulate` | Runs Monte Carlo lateral movement & chokepoint simulation |
| `POST` | `/api/malware/scan` | Static reverse engineering, Shannon entropy & YARA-L synthesis |
| `GET` | `/api/sbom/projects` | Discovers live Git repos in workspace (no mock data) |
| `POST` | `/api/sbom/scan` | CycloneDX 1.6, AST reachability triage & OpenVEX synthesis |
| `POST` | `/api/sbom/pdf` | Generates enterprise Code Scoring multi-page PDF audit report |
| `POST` | `/api/sbom/patch` | Generates unified `.patch` file for reachability-proven CVEs |
| `POST` | `/api/lsp/analyze` | Live AST taint flow analysis with QuickFix suggestions |
| `POST` | `/api/lsp/quick-fix` | Applies AST-verified TextEdits and validates taint resolution |
| `GET` | `/api/lsp/capabilities` | Returns LSP 3.17 server capabilities and IDE configuration snippets |

---

## 🔒 Security & Safe AI Practices

- **Strict Breach & Attack Simulation (BAS) Safety**: Red agent activities simulate telemetry signatures, log events, and network packets. No actual weaponized exploit binaries or harmful payload scripts are compiled or distributed.
- **SQL Injection Immunization**: All SQLite database interactions strictly use parameterized queries (`?`).
- **Least Privilege Enforcement**: Subgraph agents are constrained by explicit RBAC rules. Threat analysis agents cannot perform perimeter firewall changes without HITL authorization.
- **PII & RFC 1918 Masking**: Enterprise internal subnet ranges and secrets are masked prior to presenting data in UI components or external reports.

---

## 📄 License
Licensed under the [Apache License 2.0](LICENSE).
