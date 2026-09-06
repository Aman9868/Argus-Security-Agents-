"""Database persistence module for cyber-agent using SQLite.

Manages persistent storage for:
- Security investigations
- Human-in-the-loop containment approvals (Quarantine records)
- Enriched IOC Threat Intelligence Dossiers
"""

import os
import json
import sqlite3
import time
from typing import Dict, Any, List, Optional
import structlog

logger = structlog.get_logger(__name__)

DB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
DB_PATH = os.path.join(DB_DIR, "cyber_agent.db")


def get_db_connection() -> sqlite3.Connection:
    """Returns a SQLite connection with row factory configured."""
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initializes SQLite schema and seeds default intelligence records."""
    os.makedirs(DB_DIR, exist_ok=True)
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        # 1. Investigations Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS investigations (
                id TEXT PRIMARY KEY,
                seed_ioc TEXT NOT NULL,
                ioc_type TEXT,
                verdict TEXT,
                confidence_score REAL,
                analyst_summary TEXT,
                total_entities INTEGER DEFAULT 0,
                total_links INTEGER DEFAULT 0,
                mitre_attck TEXT,
                d3fend_countermeasures TEXT,
                sigma_rule TEXT,
                yara_rule TEXT,
                stix_bundle TEXT,
                knowledge_graph_json TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # 2. Containment Records Table (HITL Approvals)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS containment_records (
                id TEXT PRIMARY KEY,
                task_id TEXT,
                investigation_id TEXT,
                target TEXT NOT NULL,
                action_type TEXT NOT NULL,
                status TEXT NOT NULL,
                firewall_rule TEXT,
                enforcement_details TEXT,
                analyst_notes TEXT,
                approved_by TEXT DEFAULT 'SOC_ANALYST',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # 3. IOC Intelligence Dossiers Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ioc_intelligence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ioc TEXT UNIQUE NOT NULL,
                ioc_type TEXT NOT NULL,
                threat_score INTEGER DEFAULT 0,
                threat_level TEXT DEFAULT 'UNKNOWN',
                attribution TEXT,
                country TEXT,
                country_code TEXT,
                city TEXT,
                asn TEXT,
                org TEXT,
                registrar TEXT,
                registration_date TEXT,
                is_nrd INTEGER DEFAULT 0,
                open_ports TEXT,
                c2_status TEXT,
                malware_families TEXT,
                virustotal_ratio TEXT,
                alienvault_pulses INTEGER DEFAULT 0,
                raw_dossier TEXT,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # 4. Generative Chameleon Deception Traps Table (Honeytokens & Decoy Sinks)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS deception_traps (
                id TEXT PRIMARY KEY,
                trap_type TEXT NOT NULL,
                trap_name TEXT NOT NULL,
                trap_value TEXT NOT NULL,
                lure_context TEXT,
                target_ioc TEXT,
                status TEXT DEFAULT 'ARMED',
                tripped_count INTEGER DEFAULT 0,
                last_tripped_at TIMESTAMP,
                tripped_ip TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # 5. GraphRAG Multi-Hop Threat Hunt Hops Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS threat_hunt_hops (
                hunt_id TEXT PRIMARY KEY,
                root_ioc TEXT NOT NULL,
                hop_depth INTEGER DEFAULT 3,
                nodes_discovered INTEGER DEFAULT 0,
                edges_discovered INTEGER DEFAULT 0,
                evidence_chain_json TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # 6. Autonomous Adversarial Arena Simulations Table (Red vs. Blue Self-Play)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS arena_simulations (
                match_id TEXT PRIMARY KEY,
                adversary_persona TEXT NOT NULL,
                defense_posture TEXT NOT NULL,
                rounds_count INTEGER DEFAULT 3,
                detection_rate REAL DEFAULT 0.0,
                avg_ttd_ms INTEGER DEFAULT 0,
                red_score INTEGER DEFAULT 0,
                blue_score INTEGER DEFAULT 0,
                rounds_json TEXT NOT NULL,
                sigma_rules_json TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # 7. Autonomous Attack Path & Blast Radius Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS attack_path_simulations (
                simulation_id TEXT PRIMARY KEY,
                root_ioc TEXT NOT NULL,
                compromised_node TEXT NOT NULL,
                crown_jewels_at_risk INTEGER DEFAULT 0,
                mean_time_to_breach_min INTEGER DEFAULT 0,
                chokepoints_json TEXT NOT NULL,
                paths_json TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # 8. Autonomous Payload & Binary Dissections Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS payload_dissections (
                analysis_id TEXT PRIMARY KEY,
                sample_name TEXT NOT NULL,
                file_hash TEXT NOT NULL,
                file_type TEXT DEFAULT 'PE_EXE',
                entropy_score REAL DEFAULT 0.0,
                is_packed INTEGER DEFAULT 0,
                suspicious_apis_json TEXT NOT NULL,
                extracted_iocs_json TEXT NOT NULL,
                yara_rule TEXT NOT NULL,
                execution_flow_json TEXT NOT NULL,
                verdict TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        try:
            cursor.execute("ALTER TABLE payload_dissections ADD COLUMN verdict TEXT")
        except sqlite3.OperationalError:
            pass

        # 9. Quishing & Advanced Phishing Investigations Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS phishing_investigations (
                analysis_id TEXT PRIMARY KEY,
                sample_id TEXT NOT NULL,
                subject TEXT NOT NULL,
                sender TEXT NOT NULL,
                recipient TEXT NOT NULL,
                sender_ip TEXT,
                has_qr_code INTEGER DEFAULT 0,
                qr_decoded_url TEXT,
                final_destination_url TEXT,
                risk_score INTEGER DEFAULT 0,
                verdict TEXT NOT NULL,
                headers_json TEXT NOT NULL,
                landing_page_json TEXT NOT NULL,
                remediation_json TEXT NOT NULL,
                affected_mailboxes_estimate INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        conn.commit()

        # Seed initial intelligence if table is empty
        cursor.execute("SELECT COUNT(*) as cnt FROM ioc_intelligence")
        count = cursor.fetchone()["cnt"]
        if count == 0:
            seed_initial_intelligence(conn)


def seed_initial_intelligence(conn: sqlite3.Connection):
    """Seeds baseline realistic threat intelligence for demo and standard testing."""
    cursor = conn.cursor()
    
    # Target 1: 185.220.101.45 (C2 IP)
    ports_185 = [
        {"port": 80, "service": "HTTP", "state": "OPEN", "banner": "nginx/1.18.0 (Ubuntu)", "c2_risk": "MEDIUM"},
        {"port": 443, "service": "HTTPS", "state": "OPEN", "banner": "TLSv1.3 / Cobalt Strike Beacon Listener", "c2_risk": "HIGH"},
        {"port": 8080, "service": "HTTP-PROXY", "state": "OPEN", "banner": "AsyncRAT Stager Webhook", "c2_risk": "CRITICAL"},
        {"port": 9001, "service": "TOR-ORPORT", "state": "FILTERED", "banner": "Tor Relay Service", "c2_risk": "HIGH"}
    ]
    malware_185 = ["Cobalt Strike", "AsyncRAT", "Sliver C2", "RedLine Stealer"]
    raw_185 = {
        "ioc": "185.220.101.45",
        "category": "Command & Control / Tor Gateway",
        "description": "Bulletproof Tor Exit Node and active Cobalt Strike Beacon listener hosted in Frankfurt, Germany.",
        "whois": {"registrar": "NameCheap, Inc.", "asn": "AS60729", "org": "Stiftung Erneuerbare Freiheit"},
        "dns": {"ptr": "tor-exit-45.erneuerbare-freiheit.de", "domains": ["update-microsoft-s.net", "telemetry-sync-edge.com"]}
    }

    cursor.execute("""
        INSERT INTO ioc_intelligence (
            ioc, ioc_type, threat_score, threat_level, attribution, country, country_code,
            city, asn, org, registrar, open_ports, c2_status, malware_families,
            virustotal_ratio, alienvault_pulses, raw_dossier
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        "185.220.101.45", "IP", 92, "CRITICAL", "UNC1151 / Storm-0558 Affiliate",
        "Germany", "DE", "Frankfurt am Main", "AS60729 Stiftung Erneuerbare Freiheit",
        "Stiftung Erneuerbare Freiheit", "NameCheap, Inc.", json.dumps(ports_185),
        "ACTIVE_C2_LISTENER", json.dumps(malware_185), "58 / 72 Security Vendors (Malicious)",
        14, json.dumps(raw_185)
    ))

    # Target 2: update-microsoft-s.net (Domain)
    raw_domain = {
        "ioc": "update-microsoft-s.net",
        "category": "Typosquat / Spearphishing Landing Page",
        "description": "Deceptive lookalike domain mimicking legitimate Microsoft Windows Update telemetry endpoints.",
        "registrar_info": {"registrar": "NameCheap, Inc.", "created": "2026-09-01", "expires": "2027-09-01", "nameservers": ["dns1.registrar-servers.com"]}
    }
    cursor.execute("""
        INSERT INTO ioc_intelligence (
            ioc, ioc_type, threat_score, threat_level, attribution, country, country_code,
            city, asn, org, registrar, registration_date, is_nrd, open_ports, c2_status,
            malware_families, virustotal_ratio, alienvault_pulses, raw_dossier
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        "update-microsoft-s.net", "DOMAIN", 88, "HIGH", "Lazarus Group / APT38 Mimic",
        "Germany", "DE", "Frankfurt am Main", "AS60729 Stiftung Erneuerbare Freiheit",
        "NameCheap Privacy Protect", "NameCheap, Inc.", "2026-09-01", 1,
        json.dumps([{"port": 443, "service": "HTTPS", "state": "OPEN"}]),
        "HOSTING_MALICIOUS_PAYLOAD", json.dumps(["AgentTesla", "FormBook"]),
        "46 / 70 Security Vendors (Malicious)", 9, json.dumps(raw_domain)
    ))

    # Initial Sample Investigation
    initial_inv_id = "INV-2026-0941"
    cursor.execute("""
        INSERT OR IGNORE INTO investigations (
            id, seed_ioc, ioc_type, verdict, confidence_score, analyst_summary,
            total_entities, total_links, mitre_attck, d3fend_countermeasures,
            created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now', '-2 hours'))
    """, (
        initial_inv_id, "185.220.101.45", "IP", "MALICIOUS", 0.90,
        "Automated multi-agent investigation confirmed 185.220.101.45 as an active Cobalt Strike C2 node operating through bulletproof German ASN 60729 with associated newly registered lookalike domains.",
        10, 7, json.dumps(["T1071.001", "T1583.001", "T1566.002"]),
        json.dumps(["D3-NPA", "D3-OTF", "D3-SINK", "D3-DNSR"])
    ))

    conn.commit()


# ==============================================================================
# INVESTIGATION STORAGE METHODS
# ==============================================================================

def save_investigation_to_db(inv_id: str, seed_ioc: str, ioc_type: str, verdict: str,
                             confidence_score: float, analyst_summary: str,
                             total_entities: int, total_links: int,
                             mitre_attck: List[str], d3fend: List[str],
                             sigma_rule: Optional[str] = None, yara_rule: Optional[str] = None,
                             stix_bundle: Optional[Dict[str, Any]] = None,
                             kg_json: Optional[Dict[str, Any]] = None) -> bool:
    """Inserts or replaces an investigation record into the database."""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO investigations (
                    id, seed_ioc, ioc_type, verdict, confidence_score, analyst_summary,
                    total_entities, total_links, mitre_attck, d3fend_countermeasures,
                    sigma_rule, yara_rule, stix_bundle, knowledge_graph_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """, (
                inv_id, seed_ioc, ioc_type, verdict, confidence_score, analyst_summary,
                total_entities, total_links,
                json.dumps(mitre_attck or []),
                json.dumps(d3fend or []),
                sigma_rule, yara_rule,
                json.dumps(stix_bundle) if stix_bundle else None,
                json.dumps(kg_json) if kg_json else None
            ))
            conn.commit()
            return True
    except Exception as e:
        logger.error("Failed to save investigation to DB", error=str(e), inv_id=inv_id)
        return False


def get_all_investigations(limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieves all investigation records ordered by timestamp."""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, seed_ioc, ioc_type, verdict, confidence_score, analyst_summary,
                       total_entities, total_links, mitre_attck, d3fend_countermeasures,
                       created_at
                FROM investigations
                ORDER BY created_at DESC
                LIMIT ?
            """, (limit,))
            rows = cursor.fetchall()
            results = []
            for r in rows:
                results.append({
                    "id": r["id"],
                    "seed_ioc": r["seed_ioc"],
                    "ioc_type": r["ioc_type"],
                    "verdict": r["verdict"],
                    "confidence_score": r["confidence_score"],
                    "analyst_summary": r["analyst_summary"],
                    "total_entities": r["total_entities"],
                    "total_links": r["total_links"],
                    "mitre_attck": json.loads(r["mitre_attck"] or "[]"),
                    "d3fend_countermeasures": json.loads(r["d3fend_countermeasures"] or "[]"),
                    "created_at": r["created_at"]
                })
            return results
    except Exception as e:
        logger.error("Failed to list investigations", error=str(e))
        return []


def get_investigation_by_id(inv_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves full investigation including rules, STIX bundle, and knowledge graph."""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM investigations WHERE id = ?", (inv_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return {
                "id": row["id"],
                "seed_ioc": row["seed_ioc"],
                "ioc_type": row["ioc_type"],
                "verdict": row["verdict"],
                "confidence_score": row["confidence_score"],
                "analyst_summary": row["analyst_summary"],
                "total_entities": row["total_entities"],
                "total_links": row["total_links"],
                "mitre_attck": json.loads(row["mitre_attck"] or "[]"),
                "d3fend_countermeasures": json.loads(row["d3fend_countermeasures"] or "[]"),
                "sigma_rule": row["sigma_rule"],
                "yara_rule": row["yara_rule"],
                "stix_bundle": json.loads(row["stix_bundle"]) if row["stix_bundle"] else None,
                "knowledge_graph": json.loads(row["knowledge_graph_json"]) if row["knowledge_graph_json"] else None,
                "created_at": row["created_at"]
            }
    except Exception as e:
        logger.error("Failed to fetch investigation", inv_id=inv_id, error=str(e))
        return None


# ==============================================================================
# CONTAINMENT / QUARANTINE STORAGE METHODS (HITL PERSISTENCE)
# ==============================================================================

def save_containment_action(task_id: str, target: str, action_type: str, status: str,
                            firewall_rule: str, enforcement_details: Dict[str, Any],
                            investigation_id: Optional[str] = None,
                            analyst_notes: Optional[str] = None) -> str:
    """Saves an enforced containment action (Quarantine) to SQLite."""
    record_id = f"CONT-{int(time.time())}"
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO containment_records (
                    id, task_id, investigation_id, target, action_type, status,
                    firewall_rule, enforcement_details, analyst_notes, approved_by,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'SOC_ANALYST', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            """, (
                record_id, task_id, investigation_id, target, action_type, status,
                firewall_rule, json.dumps(enforcement_details or {}),
                analyst_notes or "Perimeter isolation approved via Analyst Dashboard."
            ))
            conn.commit()
            logger.info("Containment record saved to DB", record_id=record_id, target=target, status=status)
            return record_id
    except Exception as e:
        logger.error("Failed to save containment record", error=str(e), target=target)
        return record_id


def get_all_containment_records(limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieves all quarantined entities and containment records."""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM containment_records
                ORDER BY created_at DESC
                LIMIT ?
            """, (limit,))
            rows = cursor.fetchall()
            results = []
            for r in rows:
                results.append({
                    "id": r["id"],
                    "task_id": r["task_id"],
                    "investigation_id": r["investigation_id"],
                    "target": r["target"],
                    "action_type": r["action_type"],
                    "status": r["status"],
                    "firewall_rule": r["firewall_rule"],
                    "enforcement_details": json.loads(r["enforcement_details"] or "{}"),
                    "analyst_notes": r["analyst_notes"],
                    "approved_by": r["approved_by"],
                    "created_at": r["created_at"],
                    "updated_at": r["updated_at"]
                })
            return results
    except Exception as e:
        logger.error("Failed to list containment records", error=str(e))
        return []


def get_active_containment_for_target(target: str) -> Optional[Dict[str, Any]]:
    """Checks if a target is actively quarantined in the database."""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM containment_records
                WHERE target = ? AND status IN ('APPROVED_AND_EXECUTED', 'APPLIED', 'ACTIVE')
                ORDER BY created_at DESC
                LIMIT 1
            """, (target,))
            row = cursor.fetchone()
            if not row:
                return None
            return {
                "id": row["id"],
                "target": row["target"],
                "action_type": row["action_type"],
                "status": row["status"],
                "firewall_rule": row["firewall_rule"],
                "enforcement_details": json.loads(row["enforcement_details"] or "{}"),
                "created_at": row["created_at"]
            }
    except Exception as e:
        logger.error("Failed to check active containment", target=target, error=str(e))
        return None


def revoke_containment_action(record_id: str) -> bool:
    """Revokes a quarantine and marks rule as WITHDRAWN in DB."""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE containment_records
                SET status = 'REVOKED', updated_at = CURRENT_TIMESTAMP
                WHERE id = ? OR target = ?
            """, (record_id, record_id))
            conn.commit()
            return True
    except Exception as e:
        logger.error("Failed to revoke containment", record_id=record_id, error=str(e))
        return False


# ==============================================================================
# IOC INTELLIGENCE DOSSIER METHODS
# ==============================================================================

def get_ioc_dossier_from_db(ioc: str) -> Optional[Dict[str, Any]]:
    """Fetches high-fidelity threat intelligence dossier from SQLite."""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM ioc_intelligence WHERE ioc = ?", (ioc,))
            row = cursor.fetchone()
            if not row:
                return None
            return {
                "ioc": row["ioc"],
                "ioc_type": row["ioc_type"],
                "threat_score": row["threat_score"],
                "threat_level": row["threat_level"],
                "attribution": row["attribution"],
                "country": row["country"],
                "country_code": row["country_code"],
                "city": row["city"],
                "asn": row["asn"],
                "org": row["org"],
                "registrar": row["registrar"],
                "registration_date": row["registration_date"],
                "is_nrd": bool(row["is_nrd"]),
                "open_ports": json.loads(row["open_ports"] or "[]"),
                "c2_status": row["c2_status"],
                "malware_families": json.loads(row["malware_families"] or "[]"),
                "virustotal_ratio": row["virustotal_ratio"],
                "alienvault_pulses": row["alienvault_pulses"],
                "raw_dossier": json.loads(row["raw_dossier"] or "{}"),
                "last_seen": row["last_seen"]
            }
    except Exception as e:
        logger.error("Failed to fetch IOC dossier", ioc=ioc, error=str(e))
        return None


# ==============================================================================
# GENERATIVE CHAMELEON DECEPTION STORAGE METHODS
# ==============================================================================

def save_deception_trap(trap_id: str, trap_type: str, trap_name: str, trap_value: str,
                        lure_context: str, target_ioc: Optional[str] = None) -> bool:
    """Inserts a new active honeytoken/decoy lure into the database."""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO deception_traps (
                    id, trap_type, trap_name, trap_value, lure_context, target_ioc, status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, 'ARMED', CURRENT_TIMESTAMP)
            """, (trap_id, trap_type, trap_name, trap_value, lure_context, target_ioc))
            conn.commit()
            logger.info("Deception trap deployed", trap_id=trap_id, trap_type=trap_type)
            return True
    except Exception as e:
        logger.error("Failed to save deception trap", trap_id=trap_id, error=str(e))
        return False


def get_all_deception_traps(limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieves all active and historical deception lures."""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, trap_type, trap_name, trap_value, lure_context, target_ioc,
                       status, tripped_count, last_tripped_at, tripped_ip, created_at
                FROM deception_traps
                ORDER BY created_at DESC
                LIMIT ?
            """, (limit,))
            rows = cursor.fetchall()
            return [dict(r) for r in rows]
    except Exception as e:
        logger.error("Failed to fetch deception traps", error=str(e))
        return []


def trip_deception_trap(trap_id: str, intruder_ip: str) -> Optional[Dict[str, Any]]:
    """Records an attacker tripping a honeytoken lure, updating counter and timestamp."""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE deception_traps
                SET status = 'TRIPPED',
                    tripped_count = tripped_count + 1,
                    last_tripped_at = CURRENT_TIMESTAMP,
                    tripped_ip = ?
                WHERE id = ?
            """, (intruder_ip, trap_id))
            conn.commit()

            cursor.execute("SELECT * FROM deception_traps WHERE id = ?", (trap_id,))
            row = cursor.fetchone()
            if row:
                logger.warning("ALERT: Deception trap tripped by adversary!", trap_id=trap_id, ip=intruder_ip)
                return dict(row)
            return None
    except Exception as e:
        logger.error("Failed to trip deception trap", trap_id=trap_id, error=str(e))
        return None


def revoke_deception_trap(trap_id: str) -> bool:
    """Disarms a deception lure."""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE deception_traps SET status = 'REVOKED' WHERE id = ?", (trap_id,))
            conn.commit()
            return True
    except Exception as e:
        logger.error("Failed to revoke deception trap", trap_id=trap_id, error=str(e))
        return False


# ==============================================================================
# GRAPHRAG THREAT HUNT HOPS STORAGE METHODS
# ==============================================================================

def save_threat_hunt_hop(hunt_id: str, root_ioc: str, hop_depth: int,
                         nodes_discovered: int, edges_discovered: int,
                         evidence_chain: List[Dict[str, Any]]) -> bool:
    """Saves a multi-hop GraphRAG threat hunting exploration record."""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO threat_hunt_hops (
                    hunt_id, root_ioc, hop_depth, nodes_discovered, edges_discovered,
                    evidence_chain_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """, (hunt_id, root_ioc, hop_depth, nodes_discovered, edges_discovered, json.dumps(evidence_chain)))
            conn.commit()
            return True
    except Exception as e:
        logger.error("Failed to save threat hunt hop", hunt_id=hunt_id, error=str(e))
        return False


def get_all_threat_hunts(limit: int = 20) -> List[Dict[str, Any]]:
    """Retrieves previous GraphRAG threat hunting sessions."""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT hunt_id, root_ioc, hop_depth, nodes_discovered, edges_discovered,
                       evidence_chain_json, created_at
                FROM threat_hunt_hops
                ORDER BY created_at DESC
                LIMIT ?
            """, (limit,))
            rows = cursor.fetchall()
            results = []
            for r in rows:
                results.append({
                    "hunt_id": r["hunt_id"],
                    "root_ioc": r["root_ioc"],
                    "hop_depth": r["hop_depth"],
                    "nodes_discovered": r["nodes_discovered"],
                    "edges_discovered": r["edges_discovered"],
                    "evidence_chain": json.loads(r["evidence_chain_json"] or "[]"),
                    "created_at": r["created_at"]
                })
            return results
    except Exception as e:
        logger.error("Failed to fetch threat hunts", error=str(e))
        return []


# ==============================================================================
# AUTONOMOUS ADVERSARIAL ARENA STORAGE METHODS (RED VS. BLUE)
# ==============================================================================

def save_arena_simulation(match_data: Dict[str, Any]) -> bool:
    """Inserts a completed adversarial arena match record into SQLite."""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO arena_simulations (
                    match_id, adversary_persona, defense_posture, rounds_count,
                    detection_rate, avg_ttd_ms, red_score, blue_score,
                    rounds_json, sigma_rules_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """, (
                match_data["match_id"],
                match_data["adversary_persona"],
                match_data["defense_posture"],
                match_data.get("rounds_count", 3),
                match_data.get("detection_rate", 0.0),
                match_data.get("avg_ttd_ms", 0),
                match_data.get("red_score", 0),
                match_data.get("blue_score", 0),
                json.dumps(match_data.get("rounds", [])),
                json.dumps(match_data.get("sigma_rules", []))
            ))
            conn.commit()
            logger.info("Adversarial arena match saved", match_id=match_data["match_id"])
            return True
    except Exception as e:
        logger.error("Failed to save arena simulation", match_id=match_data.get("match_id"), error=str(e))
        return False


def get_all_arena_simulations(limit: int = 20) -> List[Dict[str, Any]]:
    """Retrieves past adversarial duel records from SQLite."""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT match_id, adversary_persona, defense_posture, rounds_count,
                       detection_rate, avg_ttd_ms, red_score, blue_score,
                       rounds_json, sigma_rules_json, created_at
                FROM arena_simulations
                ORDER BY created_at DESC
                LIMIT ?
            """, (limit,))
            rows = cursor.fetchall()
            results = []
            for r in rows:
                results.append({
                    "match_id": r["match_id"],
                    "adversary_persona": r["adversary_persona"],
                    "defense_posture": r["defense_posture"],
                    "rounds_count": r["rounds_count"],
                    "detection_rate": r["detection_rate"],
                    "avg_ttd_ms": r["avg_ttd_ms"],
                    "red_score": r["red_score"],
                    "blue_score": r["blue_score"],
                    "rounds": json.loads(r["rounds_json"] or "[]"),
                    "sigma_rules": json.loads(r["sigma_rules_json"] or "[]"),
                    "created_at": r["created_at"]
                })
            return results
    except Exception as e:
        logger.error("Failed to fetch arena simulations", error=str(e))
        return []


def get_arena_simulation_by_id(match_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves detailed round telemetry and rules for a specific duel."""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM arena_simulations WHERE match_id = ?", (match_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return {
                "match_id": row["match_id"],
                "adversary_persona": row["adversary_persona"],
                "defense_posture": row["defense_posture"],
                "rounds_count": row["rounds_count"],
                "detection_rate": row["detection_rate"],
                "avg_ttd_ms": row["avg_ttd_ms"],
                "red_score": row["red_score"],
                "blue_score": row["blue_score"],
                "rounds": json.loads(row["rounds_json"] or "[]"),
                "sigma_rules": json.loads(row["sigma_rules_json"] or "[]"),
                "created_at": row["created_at"]
            }
    except Exception as e:
        logger.error("Failed to fetch arena simulation by ID", match_id=match_id, error=str(e))
        return None


# ==============================================================================
# ATTACK PATH & BLAST RADIUS STORAGE METHODS
# ==============================================================================
# ATTACK PATH & BLAST RADIUS STORAGE METHODS
# ==============================================================================

def save_attack_path_simulation(data: Dict[str, Any]) -> bool:
    """Saves an attack path and blast radius simulation to SQLite."""
    try:
        sim_id = data.get("simulation_id") or f"SIM-{secrets.token_hex(4)}"
        root_ioc = data.get("root_ioc") or data.get("compromised_origin") or "185.220.101.45"
        compromised_node = data.get("compromised_node") or data.get("compromised_origin") or "WS-CORP-402"
        jewels = data.get("crown_jewels_at_risk")
        crown_jewels_count = len(jewels) if isinstance(jewels, list) else (jewels or 0)
        mttb = data.get("mean_time_to_breach_min") or data.get("mttb_minutes") or 18
        chokepoints = data.get("chokepoints") or data.get("chokepoint_defenses") or []
        paths = data.get("paths") or data.get("critical_attack_paths") or []

        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO attack_path_simulations (
                    simulation_id, root_ioc, compromised_node, crown_jewels_at_risk,
                    mean_time_to_breach_min, chokepoints_json, paths_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """, (
                sim_id,
                root_ioc,
                compromised_node,
                crown_jewels_count,
                mttb,
                json.dumps(chokepoints),
                json.dumps(paths)
            ))
            conn.commit()
            return True
    except Exception as e:
        logger.error("Failed to save attack path simulation", error=str(e))
        return False


def get_attack_path_simulation(simulation_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves an attack path simulation record by ID."""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM attack_path_simulations WHERE simulation_id = ?", (simulation_id,))
            row = cursor.fetchone()
            if not row:
                return None
            chokepoints = json.loads(row["chokepoints_json"] or "[]")
            paths = json.loads(row["paths_json"] or "[]")
            return {
                "simulation_id": row["simulation_id"],
                "root_ioc": row["root_ioc"],
                "compromised_origin": row["root_ioc"],
                "compromised_node": row["compromised_node"],
                "crown_jewels_at_risk": row["crown_jewels_at_risk"],
                "mean_time_to_breach_min": row["mean_time_to_breach_min"],
                "mttb_minutes": row["mean_time_to_breach_min"],
                "chokepoints": chokepoints,
                "chokepoint_defenses": chokepoints,
                "paths": paths,
                "critical_attack_paths": paths,
                "created_at": row["created_at"]
            }
    except Exception as e:
        logger.error("Failed to fetch attack path simulation", error=str(e))
        return None


# ==============================================================================
# PAYLOAD & BINARY DISSECTION STORAGE METHODS
# ==============================================================================

def save_payload_dissection(data: Dict[str, Any]) -> bool:
    """Saves static reverse engineering dissection report to SQLite."""
    try:
        analysis_id = data.get("analysis_id") or data.get("sha256") or data.get("sample_id") or secrets.token_hex(8)
        sample_name = data.get("sample_name") or data.get("file_name") or data.get("sample_id") or "sample.bin"
        file_hash = data.get("file_hash") or data.get("sha256") or data.get("md5") or analysis_id
        file_type = data.get("file_type") or "PE_EXE"
        entropy = data.get("entropy_score") if "entropy_score" in data else data.get("overall_entropy", 0.0)
        is_packed = 1 if (data.get("is_packed") or entropy > 7.0) else 0
        apis = data.get("suspicious_apis") or data.get("suspicious_imports") or []
        iocs = data.get("extracted_iocs") or data.get("obfuscated_strings") or []
        yara = data.get("yara_rule") or data.get("yara_l_rule") or ""
        flow = data.get("execution_flow") or data.get("sections") or data.get("recommendations") or []
        verdict = data.get("verdict") or ("CRITICAL" if entropy > 7.0 else "MALICIOUS")

        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO payload_dissections (
                    analysis_id, sample_name, file_hash, file_type, entropy_score,
                    is_packed, suspicious_apis_json, extracted_iocs_json, yara_rule,
                    execution_flow_json, verdict, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """, (
                analysis_id,
                sample_name,
                file_hash,
                file_type,
                entropy,
                is_packed,
                json.dumps(apis),
                json.dumps(iocs),
                yara,
                json.dumps(flow),
                verdict
            ))
            conn.commit()
            return True
    except Exception as e:
        logger.error("Failed to save payload dissection", error=str(e))
        return False


def get_payload_dissection(identifier: str) -> Optional[Dict[str, Any]]:
    """Retrieves dissection report by analysis ID or file hash."""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM payload_dissections WHERE analysis_id = ? OR file_hash = ?", (identifier, identifier))
            row = cursor.fetchone()
            if not row:
                return None
            apis = json.loads(row["suspicious_apis_json"] or "[]")
            iocs = json.loads(row["extracted_iocs_json"] or "[]")
            flow = json.loads(row["execution_flow_json"] or "[]")
            verdict_val = row["verdict"] if ("verdict" in row.keys() and row["verdict"]) else ("CRITICAL" if row["entropy_score"] > 7.0 else "MALICIOUS")
            return {
                "analysis_id": row["analysis_id"],
                "sample_name": row["sample_name"],
                "file_name": row["sample_name"],
                "file_hash": row["file_hash"],
                "sha256": row["file_hash"],
                "file_type": row["file_type"],
                "entropy_score": row["entropy_score"],
                "overall_entropy": row["entropy_score"],
                "is_packed": bool(row["is_packed"]),
                "suspicious_apis": apis,
                "suspicious_imports": apis,
                "extracted_iocs": iocs,
                "obfuscated_strings": iocs,
                "yara_rule": row["yara_rule"],
                "yara_l_rule": row["yara_rule"],
                "execution_flow": flow,
                "sections": flow,
                "verdict": verdict_val,
                "created_at": row["created_at"]
            }
    except Exception as e:
        logger.error("Failed to fetch payload dissection", error=str(e))
        return None


def get_all_payload_dissections(limit: int = 20) -> List[Dict[str, Any]]:
    """Lists recent payload dissection reports."""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT analysis_id, sample_name, file_hash, file_type, entropy_score,
                       is_packed, suspicious_apis_json, extracted_iocs_json, yara_rule,
                       execution_flow_json, verdict, created_at
                FROM payload_dissections
                ORDER BY created_at DESC
                LIMIT ?
            """, (limit,))
            rows = cursor.fetchall()
            results = []
            for r in rows:
                verdict_val = r["verdict"] if ("verdict" in r.keys() and r["verdict"]) else ("CRITICAL" if r["entropy_score"] > 7.0 else "MALICIOUS")
                results.append({
                    "analysis_id": r["analysis_id"],
                    "sample_name": r["sample_name"],
                    "file_name": r["sample_name"],
                    "file_hash": r["file_hash"],
                    "sha256": r["file_hash"],
                    "file_type": r["file_type"],
                    "entropy_score": r["entropy_score"],
                    "overall_entropy": r["entropy_score"],
                    "is_packed": bool(r["is_packed"]),
                    "verdict": verdict_val,
                    "created_at": r["created_at"]
                })
            return results
    except Exception as e:
        logger.error("Failed to fetch all payload dissections", error=str(e))
        return []


# ==============================================================================
# QUISHING & PHISHING INVESTIGATION STORAGE METHODS
# ==============================================================================

def save_phishing_investigation(data: Dict[str, Any]) -> bool:
    """Persists a Quishing or email phishing forensic analysis record to SQLite."""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO phishing_investigations (
                    analysis_id, sample_id, subject, sender, recipient, sender_ip,
                    has_qr_code, qr_decoded_url, final_destination_url, risk_score,
                    verdict, headers_json, landing_page_json, remediation_json,
                    affected_mailboxes_estimate, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """, (
                data["analysis_id"],
                data.get("sample_id", "custom_email"),
                data.get("subject", "Unknown Subject"),
                data.get("sender", "Unknown Sender"),
                data.get("recipient", "Unknown Recipient"),
                data.get("sender_ip", ""),
                1 if data.get("has_qr_code") else 0,
                data.get("qr_data", {}).get("raw_encoded_payload") if data.get("qr_data") else None,
                data.get("final_destination_url", ""),
                data.get("risk_score", 0),
                data.get("verdict", "SUSPICIOUS"),
                json.dumps(data.get("headers", {})),
                json.dumps(data.get("landing_page_analysis", {})),
                json.dumps(data.get("remediation_playbook", [])),
                data.get("affected_mailboxes_estimate", 0)
            ))
            conn.commit()
            return True
    except Exception as e:
        logger.error("Failed to save phishing investigation", error=str(e))
        return False


def get_phishing_investigation(analysis_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves specific phishing investigation report by analysis ID."""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM phishing_investigations WHERE analysis_id = ?", (analysis_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return {
                "analysis_id": row["analysis_id"],
                "sample_id": row["sample_id"],
                "subject": row["subject"],
                "sender": row["sender"],
                "recipient": row["recipient"],
                "sender_ip": row["sender_ip"],
                "has_qr_code": bool(row["has_qr_code"]),
                "qr_decoded_url": row["qr_decoded_url"],
                "final_destination_url": row["final_destination_url"],
                "risk_score": row["risk_score"],
                "verdict": row["verdict"],
                "headers": json.loads(row["headers_json"] or "{}"),
                "landing_page_analysis": json.loads(row["landing_page_json"] or "{}"),
                "remediation_playbook": json.loads(row["remediation_json"] or "[]"),
                "affected_mailboxes_estimate": row["affected_mailboxes_estimate"],
                "created_at": row["created_at"]
            }
    except Exception as e:
        logger.error("Failed to fetch phishing investigation", analysis_id=analysis_id, error=str(e))
        return None


def get_all_phishing_investigations(limit: int = 20) -> List[Dict[str, Any]]:
    """Lists recent phishing and quishing triage investigations."""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT analysis_id, sample_id, subject, sender, recipient, has_qr_code,
                       risk_score, verdict, affected_mailboxes_estimate, created_at
                FROM phishing_investigations
                ORDER BY created_at DESC
                LIMIT ?
            """, (limit,))
            rows = cursor.fetchall()
            results = []
            for r in rows:
                results.append({
                    "analysis_id": r["analysis_id"],
                    "sample_id": r["sample_id"],
                    "subject": r["subject"],
                    "sender": r["sender"],
                    "recipient": r["recipient"],
                    "has_qr_code": bool(r["has_qr_code"]),
                    "risk_score": r["risk_score"],
                    "verdict": r["verdict"],
                    "affected_mailboxes_estimate": r["affected_mailboxes_estimate"],
                    "created_at": r["created_at"]
                })
            return results
    except Exception as e:
        logger.error("Failed to fetch all phishing investigations", error=str(e))
        return []


# Initialize DB automatically when imported
init_db()

