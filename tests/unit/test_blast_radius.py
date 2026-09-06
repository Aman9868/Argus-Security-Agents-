"""Unit tests for Autonomous Attack Path & Blast Radius Engine."""

import pytest
from tools.blast_radius import AttackPathPredictor, ENTERPRISE_TOPOLOGY
from storage.db import save_attack_path_simulation, get_attack_path_simulation

def test_enterprise_topology_structure():
    """Verify internal enterprise network and IAM topology is properly modeled."""
    topo = AttackPathPredictor.get_internal_topology()
    assert "nodes" in topo
    assert "edges" in topo
    assert len(topo["nodes"]) >= 7
    assert len(topo["edges"]) >= 8

    node_names = [n["name"] for n in topo["nodes"]]
    assert "DC-CORP-01" in node_names
    assert "SQL-PCI-PROD-01" in node_names
    assert "Role/DevOps-Admin" in node_names

def test_attack_path_simulation_execution():
    """Verify Monte Carlo attack path simulation computes probability, MTTB, and chokepoints."""
    result = AttackPathPredictor.simulate_lateral_movement(
        start_ioc_or_host="185.220.101.45",
        iterations=300
    )

    assert "simulation_id" in result
    assert result["compromised_origin"] == "185.220.101.45"
    assert 0.0 <= result["compromise_probability"] <= 1.0
    assert result["mttb_minutes"] > 0
    assert isinstance(result["critical_attack_paths"], list)
    assert len(result["critical_attack_paths"]) >= 1

    # Check crown jewels at risk
    assert isinstance(result["crown_jewels_at_risk"], list)
    jewel_names = [j["node"] for j in result["crown_jewels_at_risk"]]
    assert "SQL-PCI-PROD-01" in jewel_names

    # Check chokepoint recommendations
    assert isinstance(result["chokepoint_defenses"], list)
    assert len(result["chokepoint_defenses"]) >= 1
    cp_ids = [cp["id"] for cp in result["chokepoint_defenses"]]
    assert "CP-01" in cp_ids

    # Check Cytoscape visualization elements
    assert "cytoscape_elements" in result
    assert len(result["cytoscape_elements"]) >= 5
    has_attack_path_flag = any(
        el.get("data", {}).get("isAttackPath") is True for el in result["cytoscape_elements"]
    )
    assert has_attack_path_flag is True

def test_simulation_db_persistence():
    """Verify simulation results can be persisted and retrieved from SQLite."""
    sim = AttackPathPredictor.simulate_lateral_movement("SRV-DEV-01", iterations=100)
    sim_id = sim["simulation_id"]

    save_attack_path_simulation(sim)
    retrieved = get_attack_path_simulation(sim_id)

    assert retrieved is not None
    assert retrieved["simulation_id"] == sim_id
    assert retrieved["compromised_origin"] == "SRV-DEV-01"
    assert retrieved["mttb_minutes"] == sim["mttb_minutes"]
    assert len(retrieved["critical_attack_paths"]) == len(sim["critical_attack_paths"])

def test_benign_indicator_dynamic_zero_probability():
    """Verify that searching a clean domain like yahoo.com dynamically returns 0% compromise probability."""
    clean_sim = AttackPathPredictor.simulate_lateral_movement("yahoo.com")
    assert clean_sim["compromise_probability"] == 0.0
    assert clean_sim["mttb_minutes"] == 0
    assert len(clean_sim["critical_attack_paths"]) == 0
    assert len(clean_sim["crown_jewels_at_risk"]) == 0
    assert "BENIGN / CLEAN" in clean_sim["executive_summary"]
