"""Unit tests for the Adversarial Arena Engine."""

import pytest
from agents.arena.engine import AdversarialArenaEngine, APT_PERSONA_PROFILES


def test_apt_personas_availability():
    """Verify that predefined APT persona profiles exist with stages."""
    assert "APT29" in APT_PERSONA_PROFILES
    assert "FIN7" in APT_PERSONA_PROFILES
    assert "LAZARUS" in APT_PERSONA_PROFILES

    for persona, details in APT_PERSONA_PROFILES.items():
        assert "name" in details
        assert "stages" in details
        assert len(details["stages"]) >= 4
        for stage in details["stages"]:
            assert "stage_name" in stage
            assert "mitre_id" in stage
            assert "technique" in stage
            assert "red_action" in stage
            assert "simulated_telemetry" in stage
            assert "default_sigma" in stage


def test_arena_simulation_apt29():
    """Test adversarial simulation against APT29 persona."""
    engine = AdversarialArenaEngine(adversary="APT29", defense_posture="Balanced SOC")
    result = engine.run_simulation()

    assert result["match_id"].startswith("arena-")
    assert "APT29" in result["adversary"]
    assert result["defense_posture"] == "Balanced SOC"
    assert len(result["rounds"]) == 4
    assert result["winner"] in ["BLUE_TEAM", "RED_TEAM", "CONTESTED"]
    assert result["detection_rate"] >= 0.0
    assert result["avg_ttd_ms"] > 0
    assert len(result["sigma_rules"]) >= 1

    # Check structure of each round
    for r in result["rounds"]:
        assert "round_number" in r
        assert "stage_name" in r
        assert "mitre_id" in r
        assert "red_agent" in r
        assert "blue_agent" in r

        red = r["red_agent"]
        assert "action" in red
        assert "telemetry" in red
        assert red["stealth_rating"] > 0

        blue = r["blue_agent"]
        assert "status" in blue
        assert "containment" in blue
        assert blue["ttd_ms"] > 0
        assert "sigma_rule" in blue
        assert "title:" in blue["sigma_rule"]


def test_arena_simulation_all_postures():
    """Verify duel runs smoothly under all defense postures."""
    postures = ["Strict Zero-Trust", "Balanced SOC", "Aggressive Autonomous"]
    for posture in postures:
        engine = AdversarialArenaEngine(adversary="FIN7", defense_posture=posture)
        result = engine.run_simulation()
        assert result["defense_posture"] == posture
        assert len(result["rounds"]) == 4
        assert result["blue_score"] >= 0
        assert result["red_score"] >= 0


def test_arena_simulation_lazarus():
    """Test simulation for Lazarus Group persona."""
    engine = AdversarialArenaEngine(adversary="LAZARUS", defense_posture="Aggressive Autonomous")
    result = engine.run_simulation()
    assert "Lazarus" in result["adversary"]
    assert result["summary"] != ""
    assert isinstance(result["sigma_rules"], list)

