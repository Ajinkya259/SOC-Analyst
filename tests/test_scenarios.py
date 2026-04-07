"""Tests for scenario data integrity — uniqueness, structure, and consistency."""

import pytest
from server.scenarios import SCENARIOS, get_scenarios_by_difficulty
from server.constants import INV_DATA_KEY
from server.scenarios import RESPONSE_ACTIONS


class TestScenarioStructure:
    """Every scenario must have the correct structure."""

    REQUIRED_ALERT_FIELDS = [
        "ticket_id", "timestamp", "source_tool", "alert_type",
        "severity_reported", "summary", "affected_user",
        "affected_device", "source_ip",
    ]
    REQUIRED_GT_FIELDS = ["classification", "severity", "actions", "explanation"]
    VALID_ALERT_TYPES = {"phishing", "suspicious_login", "malware_download", "data_exfiltration", "brute_force"}
    VALID_DIFFICULTIES = {"easy", "medium", "hard"}
    VALID_SEVERITIES = {"low", "medium", "high", "critical"}
    VALID_CLASSIFICATIONS = {"true_positive", "false_positive"}

    def test_scenario_count(self):
        assert len(SCENARIOS) == 25

    def test_unique_ids(self):
        ids = [s["id"] for s in SCENARIOS]
        assert len(ids) == len(set(ids)), f"Duplicate IDs: {[x for x in ids if ids.count(x) > 1]}"

    def test_unique_ticket_ids(self):
        tickets = [s["alert"]["ticket_id"] for s in SCENARIOS]
        assert len(tickets) == len(set(tickets)), f"Duplicate tickets: {[x for x in tickets if tickets.count(x) > 1]}"

    @pytest.mark.parametrize("scenario", SCENARIOS, ids=[s["id"] for s in SCENARIOS])
    def test_alert_fields(self, scenario):
        for field in self.REQUIRED_ALERT_FIELDS:
            assert field in scenario["alert"], f"{scenario['id']}: alert missing '{field}'"

    @pytest.mark.parametrize("scenario", SCENARIOS, ids=[s["id"] for s in SCENARIOS])
    def test_ground_truth_fields(self, scenario):
        for field in self.REQUIRED_GT_FIELDS:
            assert field in scenario["ground_truth"], f"{scenario['id']}: ground_truth missing '{field}'"

    @pytest.mark.parametrize("scenario", SCENARIOS, ids=[s["id"] for s in SCENARIOS])
    def test_investigation_data_keys(self, scenario):
        for key in INV_DATA_KEY.values():
            assert key in scenario["investigation_data"], f"{scenario['id']}: investigation_data missing '{key}'"

    @pytest.mark.parametrize("scenario", SCENARIOS, ids=[s["id"] for s in SCENARIOS])
    def test_valid_alert_type(self, scenario):
        assert scenario["alert"]["alert_type"] in self.VALID_ALERT_TYPES

    @pytest.mark.parametrize("scenario", SCENARIOS, ids=[s["id"] for s in SCENARIOS])
    def test_valid_difficulty(self, scenario):
        assert scenario["difficulty"] in self.VALID_DIFFICULTIES

    @pytest.mark.parametrize("scenario", SCENARIOS, ids=[s["id"] for s in SCENARIOS])
    def test_valid_classification(self, scenario):
        assert scenario["ground_truth"]["classification"] in self.VALID_CLASSIFICATIONS

    @pytest.mark.parametrize("scenario", SCENARIOS, ids=[s["id"] for s in SCENARIOS])
    def test_valid_severity(self, scenario):
        assert scenario["ground_truth"]["severity"] in self.VALID_SEVERITIES

    @pytest.mark.parametrize("scenario", SCENARIOS, ids=[s["id"] for s in SCENARIOS])
    def test_response_actions_are_valid(self, scenario):
        for action in scenario["ground_truth"]["actions"]:
            assert action in RESPONSE_ACTIONS, f"{scenario['id']}: unknown action '{action}'"

    @pytest.mark.parametrize("scenario", SCENARIOS, ids=[s["id"] for s in SCENARIOS])
    def test_relevant_investigations_are_valid(self, scenario):
        valid_keys = set(INV_DATA_KEY.values())
        for inv in scenario.get("relevant_investigations", []):
            assert inv in valid_keys, f"{scenario['id']}: unknown investigation key '{inv}'"

    def test_difficulty_distribution(self):
        easy = get_scenarios_by_difficulty("easy")
        medium = get_scenarios_by_difficulty("medium")
        hard = get_scenarios_by_difficulty("hard")
        assert len(easy) >= 3, "Need at least 3 easy scenarios"
        assert len(medium) >= 3, "Need at least 3 medium scenarios"
        assert len(hard) >= 3, "Need at least 3 hard scenarios"

    def test_has_both_tp_and_fp(self):
        tp = [s for s in SCENARIOS if s["ground_truth"]["classification"] == "true_positive"]
        fp = [s for s in SCENARIOS if s["ground_truth"]["classification"] == "false_positive"]
        assert len(tp) >= 5, "Need at least 5 TP scenarios"
        assert len(fp) >= 5, "Need at least 5 FP scenarios"
