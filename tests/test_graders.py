"""Tests for grading functions — edge cases, boundary conditions, and scoring."""

import pytest
from server.graders import grade_alert_triage, grade_full_investigation, grade_multi_alert
from models import SOCState


def _make_state(step_count: int = 5) -> SOCState:
    """Create a minimal SOCState for grading."""
    return SOCState(episode_id="test", step_count=step_count, task_name="test")


def _make_alert_state(
    scenario_id="PH-01",
    classification="true_positive",
    gt_classification="true_positive",
    severity_assigned="high",
    gt_severity="high",
    response_actions=None,
    gt_actions=None,
    investigation_actions=None,
    relevant_investigations=None,
    close_action="close_ticket_true_positive",
) -> dict:
    """Create a minimal alert state dict for grading."""
    return {
        "scenario": {
            "id": scenario_id,
            "ground_truth": {
                "classification": gt_classification,
                "severity": gt_severity,
                "actions": gt_actions or [],
            },
            "relevant_investigations": relevant_investigations or [],
        },
        "classification": classification,
        "severity_assigned": severity_assigned,
        "response_actions_taken": response_actions or [],
        "investigation_actions_taken": investigation_actions or [],
        "close_action": close_action,
    }


class TestAlertTriage:
    """Easy task grader."""

    def test_perfect_score(self):
        alert = _make_alert_state(
            classification="false_positive",
            gt_classification="false_positive",
            relevant_investigations=["user_profile", "ip_reputation"],
            investigation_actions=["check_user_profile", "check_ip_reputation"],
        )
        # 4 steps: 2 investigations + classify + close
        score = grade_alert_triage(alert, _make_state(step_count=4))
        assert score >= 0.95

    def test_wrong_classification_caps_score(self):
        alert = _make_alert_state(
            classification="true_positive",
            gt_classification="false_positive",
        )
        score = grade_alert_triage(alert, _make_state())
        assert score < 0.40  # Misses the 0.60 classification weight

    def test_score_in_bounds(self):
        alert = _make_alert_state()
        score = grade_alert_triage(alert, _make_state())
        assert 0.0 <= score <= 1.0

    def test_no_investigation_still_scores(self):
        alert = _make_alert_state(
            relevant_investigations=["user_profile"],
            investigation_actions=[],
        )
        score = grade_alert_triage(alert, _make_state())
        assert score > 0.0  # Gets classification + efficiency points


class TestFullInvestigation:
    """Medium task grader."""

    def test_perfect_score(self):
        alert = _make_alert_state(
            classification="true_positive",
            gt_classification="true_positive",
            severity_assigned="high",
            gt_severity="high",
            response_actions=["block_ip", "isolate_device"],
            gt_actions=["block_ip", "isolate_device"],
            relevant_investigations=["ip_reputation", "device_info"],
            investigation_actions=["check_ip_reputation", "check_device_info"],
        )
        score = grade_full_investigation(alert, _make_state())
        assert score >= 0.95

    def test_severity_off_by_one(self):
        alert = _make_alert_state(
            severity_assigned="medium",
            gt_severity="high",
        )
        score_exact = grade_full_investigation(
            _make_alert_state(severity_assigned="high", gt_severity="high"),
            _make_state(),
        )
        score_off = grade_full_investigation(alert, _make_state())
        assert score_off < score_exact

    def test_response_f1_partial_credit(self):
        alert = _make_alert_state(
            response_actions=["block_ip"],  # 1 of 2 correct
            gt_actions=["block_ip", "isolate_device"],
        )
        score = grade_full_investigation(alert, _make_state())
        assert 0.0 < score < 1.0

    def test_no_actions_needed_no_actions_taken(self):
        """FP with no required actions and none taken should get full F1."""
        alert = _make_alert_state(
            classification="false_positive",
            gt_classification="false_positive",
            response_actions=[],
            gt_actions=[],
        )
        score = grade_full_investigation(alert, _make_state())
        assert score > 0.5  # Gets classification + F1 (1.0) + investigation


class TestMultiAlert:
    """Hard task grader."""

    def test_empty_returns_zero(self):
        assert grade_multi_alert([], _make_state()) == 0.0

    def test_three_perfect_alerts(self):
        alerts = [
            _make_alert_state(
                response_actions=["block_ip"],
                gt_actions=["block_ip"],
                relevant_investigations=["ip_reputation"],
                investigation_actions=["check_ip_reputation"],
            )
            for _ in range(3)
        ]
        score = grade_multi_alert(alerts, _make_state())
        assert score >= 0.90

    def test_incomplete_penalty(self):
        """Completing only 1 of 3 alerts should be penalized."""
        alerts = [_make_alert_state(
            response_actions=["block_ip"],
            gt_actions=["block_ip"],
        )]
        score = grade_multi_alert(alerts, _make_state())
        assert score < 0.50  # Penalized by (1/3) * 0.7

    def test_later_alerts_weighted_more(self):
        """Alert 3 (weight 0.40) matters more than alert 1 (weight 0.25)."""
        # Perfect first, bad third
        good = _make_alert_state(response_actions=["block_ip"], gt_actions=["block_ip"])
        bad = _make_alert_state(classification="true_positive", gt_classification="false_positive")
        score_bad_last = grade_multi_alert([good, good, bad], _make_state())
        score_bad_first = grade_multi_alert([bad, good, good], _make_state())
        assert score_bad_first > score_bad_last  # Bad last hurts more

    def test_score_in_bounds(self):
        alerts = [_make_alert_state() for _ in range(3)]
        score = grade_multi_alert(alerts, _make_state())
        assert 0.0 <= score <= 1.0
