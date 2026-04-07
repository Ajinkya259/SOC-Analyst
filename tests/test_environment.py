"""Tests for the SOC Analyst environment — reset, step, state, and edge cases."""

import pytest
from server.environment import SOCEnvironment
from models import SOCAction, SOCObservation, SOCState


class TestReset:
    """Environment reset behavior."""

    def test_reset_returns_observation(self):
        env = SOCEnvironment()
        obs = env.reset(task_name="alert_triage", seed=0)
        assert isinstance(obs, SOCObservation)
        assert obs.done is False
        assert obs.reward is None
        assert obs.ticket_id != ""
        assert obs.alert_type != ""
        assert obs.step_number == 0

    def test_reset_with_seed_is_deterministic(self):
        env1 = SOCEnvironment()
        obs1 = env1.reset(task_name="alert_triage", seed=42)
        env2 = SOCEnvironment()
        obs2 = env2.reset(task_name="alert_triage", seed=42)
        assert obs1.ticket_id == obs2.ticket_id
        assert obs1.alert_type == obs2.alert_type

    def test_reset_selects_correct_difficulty_pool(self):
        env = SOCEnvironment()
        env.reset(task_name="alert_triage", seed=0)
        assert env._current_scenario["difficulty"] == "easy"

    def test_reset_multi_alert_selects_three_scenarios(self):
        env = SOCEnvironment()
        obs = env.reset(task_name="multi_alert_triage", seed=0)
        assert obs.total_alerts == 3
        assert len(env._scenarios) == 3

    def test_reset_invalid_task_falls_back(self):
        env = SOCEnvironment()
        obs = env.reset(task_name="nonexistent_task")
        assert env._state.task_name == "alert_triage"

    def test_state_property(self):
        env = SOCEnvironment()
        env.reset(task_name="alert_triage", seed=0)
        state = env.state
        assert isinstance(state, SOCState)
        assert state.step_count == 0
        assert state.task_name == "alert_triage"


class TestInvestigation:
    """Investigation actions."""

    def test_investigation_returns_data(self):
        env = SOCEnvironment()
        env.reset(task_name="alert_triage", seed=0)
        obs = env.step(SOCAction(action_type="check_user_profile", parameters={}))
        assert obs.done is False
        assert obs.reward is not None
        assert "user_profile" in obs.investigation_results

    def test_repeated_investigation_penalized(self):
        env = SOCEnvironment()
        env.reset(task_name="alert_triage", seed=0)
        env.step(SOCAction(action_type="check_user_profile", parameters={}))
        obs = env.step(SOCAction(action_type="check_user_profile", parameters={}))
        assert obs.reward == -0.02

    def test_email_headers_only_for_phishing(self):
        """check_email_headers should fail on non-phishing alerts."""
        env = SOCEnvironment()
        # Seed to get a non-phishing scenario
        for seed in range(100):
            env.reset(task_name="alert_triage", seed=seed)
            if env._current_scenario["alert"]["alert_type"] != "phishing":
                break
        if env._current_scenario["alert"]["alert_type"] != "phishing":
            obs = env.step(SOCAction(action_type="check_email_headers", parameters={}))
            assert obs.reward == -0.01
            assert "not applicable" in obs.message


class TestDecision:
    """Classification and severity assignment."""

    def test_correct_classification_rewarded(self):
        env = SOCEnvironment()
        env.reset(task_name="alert_triage", seed=0)
        gt = env._current_scenario["ground_truth"]
        obs = env.step(SOCAction(
            action_type="classify_alert",
            parameters={"classification": gt["classification"]},
        ))
        assert obs.reward == 0.15

    def test_wrong_classification_penalized(self):
        env = SOCEnvironment()
        env.reset(task_name="alert_triage", seed=0)
        gt = env._current_scenario["ground_truth"]
        wrong = "false_positive" if gt["classification"] == "true_positive" else "true_positive"
        obs = env.step(SOCAction(
            action_type="classify_alert",
            parameters={"classification": wrong},
        ))
        assert obs.reward == -0.10

    def test_invalid_classification_rejected(self):
        env = SOCEnvironment()
        env.reset(task_name="alert_triage", seed=0)
        obs = env.step(SOCAction(
            action_type="classify_alert",
            parameters={"classification": "maybe"},
        ))
        assert obs.reward == -0.02

    def test_severity_exact_match(self):
        env = SOCEnvironment()
        env.reset(task_name="full_investigation", seed=0)
        gt = env._current_scenario["ground_truth"]
        obs = env.step(SOCAction(
            action_type="assign_severity",
            parameters={"severity": gt["severity"]},
        ))
        assert obs.reward == 0.10


class TestResponse:
    """Response actions and workflow enforcement."""

    def test_response_before_classify_penalized(self):
        env = SOCEnvironment()
        env.reset(task_name="alert_triage", seed=0)
        obs = env.step(SOCAction(action_type="block_ip", parameters={}))
        assert obs.reward == -0.05
        assert "Classify" in obs.message

    def test_response_after_classify_accepted(self):
        env = SOCEnvironment()
        env.reset(task_name="full_investigation", seed=0)
        gt = env._current_scenario["ground_truth"]
        env.step(SOCAction(
            action_type="classify_alert",
            parameters={"classification": gt["classification"]},
        ))
        if gt["actions"]:
            obs = env.step(SOCAction(action_type=gt["actions"][0], parameters={}))
            assert obs.reward == 0.05


class TestTerminal:
    """Ticket closure and episode completion."""

    def test_close_ends_episode(self):
        env = SOCEnvironment()
        env.reset(task_name="alert_triage", seed=0)
        gt = env._current_scenario["ground_truth"]
        env.step(SOCAction(
            action_type="classify_alert",
            parameters={"classification": gt["classification"]},
        ))
        close = (
            "close_ticket_true_positive"
            if gt["classification"] == "true_positive"
            else "close_ticket_false_positive"
        )
        obs = env.step(SOCAction(action_type=close, parameters={}))
        assert obs.done is True
        assert 0.0 <= obs.reward <= 1.0

    def test_invalid_action_penalized(self):
        env = SOCEnvironment()
        env.reset(task_name="alert_triage", seed=0)
        obs = env.step(SOCAction(action_type="hack_the_planet", parameters={}))
        assert obs.reward == -0.02
        assert obs.done is False

    def test_step_limit_ends_episode(self):
        env = SOCEnvironment()
        env.reset(task_name="alert_triage", seed=0)
        for _ in range(21):
            obs = env.step(SOCAction(action_type="check_user_profile", parameters={}))
        assert obs.done is True
