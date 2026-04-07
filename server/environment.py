"""
Cybersecurity Threat Response Agent — OpenEnv Environment

Core environment implementing the step / reset / state API for SOC alert
investigation. An agent investigates alerts, classifies threats (TP/FP),
assigns severity, takes response actions, and closes tickets.
"""

import uuid
import random
from typing import Optional

from openenv.core.env_server import Environment

from models import SOCAction, SOCObservation, SOCState
from server.constants import (
    SEVERITY_LEVELS,
    INV_DATA_KEY,
    REWARD_EARLY_INVESTIGATION,
    REWARD_RELEVANT_EVIDENCE,
    REWARD_IRRELEVANT_EVIDENCE,
    REWARD_REPEATED_INVESTIGATION,
    REWARD_NOT_APPLICABLE,
    REWARD_NO_DATA,
    REWARD_CORRECT_CLASSIFICATION,
    REWARD_WRONG_CLASSIFICATION,
    REWARD_SEVERITY_EXACT,
    REWARD_SEVERITY_OFF_BY_ONE,
    REWARD_SEVERITY_OFF_BY_MORE,
    REWARD_CORRECT_RESPONSE,
    REWARD_UNNECESSARY_RESPONSE,
    REWARD_HARMFUL_ON_FP,
    REWARD_RESPONSE_BEFORE_CLASSIFY,
    REWARD_CONSISTENT_CLOSE,
    REWARD_INCONSISTENT_CLOSE,
    REWARD_TIMEOUT,
    REWARD_INVALID_ACTION,
    REWARD_MISMATCHED_IP,
)
from server.scenarios import (
    SCENARIOS,
    INVESTIGATION_ACTIONS,
    DECISION_ACTIONS,
    RESPONSE_ACTIONS,
    TERMINAL_ACTIONS,
    ALL_ACTIONS,
    ALERT_SPECIFIC_ACTIONS,
    get_scenarios_by_difficulty,
)
from server.graders import grade_alert_triage, grade_full_investigation, grade_multi_alert


# ── Task configurations ──────────────────────────────────────────────────────

TASK_CONFIGS = {
    "alert_triage": {
        "difficulty": "easy",
        "max_steps": 20,
        "num_alerts": 1,
        "grader": grade_alert_triage,
    },
    "full_investigation": {
        "difficulty": "medium",
        "max_steps": 20,
        "num_alerts": 1,
        "grader": grade_full_investigation,
    },
    "multi_alert_triage": {
        "difficulty": "hard",
        "max_steps": 45,
        "num_alerts": 3,
        "grader": grade_multi_alert,
    },
}


class SOCEnvironment(Environment):
    """Security Operations Center environment for training threat response agents."""

    SUPPORTS_CONCURRENT_SESSIONS = True

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._state = SOCState()
        self._task_config: dict = {}
        self._scenarios: list = []
        self._current_scenario: dict = {}
        self._investigation_results: dict = {}
        self._actions_log: list = []
        self._classified: bool = False
        self._per_alert_states: list = []

    # ── Core API ─────────────────────────────────────────────────────────────

    def reset(
        self, seed=None, episode_id=None, task_name="alert_triage", **kwargs
    ) -> SOCObservation:
        """Start a new episode. Selects scenario(s) based on task difficulty."""
        if seed is not None:
            random.seed(seed)

        if task_name not in TASK_CONFIGS:
            task_name = "alert_triage"
        self._task_config = TASK_CONFIGS[task_name]

        # Select scenarios from the appropriate difficulty pool
        pool = get_scenarios_by_difficulty(self._task_config["difficulty"])
        if len(pool) < self._task_config["num_alerts"]:
            pool = SCENARIOS  # fallback to full pool
        num_alerts = min(self._task_config["num_alerts"], len(pool))
        self._scenarios = random.sample(pool, num_alerts)
        self._current_scenario = self._scenarios[0]

        # Reset all episode state
        self._investigation_results = {}
        self._actions_log = []
        self._classified = False
        self._per_alert_states = []

        self._state = SOCState(
            episode_id=episode_id or str(uuid.uuid4()),
            step_count=0,
            task_name=task_name,
            scenario_id=self._current_scenario["id"],
            current_alert_index=0,
            total_alerts=num_alerts,
        )

        return self._build_observation(
            done=False,
            reward=None,
            message="New security alert assigned. Investigate and resolve.",
        )

    def step(self, action: SOCAction, **kwargs) -> SOCObservation:
        """Process one agent action and return the next observation."""
        self._state.step_count += 1
        action_type = action.action_type.strip()
        params = action.parameters or {}
        max_steps = self._task_config.get("max_steps", 20)

        # Step limit exceeded
        if self._state.step_count > max_steps:
            self._state.cumulative_reward += REWARD_TIMEOUT
            final_score = self._compute_final_score()
            return self._build_observation(
                done=True,
                reward=final_score,
                message=f"Step limit reached ({max_steps}). Final score: {final_score:.3f}",
            )

        # Unknown action
        if action_type not in ALL_ACTIONS:
            return self._apply_reward(
                REWARD_INVALID_ACTION, done=False,
                log=f"INVALID: {action_type}",
                message=f"Unrecognized action '{action_type}'. Use one of: {', '.join(ALL_ACTIONS)}",
            )

        # Dispatch
        if action_type in INVESTIGATION_ACTIONS:
            return self._handle_investigation(action_type, params)
        if action_type in DECISION_ACTIONS:
            return self._handle_decision(action_type, params)
        if action_type in RESPONSE_ACTIONS:
            return self._handle_response(action_type, params)
        return self._handle_terminal(action_type)

    @property
    def state(self) -> SOCState:
        """Return current episode state."""
        return self._state

    # ── Investigation ────────────────────────────────────────────────────────

    def _handle_investigation(self, action_type: str, params: dict) -> SOCObservation:
        """Gather evidence — returns data from the scenario."""
        scenario = self._current_scenario
        alert_type = scenario["alert"]["alert_type"]

        # Alert-type restriction (e.g. email_headers only for phishing)
        if action_type in ALERT_SPECIFIC_ACTIONS:
            if alert_type not in ALERT_SPECIFIC_ACTIONS[action_type]:
                return self._apply_reward(
                    REWARD_NOT_APPLICABLE, done=False,
                    log=f"{action_type} (not applicable)",
                    message=f"'{action_type}' is not applicable for {alert_type} alerts.",
                )

        # Repeated investigation penalty
        if action_type in self._state.investigation_actions_taken:
            return self._apply_reward(
                REWARD_REPEATED_INVESTIGATION, done=False,
                log=f"{action_type} (repeated)",
                message=f"Already retrieved '{action_type}' data. No new information.",
            )

        data_key = INV_DATA_KEY.get(action_type, action_type)
        inv_data = scenario["investigation_data"].get(data_key)

        # No data available for this action
        if inv_data is None:
            self._state.investigation_actions_taken.append(action_type)
            return self._apply_reward(
                REWARD_NO_DATA, done=False,
                log=f"{action_type} (no data)",
                message=f"No data available for '{action_type}' on this alert.",
            )

        # IP reputation with a non-matching IP parameter
        if action_type == "check_ip_reputation" and params.get("ip"):
            if params["ip"] != scenario["alert"]["source_ip"]:
                self._state.investigation_actions_taken.append(action_type)
                self._investigation_results[data_key] = {
                    "ip": params["ip"],
                    "note": f"IP {params['ip']} not directly associated with this alert.",
                    "abuse_score": "unknown",
                }
                return self._apply_reward(
                    REWARD_MISMATCHED_IP, done=False,
                    log=f"{action_type}({params['ip']})",
                    message=f"IP reputation check for {params['ip']}: not associated with this alert.",
                )

        # Store result and record action
        self._investigation_results[data_key] = inv_data
        self._state.investigation_actions_taken.append(action_type)

        # Reward: early investigation bonus + relevance
        relevant = scenario.get("relevant_investigations", [])
        is_early = self._state.step_count <= 3
        reward = (REWARD_EARLY_INVESTIGATION if is_early else 0.0)
        reward += REWARD_RELEVANT_EVIDENCE if data_key in relevant else REWARD_IRRELEVANT_EVIDENCE

        return self._apply_reward(
            reward, done=False,
            log=action_type,
            message=f"Investigation complete: {action_type}",
        )

    # ── Decision ─────────────────────────────────────────────────────────────

    def _handle_decision(self, action_type: str, params: dict) -> SOCObservation:
        """Handle classify_alert and assign_severity."""
        gt = self._current_scenario["ground_truth"]

        if action_type == "classify_alert":
            classification = params.get("classification", "").lower().strip()
            if classification not in ("true_positive", "false_positive"):
                return self._apply_reward(
                    REWARD_INVALID_ACTION, done=False,
                    log=f"classify_alert (invalid: {classification})",
                    message="Invalid classification. Must be 'true_positive' or 'false_positive'.",
                )

            self._state.classification = classification
            self._classified = True
            is_correct = classification == gt["classification"]
            reward = REWARD_CORRECT_CLASSIFICATION if is_correct else REWARD_WRONG_CLASSIFICATION

            response_note = (
                "Response actions now available."
                if classification == "true_positive"
                else "You may close the ticket."
            )
            return self._apply_reward(
                reward, done=False,
                log=f"classify_alert({classification})",
                message=f"Alert classified as {classification}. {response_note}",
            )

        # assign_severity
        severity = params.get("severity", "").lower().strip()
        if severity not in SEVERITY_LEVELS:
            return self._apply_reward(
                REWARD_INVALID_ACTION, done=False,
                log=f"assign_severity (invalid: {severity})",
                message=f"Invalid severity. Must be one of: {', '.join(SEVERITY_LEVELS.keys())}",
            )

        self._state.severity_assigned = severity
        diff = abs(SEVERITY_LEVELS[severity] - SEVERITY_LEVELS[gt["severity"]])
        if diff == 0:
            reward = REWARD_SEVERITY_EXACT
        elif diff == 1:
            reward = REWARD_SEVERITY_OFF_BY_ONE
        else:
            reward = REWARD_SEVERITY_OFF_BY_MORE

        return self._apply_reward(
            reward, done=False,
            log=f"assign_severity({severity})",
            message=f"Severity assigned: {severity}.",
        )

    # ── Response ─────────────────────────────────────────────────────────────

    def _handle_response(self, action_type: str, params: dict) -> SOCObservation:
        """Handle remediation actions (block_ip, isolate_device, etc.)."""
        gt = self._current_scenario["ground_truth"]

        # Must classify before responding
        if not self._classified:
            return self._apply_reward(
                REWARD_RESPONSE_BEFORE_CLASSIFY, done=False,
                log=f"{action_type} (before classify)",
                message=f"Classify the alert before taking response action '{action_type}'.",
            )

        # Record action (deduplicated)
        if action_type not in self._state.response_actions_taken:
            self._state.response_actions_taken.append(action_type)

        # Compute reward
        correct_actions = set(gt["actions"])
        is_fp = gt["classification"] == "false_positive"
        harmful_on_fp = action_type in (
            "disable_user_account", "isolate_device", "block_ip", "block_sender_ip",
        )

        if is_fp and harmful_on_fp:
            reward = REWARD_HARMFUL_ON_FP
        elif action_type in correct_actions:
            reward = REWARD_CORRECT_RESPONSE
        else:
            reward = REWARD_UNNECESSARY_RESPONSE

        return self._apply_reward(
            reward, done=False,
            log=action_type,
            message=f"Response action executed: {action_type}.",
        )

    # ── Terminal ─────────────────────────────────────────────────────────────

    def _handle_terminal(self, action_type: str) -> SOCObservation:
        """Handle close_ticket. Advances to next alert in multi-alert tasks."""
        # Check consistency between close action and prior classification
        close_as_tp = action_type == "close_ticket_true_positive"
        classified_as_tp = self._state.classification == "true_positive"

        if self._classified and (close_as_tp != classified_as_tp):
            self._state.cumulative_reward += REWARD_INCONSISTENT_CLOSE
        elif self._classified:
            self._state.cumulative_reward += REWARD_CONSISTENT_CLOSE

        # Save per-alert state for grading
        self._per_alert_states.append({
            "scenario": self._current_scenario,
            "classification": self._state.classification,
            "severity_assigned": self._state.severity_assigned,
            "response_actions_taken": list(self._state.response_actions_taken),
            "investigation_actions_taken": list(self._state.investigation_actions_taken),
            "close_action": action_type,
        })
        self._state.alerts_completed += 1
        self._actions_log.append(action_type)

        # More alerts remaining (multi-alert task)
        if self._state.current_alert_index + 1 < self._state.total_alerts:
            self._state.current_alert_index += 1
            self._current_scenario = self._scenarios[self._state.current_alert_index]
            self._state.scenario_id = self._current_scenario["id"]

            # Reset per-alert tracking (actions_log persists as episode history)
            self._investigation_results = {}
            self._state.classification = None
            self._state.severity_assigned = None
            self._state.response_actions_taken = []
            self._state.investigation_actions_taken = []
            self._classified = False

            alert_num = self._state.current_alert_index + 1
            return self._build_observation(
                done=False, reward=0.0,
                message=f"Ticket closed. Next alert ({alert_num}/{self._state.total_alerts}) assigned.",
            )

        # All alerts done — compute final grader score
        final_score = self._compute_final_score()
        return self._build_observation(
            done=True, reward=final_score,
            message=f"All tickets resolved. Final score: {final_score:.3f}",
        )

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _apply_reward(self, reward: float, done: bool, log: str, message: str) -> SOCObservation:
        """Record a reward, append to the action log, and return an observation."""
        self._state.cumulative_reward += reward
        self._actions_log.append(log)
        return self._build_observation(done=done, reward=reward, message=message)

    def _compute_final_score(self) -> float:
        """Run the task grader on the completed episode."""
        grader = self._task_config.get("grader")
        if grader is None:
            return 0.0

        if self._state.task_name == "multi_alert_triage":
            return grader(self._per_alert_states, self._state)

        # Single-alert tasks — use the saved per-alert state
        alert_state = self._per_alert_states[-1] if self._per_alert_states else {
            "scenario": self._current_scenario,
            "classification": self._state.classification,
            "severity_assigned": self._state.severity_assigned,
            "response_actions_taken": list(self._state.response_actions_taken),
            "investigation_actions_taken": list(self._state.investigation_actions_taken),
            "close_action": None,
        }
        return grader(alert_state, self._state)

    def _get_available_actions(self) -> list:
        """Return the list of currently valid actions."""
        actions = list(INVESTIGATION_ACTIONS) + list(DECISION_ACTIONS) + list(TERMINAL_ACTIONS)
        if self._classified:
            actions.extend(RESPONSE_ACTIONS)
        return actions

    def _build_observation(self, done: bool, reward: Optional[float], message: str) -> SOCObservation:
        """Construct the observation from current state and scenario."""
        alert = self._current_scenario["alert"]
        return SOCObservation(
            done=done,
            reward=reward,
            ticket_id=alert["ticket_id"],
            alert_summary=alert["summary"],
            alert_type=alert["alert_type"],
            alert_severity=alert["severity_reported"],
            source_tool=alert["source_tool"],
            affected_user=alert["affected_user"],
            affected_device=alert["affected_device"],
            source_ip=alert["source_ip"],
            investigation_results=dict(self._investigation_results),
            actions_taken=list(self._actions_log),
            available_actions=self._get_available_actions(),
            step_number=self._state.step_count,
            max_steps=self._task_config.get("max_steps", 20),
            message=message,
            task_name=self._state.task_name,
            current_alert_index=self._state.current_alert_index,
            total_alerts=self._state.total_alerts,
        )
