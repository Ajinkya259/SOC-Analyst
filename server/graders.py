"""
Grading functions for the Cybersecurity Threat Response Agent.

Three graders corresponding to three tasks:
  - alert_triage     (easy)   — classify TP/FP
  - full_investigation (medium) — classify + severity + response actions
  - multi_alert_triage (hard)   — handle 3 alerts under time pressure

All graders return a float in [0.0, 1.0].
"""

from server.constants import SEVERITY_LEVELS, INV_DATA_KEY


def _investigation_ratio(alert_state: dict) -> float:
    """Fraction of relevant investigations the agent actually performed."""
    relevant = set(alert_state["scenario"].get("relevant_investigations", []))
    if not relevant:
        return 1.0
    investigated = {
        INV_DATA_KEY[a]
        for a in alert_state.get("investigation_actions_taken", [])
        if a in INV_DATA_KEY
    }
    return len(investigated & relevant) / len(relevant)


def _response_f1(alert_state: dict) -> float:
    """F1 score of response actions taken vs. ground truth required actions."""
    correct = set(alert_state["scenario"]["ground_truth"]["actions"])
    taken = set(alert_state.get("response_actions_taken", []))

    # No actions required AND none taken → perfect
    if not correct and not taken:
        return 1.0

    precision = len(taken & correct) / len(taken) if taken else 0.0
    recall = len(taken & correct) / len(correct) if correct else (1.0 if not taken else 0.0)

    if precision + recall == 0:
        return 0.0
    return 2 * precision * recall / (precision + recall)


# ── Task 1: Easy ─────────────────────────────────────────────────────────────

def grade_alert_triage(alert_state: dict, episode_state) -> float:
    """
    EASY task grader.

    Weights:
      Classification correct   0.60
      Investigation thoroughness 0.25
      Efficiency                0.15
    """
    gt = alert_state["scenario"]["ground_truth"]
    score = 0.0

    # Classification (60%)
    if alert_state.get("classification") == gt["classification"]:
        score += 0.60

    # Investigation thoroughness (25%)
    score += 0.25 * _investigation_ratio(alert_state)

    # Efficiency (15%) — penalise excess steps beyond optimal
    relevant_count = len(alert_state["scenario"].get("relevant_investigations", []))
    optimal_steps = relevant_count + 2  # investigations + classify + close
    excess = max(0, episode_state.step_count - optimal_steps)
    efficiency = max(0.0, 1.0 - excess / 20)
    score += 0.15 * efficiency

    return round(min(max(score, 0.0), 1.0), 4)


# ── Task 2: Medium ───────────────────────────────────────────────────────────

def grade_full_investigation(alert_state: dict, episode_state) -> float:
    """
    MEDIUM task grader.

    Weights:
      Classification correct      0.30
      Severity accuracy            0.20
      Response actions F1          0.35
      Investigation thoroughness   0.15
    """
    gt = alert_state["scenario"]["ground_truth"]
    score = 0.0

    # Classification (30%)
    if alert_state.get("classification") == gt["classification"]:
        score += 0.30

    # Severity (20%) — 0.33 penalty per level off
    assigned = alert_state.get("severity_assigned")
    if assigned and assigned in SEVERITY_LEVELS and gt["severity"] in SEVERITY_LEVELS:
        diff = abs(SEVERITY_LEVELS[assigned] - SEVERITY_LEVELS[gt["severity"]])
        score += 0.20 * max(0.0, 1.0 - diff * 0.33)

    # Response actions F1 (35%)
    score += 0.35 * _response_f1(alert_state)

    # Investigation thoroughness (15%)
    score += 0.15 * _investigation_ratio(alert_state)

    return round(min(max(score, 0.0), 1.0), 4)


# ── Task 3: Hard ─────────────────────────────────────────────────────────────

def grade_multi_alert(per_alert_states: list, episode_state) -> float:
    """
    HARD task grader.

    Per alert:
      classification  0.25
      severity        0.15
      response F1     0.30
      investigation   0.15
      correct close   0.15

    Alert weights: [25%, 35%, 40%] — later alerts count more.
    Incomplete penalty: score × (completed / 3) × 0.7
    """
    if not per_alert_states:
        return 0.0

    weights = [0.25, 0.35, 0.40]
    alert_scores = []

    for alert_state in per_alert_states:
        gt = alert_state["scenario"]["ground_truth"]
        s = 0.0

        # Classification (25%)
        if alert_state.get("classification") == gt["classification"]:
            s += 0.25

        # Severity (15%)
        assigned = alert_state.get("severity_assigned")
        if assigned and assigned in SEVERITY_LEVELS and gt["severity"] in SEVERITY_LEVELS:
            diff = abs(SEVERITY_LEVELS[assigned] - SEVERITY_LEVELS[gt["severity"]])
            s += 0.15 * max(0.0, 1.0 - diff * 0.33)

        # Response F1 (30%)
        s += 0.30 * _response_f1(alert_state)

        # Investigation (15%)
        s += 0.15 * _investigation_ratio(alert_state)

        # Correct close action (15%)
        expected_close = (
            "close_ticket_true_positive"
            if gt["classification"] == "true_positive"
            else "close_ticket_false_positive"
        )
        if alert_state.get("close_action") == expected_close:
            s += 0.15

        alert_scores.append(s)

    # Weighted average
    total = sum(
        weights[min(i, len(weights) - 1)] * s
        for i, s in enumerate(alert_scores)
    )
    weight_sum = sum(weights[: len(alert_scores)])
    total = total / weight_sum if weight_sum > 0 else 0.0

    # Incomplete penalty
    completed = len(per_alert_states)
    if completed < 3:
        total *= (completed / 3) * 0.7

    return round(min(max(total, 0.0), 1.0), 4)
