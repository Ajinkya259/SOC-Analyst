"""
Shared constants for the Cybersecurity Threat Response Agent.

Single source of truth for severity levels, investigation key mappings,
and reward values used across environment.py and graders.py.
"""

# ── Severity scale ────────────────────────────────────────────────────────────

SEVERITY_LEVELS = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# ── Investigation action → scenario data key mapping ─────────────────────────

INV_DATA_KEY = {
    "check_user_profile": "user_profile",
    "check_login_history": "login_history",
    "check_ip_reputation": "ip_reputation",
    "check_device_info": "device_info",
    "check_email_headers": "email_headers",
    "check_file_analysis": "file_analysis",
    "check_network_logs": "network_logs",
    "check_threat_intel": "threat_intel",
}

# ── Step rewards ──────────────────────────────────────────────────────────────
# Dense per-step feedback guiding agents toward good SOC workflow.

REWARD_EARLY_INVESTIGATION = 0.05      # Bonus for investigating in steps 1–3
REWARD_RELEVANT_EVIDENCE = 0.03        # Found evidence relevant to alert type
REWARD_IRRELEVANT_EVIDENCE = -0.01     # Investigation yielded nothing useful
REWARD_REPEATED_INVESTIGATION = -0.02  # Already retrieved this data
REWARD_NOT_APPLICABLE = -0.01          # Action not valid for this alert type
REWARD_NO_DATA = -0.01                 # No data available for this action

REWARD_CORRECT_CLASSIFICATION = 0.15
REWARD_WRONG_CLASSIFICATION = -0.10

REWARD_SEVERITY_EXACT = 0.10           # Severity matches ground truth
REWARD_SEVERITY_OFF_BY_ONE = 0.03      # One level off
REWARD_SEVERITY_OFF_BY_MORE = -0.05    # Two or more levels off

REWARD_CORRECT_RESPONSE = 0.05        # Took a required response action
REWARD_UNNECESSARY_RESPONSE = -0.05   # Took an unrequired action
REWARD_HARMFUL_ON_FP = -0.10          # Disruptive action on a false positive
REWARD_RESPONSE_BEFORE_CLASSIFY = -0.05

REWARD_CONSISTENT_CLOSE = 0.05        # Close action matches classification
REWARD_INCONSISTENT_CLOSE = -0.10     # Close contradicts classification

REWARD_TIMEOUT = -0.15                # Episode hit step limit
REWARD_INVALID_ACTION = -0.02         # Unrecognized action name
REWARD_MISMATCHED_IP = 0.01           # IP reputation check for non-alert IP
