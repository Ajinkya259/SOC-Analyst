"""
Inference Script — Cybersecurity Threat Response Agent
======================================================
Runs a baseline LLM agent against the SOC environment over HTTP.

MANDATORY environment variables:
    API_BASE_URL   The API endpoint for the LLM.
    MODEL_NAME     The model identifier to use for inference.
    HF_TOKEN       Your Hugging Face / API key.

Usage:
    API_BASE_URL=https://router.huggingface.co/v1 \
    MODEL_NAME=meta-llama/Meta-Llama-3-8B-Instruct \
    HF_TOKEN=hf_xxx \
    python inference.py
"""

import os
import re
import json
import textwrap
from typing import Dict, List

import requests
from openai import OpenAI


# ── Configuration ────────────────────────────────────────────────────────────

API_BASE_URL = os.getenv("API_BASE_URL", "https://router.huggingface.co/v1")
API_KEY = os.getenv("HF_TOKEN") or os.getenv("API_KEY")
MODEL_NAME = os.getenv("MODEL_NAME", "meta-llama/Meta-Llama-3-8B-Instruct")
ENV_URL = os.getenv("ENV_URL", "http://localhost:8000")

TASKS = ["alert_triage", "full_investigation", "multi_alert_triage"]
EPISODES_PER_TASK = 3
TEMPERATURE = 0.1
MAX_TOKENS = 200
FALLBACK_ACTION = {"action_type": "check_user_profile", "parameters": {}}


# ── System prompt ────────────────────────────────────────────────────────────

SYSTEM_PROMPT = textwrap.dedent("""\
    You are an expert cybersecurity SOC (Security Operations Center) analyst.
    You investigate security alerts, classify threats, and take appropriate
    response actions.

    WORKFLOW:
    1. Investigate — gather evidence using investigation actions
    2. Classify  — determine if the alert is a true_positive or false_positive
    3. Respond   — if true positive, assign severity and take remediation actions
    4. Close     — close the ticket with the matching classification

    AVAILABLE ACTIONS (respond with JSON):

    Investigation (information gathering):
    - check_user_profile: Get user's department, role, risk score, etc.
    - check_login_history: Get recent login attempts with IPs and locations
    - check_ip_reputation: Check IP against threat databases. Params: {"ip": "x.x.x.x"}
    - check_device_info: Get device OS, patch status, EDR status
    - check_email_headers: Get email SPF/DKIM/DMARC results (phishing alerts only)
    - check_file_analysis: Get file hash, VirusTotal results (malware alerts only)
    - check_network_logs: Get recent network connections and data transfers
    - check_threat_intel: Get MITRE ATT&CK mapping and campaign intel

    Decision:
    - classify_alert: Params: {"classification": "true_positive" or "false_positive"}
    - assign_severity: Params: {"severity": "low" or "medium" or "high" or "critical"}

    Response (only after classifying as true_positive):
    - block_ip, block_sender_ip, disable_user_account, reset_user_password,
      isolate_device, quarantine_email, quarantine_file, send_employee_alert,
      notify_manager, escalate_to_tier2

    Close:
    - close_ticket_true_positive: Close as confirmed threat
    - close_ticket_false_positive: Close as false alarm

    RESPOND WITH EXACTLY ONE JSON OBJECT per step:
    {"action_type": "<action_name>", "parameters": {"key": "value"}}
""")


# ── Helpers ──────────────────────────────────────────────────────────────────

def _extract_observation(response: dict) -> dict:
    """Pull the observation dict from the server response.

    The server returns: {"observation": {...}, "reward": ..., "done": ...}
    We merge top-level reward/done into the observation for convenience.
    """
    obs = response.get("observation", response)
    obs["reward"] = response.get("reward", obs.get("reward"))
    obs["done"] = response.get("done", obs.get("done", False))
    return obs


def build_user_prompt(obs: dict) -> str:
    """Build the per-step user prompt from an observation dict."""
    inv = obs.get("investigation_results", {})
    inv_str = json.dumps(inv, indent=2, default=str) if inv else "None yet"

    return textwrap.dedent(f"""\
        CURRENT ALERT:
        Ticket: {obs.get('ticket_id', 'N/A')}
        Type: {obs.get('alert_type', 'N/A')} | Reported Severity: {obs.get('alert_severity', 'N/A')} | Source: {obs.get('source_tool', 'N/A')}
        Summary: {obs.get('alert_summary', 'N/A')}
        Affected User: {obs.get('affected_user', 'N/A')}
        Affected Device: {obs.get('affected_device', 'N/A')}
        Source IP: {obs.get('source_ip', 'N/A')}
        Alert {obs.get('current_alert_index', 0) + 1} of {obs.get('total_alerts', 1)}

        INVESTIGATION RESULTS:
        {inv_str}

        ACTIONS TAKEN SO FAR: {obs.get('actions_taken', [])}
        STEP: {obs.get('step_number', 0)}/{obs.get('max_steps', 20)}
        LAST MESSAGE: {obs.get('message', '')}

        What is your next action? Respond with a single JSON object.
    """)


def parse_action(response_text: str) -> dict:
    """Extract a JSON action from the LLM response text.

    Handles models that use "action_type" or "action" as the key, and
    models that nest classification/severity inside the top-level dict
    rather than in a "parameters" sub-dict.
    """
    if not response_text:
        return FALLBACK_ACTION

    def _normalize(obj: dict) -> dict:
        """Convert various LLM JSON formats to our canonical format."""
        # Accept "action" as alias for "action_type"
        if "action" in obj and "action_type" not in obj:
            obj["action_type"] = obj.pop("action")

        if "action_type" not in obj:
            return FALLBACK_ACTION

        action_type = obj["action_type"]
        params = obj.get("parameters", {})

        # Some models put classification/severity at top level or nested in "alert"
        if action_type == "classify_alert" and "classification" not in params:
            for src in [obj, obj.get("alert", {})]:
                if "classification" in src:
                    params["classification"] = src["classification"]
                    break
        if action_type == "assign_severity" and "severity" not in params:
            for src in [obj, obj.get("alert", {})]:
                if "severity" in src:
                    params["severity"] = src["severity"]
                    break
        if action_type == "check_ip_reputation" and "ip" not in params:
            if "ip" in obj:
                params["ip"] = obj["ip"]

        return {"action_type": action_type, "parameters": params}

    # Try to find any JSON object in the response
    for match in re.finditer(r'\{[^{}]*\}', response_text, re.DOTALL):
        try:
            obj = json.loads(match.group())
            if "action_type" in obj or "action" in obj:
                return _normalize(obj)
        except json.JSONDecodeError:
            continue

    # Try to parse the entire response as JSON (may have nested braces)
    try:
        obj = json.loads(response_text.strip())
        if isinstance(obj, dict) and ("action_type" in obj or "action" in obj):
            return _normalize(obj)
    except (json.JSONDecodeError, ValueError):
        pass

    return FALLBACK_ACTION


# ── Main loop ────────────────────────────────────────────────────────────────

def main():
    client = OpenAI(base_url=API_BASE_URL, api_key=API_KEY)

    print("=" * 60)
    print("Cybersecurity Threat Response Agent — Baseline Inference")
    print("=" * 60)
    print(f"Model: {MODEL_NAME}")
    print(f"Environment: {ENV_URL}")

    all_scores: Dict[str, dict] = {}

    for task in TASKS:
        print(f"\n{'─' * 40}")
        print(f"Task: {task}")
        print(f"{'─' * 40}")

        task_scores: List[float] = []

        for episode in range(EPISODES_PER_TASK):
            print(f"\nSTART task={task} episode={episode + 1}/{EPISODES_PER_TASK}")

            # Reset (use episode index as seed for reproducibility)
            resp = requests.post(
                f"{ENV_URL}/reset",
                json={"task_name": task, "seed": episode},
                timeout=30,
            )
            obs = _extract_observation(resp.json())

            messages = [{"role": "system", "content": SYSTEM_PROMPT}]
            step_count = 0
            final_reward = 0.0

            while not obs.get("done", False):
                step_count += 1
                user_prompt = build_user_prompt(obs)
                messages.append({"role": "user", "content": user_prompt})

                try:
                    completion = client.chat.completions.create(
                        model=MODEL_NAME,
                        messages=messages,
                        temperature=TEMPERATURE,
                        max_tokens=MAX_TOKENS,
                        stream=False,
                    )
                    response_text = completion.choices[0].message.content or ""
                except Exception as exc:
                    print(f"    LLM error: {exc}")
                    response_text = json.dumps(FALLBACK_ACTION)

                action = parse_action(response_text)
                messages.append({"role": "assistant", "content": json.dumps(action)})

                params_str = f" {action['parameters']}" if action.get("parameters") else ""

                # Step
                step_resp = requests.post(f"{ENV_URL}/step", json={"action": action}, timeout=30)
                obs = _extract_observation(step_resp.json())

                reward = obs.get("reward", 0.0) or 0.0
                print(f"STEP {step_count} action={action['action_type']}{params_str} reward={reward:+.3f} done={obs.get('done', False)}")

                if obs.get("done"):
                    final_reward = reward
                    break

                if step_count >= 50:
                    print("STEP safety_limit_reached")
                    break

            task_scores.append(final_reward)
            print(f"END task={task} episode={episode + 1} score={final_reward:.4f}")

        avg = sum(task_scores) / len(task_scores) if task_scores else 0.0
        all_scores[task] = {"scores": task_scores, "average": avg}
        print(f"\n  {task} average: {avg:.4f}")

    # Summary
    print(f"\n{'=' * 60}")
    print("SUMMARY")
    print("=" * 60)
    for task, data in all_scores.items():
        scores_str = ", ".join(f"{s:.4f}" for s in data["scores"])
        print(f"  {task}: {data['average']:.4f}  [{scores_str}]")

    overall = sum(d["average"] for d in all_scores.values()) / len(all_scores) if all_scores else 0.0
    print(f"\n  Overall average: {overall:.4f}")


if __name__ == "__main__":
    main()
