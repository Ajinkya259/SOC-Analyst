---
title: SOC Analyst Env
emoji: 🔒
colorFrom: blue
colorTo: red
sdk: docker
app_port: 8000
tags:
  - openenv
---

# Cybersecurity Threat Response Agent

An OpenEnv environment that replicates the work of a real **Security Operations Center (SOC) analyst**. The agent investigates security alerts, classifies threats as true or false positives, assigns severity, takes response actions, and closes tickets — exactly what SOC teams do 24/7 at every company.

Built for the **Meta PyTorch OpenEnv Hackathon** based on interviews with a working SOC analyst and real-world threat intelligence from documented attack campaigns.

## Motivation

Every organization with a security team runs a SOC. Analysts process hundreds of alerts daily from tools like CrowdStrike, Splunk, Microsoft Defender, and Zscaler. Most alerts are false positives, but missing a real threat can mean a data breach. This environment trains and evaluates AI agents on the core skill: **distinguishing real threats from noise, quickly and accurately.**

No cybersecurity SOC environments exist in OpenEnv today. This fills that gap with 25 scenarios based on real incidents — Cosmic Lynx BEC campaigns, QakBot fileless malware, OilRig DNS tunneling, SocGholish drive-by downloads, and more.

## How It Works

The agent receives a security alert and follows the standard SOC workflow:

1. **Investigate** — gather evidence using 8 investigation actions
2. **Classify** — determine if the alert is a `true_positive` or `false_positive`
3. **Respond** — if true positive, assign severity and take remediation actions
4. **Close** — close the ticket with the matching classification

The environment provides dense per-step reward signals that guide agents toward good SOC practices: investigate before classifying, don't over-respond to false positives, and be efficient with your step budget.

## Scenarios

25 scenarios across 5 alert categories, each with full investigation data chains, MITRE ATT&CK mappings, realistic VirusTotal detection ratios, and deterministic ground truth.

| Category | Count | TP/FP | Examples |
|---|---|---|---|
| Phishing | 6 | 3/3 | CEO impersonation (Cosmic Lynx BEC), credential harvesting (Storm-1575/Greatness PaaS), compromised vendor email (TA505) |
| Suspicious Login | 6 | 3/3 | Impossible travel (AiTM session theft), credential stuffing (rotating proxy infra), service account abuse |
| Malware | 5 | 3/2 | Fileless PowerShell (QakBot/TA570), drive-by download (SocGholish/TA569), trojanized installers |
| Data Exfiltration | 4 | 2/2 | DNS tunneling (OilRig/APT34 patterns), insider USB theft, DLP false positives |
| Brute Force | 4 | 2/2 | Internal password spray (Nobelium-style), SSH brute force, monitoring service false alarms |

**Difficulty distribution:** 8 easy, 11 medium, 6 hard. **14 true positives, 11 false positives.**

## Action Space (22 actions)

### Investigation (8 actions — gather evidence)

| Action | Description | Constraints |
|---|---|---|
| `check_user_profile` | Department, role, risk score, access level, MFA status | — |
| `check_login_history` | Recent logins with IPs, locations, devices, MFA results | — |
| `check_ip_reputation` | AbuseIPDB/VirusTotal scores, ISP, threat tags | Params: `{"ip": "x.x.x.x"}` |
| `check_device_info` | OS, patch status, EDR status, encryption | — |
| `check_email_headers` | SPF/DKIM/DMARC results, sender IP, relay path | Phishing alerts only |
| `check_file_analysis` | File hash, VT detections, behavioral analysis, C2 indicators | Malware alerts only |
| `check_network_logs` | Connections, DNS queries, data transfer volumes | — |
| `check_threat_intel` | MITRE ATT&CK mapping, campaign intel, related IoCs | — |

### Decision (2 actions — classify the alert)

| Action | Parameters |
|---|---|
| `classify_alert` | `{"classification": "true_positive"}` or `{"classification": "false_positive"}` |
| `assign_severity` | `{"severity": "low" \| "medium" \| "high" \| "critical"}` |

### Response (10 actions — available only after classification)

`block_ip`, `block_sender_ip`, `disable_user_account`, `reset_user_password`, `isolate_device`, `quarantine_email`, `quarantine_file`, `send_employee_alert`, `notify_manager`, `escalate_to_tier2`

### Terminal (2 actions — close the ticket)

`close_ticket_true_positive`, `close_ticket_false_positive`

## Observation Space

Each step returns a `SOCObservation` with these fields:

| Field | Type | Description |
|---|---|---|
| `done` | `bool` | Whether the episode has ended |
| `reward` | `float \| None` | Step reward (intermediate) or final grader score (terminal) |
| `ticket_id` | `str` | Unique incident ticket ID |
| `alert_summary` | `str` | Human-readable alert description |
| `alert_type` | `str` | Category: phishing, suspicious_login, malware_download, data_exfiltration, brute_force |
| `alert_severity` | `str` | Reported severity from the detection tool |
| `source_tool` | `str` | Detection tool (CrowdStrike, Azure Sentinel, Zscaler, etc.) |
| `affected_user` | `str` | Email/account of the affected user |
| `affected_device` | `str` | Hostname of the affected device |
| `source_ip` | `str` | IP address that triggered the alert |
| `investigation_results` | `dict` | Accumulated evidence from investigation actions |
| `actions_taken` | `list[str]` | History of all actions in this episode |
| `available_actions` | `list[str]` | Actions valid in the current state |
| `step_number` | `int` | Current step (0-indexed) |
| `max_steps` | `int` | Step budget for this task |
| `message` | `str` | Feedback message from the environment |
| `task_name` | `str` | Current task name |
| `current_alert_index` | `int` | Which alert (0-indexed) in multi-alert tasks |
| `total_alerts` | `int` | Total alerts in this episode |

## Tasks & Grading

All graders are deterministic and produce scores in `[0.0, 1.0]`.

### Task 1: `alert_triage` (Easy)

Classify a single alert as TP or FP. Pool: easy scenarios. Budget: 20 steps.

| Component | Weight | Description |
|---|---|---|
| Classification correct | 60% | Did the agent correctly identify TP vs FP? |
| Investigation thoroughness | 25% | Fraction of relevant evidence gathered |
| Step efficiency | 15% | Penalty for excess steps beyond optimal |

### Task 2: `full_investigation` (Medium)

Full end-to-end investigation: classify, assign severity, and execute correct response actions. Pool: medium scenarios. Budget: 20 steps.

| Component | Weight | Description |
|---|---|---|
| Classification correct | 30% | TP/FP accuracy |
| Severity accuracy | 20% | Graded by distance from ground truth (0.33 penalty per level off) |
| Response actions F1 | 35% | Precision and recall of response actions taken vs. required |
| Investigation thoroughness | 15% | Fraction of relevant evidence gathered |

### Task 3: `multi_alert_triage` (Hard)

Handle 3 complex alerts sequentially under a shared 45-step budget. Pool: hard scenarios. Later alerts are weighted more heavily.

| Component | Per-Alert Weight |
|---|---|
| Classification | 25% |
| Severity | 15% |
| Response actions F1 | 30% |
| Investigation thoroughness | 15% |
| Correct close action | 15% |

Alert weights: 25% / 35% / 40%. Incomplete episodes penalized: `score × (completed/3) × 0.7`.

## Reward Function

Dense per-step rewards encourage good SOC workflow (defined in `server/constants.py`):

| Signal | Reward | Purpose |
|---|---|---|
| Early investigation (steps 1–3) | +0.05 | Investigate before deciding |
| Relevant evidence found | +0.03 | Reward useful investigation |
| Irrelevant evidence | -0.01 | Discourage random actions |
| Repeated investigation | -0.02 | Don't repeat yourself |
| Correct classification | +0.15 | Core task |
| Wrong classification | -0.10 | Strong penalty |
| Correct severity | +0.10 | Accuracy matters |
| Correct response action | +0.05 | Right remediation |
| Unnecessary response | -0.05 | Don't over-respond |
| Harmful action on FP | -0.10 | Disabling a user's account when nothing is wrong is disruptive |
| Response before classify | -0.05 | Follow proper workflow |
| Step limit exceeded | -0.15 | Be efficient |

The terminal step's `reward` field contains the **final grader score** (0.0–1.0), not the cumulative step reward.

## Baseline Scores

### Optimal play (programmatic agent with perfect knowledge)

| Task | Ep 1 | Ep 2 | Ep 3 | Average |
|---|---|---|---|---|
| `alert_triage` (Easy) | 1.0000 | 1.0000 | 1.0000 | **1.0000** |
| `full_investigation` (Medium) | 0.9700 | 1.0000 | 0.9700 | **0.9800** |
| `multi_alert_triage` (Hard) | 0.9665 | 0.9640 | 0.9550 | **0.9618** |

### LLM baseline (`gpt-4o-mini`)

| Task | Ep 1 | Ep 2 | Ep 3 | Average |
|---|---|---|---|---|
| `alert_triage` (Easy) | 0.2375 | 0.2717 | 0.8375 | **0.4489** |
| `full_investigation` (Medium) | 0.2240 | 0.7000 | 0.8100 | **0.5780** |
| `multi_alert_triage` (Hard) | 0.7057 | 0.7656 | 0.7575 | **0.7429** |

### LLM baseline (`meta-llama/Meta-Llama-3-8B-Instruct`)

| Task | Ep 1 | Ep 2 | Ep 3 | Average |
|---|---|---|---|---|
| `alert_triage` (Easy) | 0.3225 | 0.3625 | 0.8675 | **0.5175** |
| `full_investigation` (Medium) | 0.4400 | 0.2340 | 0.0600 | **0.2447** |
| `multi_alert_triage` (Hard) | 0.0000 | 0.0070 | 0.0262 | **0.0111** |

The environment clearly differentiates model capability: GPT-4o-mini scores **2.3x higher overall** than Llama-3-8B (0.59 vs 0.26), with the biggest gap on the hard task (0.74 vs 0.01). The easy task is solvable by any model that follows the JSON format. The hard task's 45-step budget across 3 complex alerts with escalating weights creates genuine time-management pressure that challenges even capable models.

Frontier models are expected to approach the optimal-play scores (0.96+) consistently.

## Setup

### Prerequisites

- Python 3.10+
- `pip install -r requirements.txt`

### Run locally

```bash
# Set PYTHONPATH to the project root
export PYTHONPATH=$(pwd)

# Start the environment server
uvicorn server.app:app --host 0.0.0.0 --port 8000

# In another terminal, run inference
API_BASE_URL=https://router.huggingface.co/v1 \
MODEL_NAME=meta-llama/Meta-Llama-3-8B-Instruct \
HF_TOKEN=hf_xxx \
python inference.py
```

### Docker

```bash
docker build -f server/Dockerfile -t soc-analyst-env .
docker run -p 8000:8000 soc-analyst-env
```

### Run tests

```bash
python -m pytest tests/ -v
```

### Validate

```bash
openenv validate
```

## API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/health` | GET | Health check |
| `/reset` | POST | Start new episode. Body: `{"task_name": "alert_triage"}` |
| `/step` | POST | Execute action. Body: `{"action": {"action_type": "...", "parameters": {...}}}` |
| `/state` | GET | Current episode state |

## Project Structure

```
soc-analyst-env/
├── openenv.yaml                  # OpenEnv manifest (3 tasks + grader refs)
├── pyproject.toml                # Package config
├── requirements.txt              # Dependencies
├── README.md
├── models.py                     # SOCAction, SOCObservation, SOCState (Pydantic)
├── client.py                     # EnvClient implementation
├── inference.py                  # Baseline LLM agent (OpenAI client)
├── server/
│   ├── __init__.py
│   ├── app.py                    # FastAPI server with stateful sessions
│   ├── environment.py            # SOCEnvironment (reset/step/state)
│   ├── constants.py              # Shared reward values, severity levels
│   ├── graders.py                # 3 grading functions
│   ├── scenarios.py              # 25 scenario loader
│   ├── _scenarios_phishing.py    # 5 phishing scenarios
│   ├── _scenarios_login.py       # 5 suspicious login scenarios
│   ├── _scenarios_malware.py     # 4 malware scenarios
│   ├── _scenarios_exfil_brute.py # 6 data exfil + brute force scenarios
│   └── Dockerfile
├── tests/
│   ├── test_environment.py       # 18 tests: reset, step, edge cases
│   ├── test_graders.py           # 13 tests: scoring, boundaries, F1
│   └── test_scenarios.py         # 230 tests: data integrity for all 25 scenarios
└── .gitignore
```

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `API_BASE_URL` | `https://router.huggingface.co/v1` | LLM API endpoint |
| `MODEL_NAME` | `meta-llama/Meta-Llama-3-8B-Instruct` | Model to use for inference |
| `HF_TOKEN` | — | Hugging Face API key |
| `ENV_URL` | `http://localhost:8000` | Environment server URL |
