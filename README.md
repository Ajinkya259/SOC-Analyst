# Cybersecurity Threat Response Agent

An OpenEnv environment where AI agents do what SOC (Security Operations Center) analysts do every day — investigate security alerts, classify threats, take response actions, and close tickets.

Built for the **Meta PyTorch OpenEnv Hackathon** using real-world threat intelligence and interviews with a working SOC analyst.

## Motivation

Every organization with a security team runs a SOC. Analysts process hundreds of alerts daily from tools like CrowdStrike, Splunk, Microsoft Defender, and Zscaler. Most alerts are false positives, but missing a real threat can mean a data breach. This environment trains and evaluates AI agents on the core skill: **distinguishing real threats from noise, quickly and accurately.**

No cybersecurity SOC environments exist in OpenEnv today. This fills that gap with 25 scenarios based on real incidents — Cosmic Lynx BEC campaigns, QakBot fileless malware, OilRig DNS tunneling, SocGholish drive-by downloads, and more.

## Workflow

```
Alert arrives → Investigate → Classify (TP/FP) → Respond → Close ticket
```

## 25 Scenarios from Real Incidents

| Category | Count | Based On |
|---|---|---|
| Phishing | 6 | Cosmic Lynx BEC, Storm-1575 credential harvesting, TA505 vendor compromise |
| Suspicious Login | 6 | AiTM impossible travel, credential stuffing, service account abuse |
| Malware | 5 | QakBot fileless PowerShell, SocGholish drive-by, trojanized installers |
| Data Exfiltration | 4 | OilRig DNS tunneling, insider USB theft |
| Brute Force | 4 | Nobelium-style password spray, SSH brute force |

8 easy / 11 medium / 6 hard. 14 true positives / 11 false positives.

## Action Space (22 actions)

**Investigation** (8 — gather evidence):

| Action | Returns | Constraints |
|---|---|---|
| `check_user_profile` | Department, role, risk score, MFA status | — |
| `check_login_history` | Recent logins with IPs, locations, devices | — |
| `check_ip_reputation` | AbuseIPDB score, ISP, threat tags | Params: `{"ip": "x.x.x.x"}` |
| `check_device_info` | OS, patch status, EDR status, encryption | — |
| `check_email_headers` | SPF/DKIM/DMARC, sender IP, relay path | Phishing only |
| `check_file_analysis` | File hash, VT detections, C2 indicators | Malware only |
| `check_network_logs` | Connections, DNS queries, data volumes | — |
| `check_threat_intel` | MITRE ATT&CK mapping, campaign intel, IoCs | — |

**Decision** (2):
- `classify_alert` — `{"classification": "true_positive" | "false_positive"}`
- `assign_severity` — `{"severity": "low" | "medium" | "high" | "critical"}`

**Response** (10 — available after classification):
`block_ip`, `block_sender_ip`, `disable_user_account`, `reset_user_password`, `isolate_device`, `quarantine_email`, `quarantine_file`, `send_employee_alert`, `notify_manager`, `escalate_to_tier2`

**Terminal** (2):
`close_ticket_true_positive`, `close_ticket_false_positive`

## Observation Space

Each step returns a typed `SOCObservation` (Pydantic model):

| Field | Type | Description |
|---|---|---|
| `done` | `bool` | Episode ended |
| `reward` | `float` | Step reward or final grader score |
| `ticket_id` | `str` | Incident ticket ID |
| `alert_summary` | `str` | Alert description |
| `alert_type` | `str` | phishing, suspicious_login, malware_download, data_exfiltration, brute_force |
| `alert_severity` | `str` | Reported severity from detection tool |
| `source_tool` | `str` | CrowdStrike, Azure Sentinel, Zscaler, etc. |
| `affected_user` | `str` | User email/account |
| `affected_device` | `str` | Device hostname |
| `source_ip` | `str` | IP that triggered the alert |
| `investigation_results` | `dict` | Accumulated evidence |
| `actions_taken` | `list[str]` | Action history |
| `available_actions` | `list[str]` | Valid actions in current state |
| `step_number` | `int` | Current step |
| `max_steps` | `int` | Step budget |
| `message` | `str` | Environment feedback |

## Tasks & Grading

| Task | Difficulty | Budget | Objective | Scoring |
|---|---|---|---|---|
| `alert_triage` | Easy | 20 steps | Classify TP or FP | Classification 60%, investigation 25%, efficiency 15% |
| `full_investigation` | Medium | 20 steps | Classify + severity + response | Classification 30%, severity 20%, response F1 35%, investigation 15% |
| `multi_alert_triage` | Hard | 45 steps | 3 alerts sequentially | Per-alert weighted scoring, later alerts count more (25/35/40%) |

All graders are deterministic and return scores in [0.0, 1.0].

## Baseline Scores

| Task | Optimal | GPT-4o-mini | Llama-3-8B |
|---|---|---|---|
| `alert_triage` | 1.00 | 0.45 | 0.52 |
| `full_investigation` | 0.98 | 0.58 | 0.24 |
| `multi_alert_triage` | 0.96 | 0.74 | 0.01 |

GPT-4o-mini scores 2.3x higher than Llama-3-8B overall. Frontier models are expected to approach optimal (0.96+).

## Reward Shaping

Dense per-step rewards (defined in `server/constants.py`):

| Signal | Reward | Purpose |
|---|---|---|
| Correct classification | +0.15 | Core task |
| Wrong classification | -0.10 | Strong penalty |
| Early investigation (steps 1-3) | +0.05 | Investigate first |
| Relevant evidence | +0.03 | Useful investigation |
| Correct severity | +0.10 | Accuracy |
| Correct response action | +0.05 | Right remediation |
| Harmful action on FP | -0.10 | Don't disable innocent users |
| Response before classify | -0.05 | Follow workflow |

## Quick Start

```bash
pip install -r requirements.txt
export PYTHONPATH=$(pwd)

# Start server
uvicorn server.app:app --host 0.0.0.0 --port 8000

# Run inference (in another terminal)
API_BASE_URL=https://router.huggingface.co/v1 \
MODEL_NAME=meta-llama/Meta-Llama-3-8B-Instruct \
HF_TOKEN=hf_xxx \
python inference.py
```

**Docker:** `docker build -f server/Dockerfile -t soc-analyst-env . && docker run -p 8000:8000 soc-analyst-env`

**Tests:** `python -m pytest tests/ -v` (261 passing)

**Validate:** `openenv validate`

## API

| Endpoint | Method | Body |
|---|---|---|
| `/health` | GET | — |
| `/reset` | POST | `{"task_name": "alert_triage"}` |
| `/step` | POST | `{"action": {"action_type": "...", "parameters": {...}}}` |
| `/state` | GET | — |

## Environment Variables

| Variable | Default | Required |
|---|---|---|
| `API_BASE_URL` | `https://router.huggingface.co/v1` | No |
| `MODEL_NAME` | `meta-llama/Meta-Llama-3-8B-Instruct` | No |
| `HF_TOKEN` | — | Yes |
