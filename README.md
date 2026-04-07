# Cybersecurity Threat Response Agent

An OpenEnv environment where AI agents do what SOC (Security Operations Center) analysts do every day — investigate security alerts, classify threats, take response actions, and close tickets.

Built for the **Meta PyTorch OpenEnv Hackathon** using real-world threat intelligence and interviews with a working SOC analyst.

## Workflow

```
Alert arrives → Investigate → Classify (TP/FP) → Respond → Close ticket
```

1. **Investigate** — 8 evidence-gathering actions (user profile, login history, IP reputation, device info, email headers, file analysis, network logs, threat intel)
2. **Classify** — `true_positive` or `false_positive`
3. **Respond** — assign severity + take remediation actions (block IP, isolate device, quarantine file, etc.)
4. **Close** — `close_ticket_true_positive` or `close_ticket_false_positive`

## 25 Scenarios from Real Incidents

| Category | Count | Based On |
|---|---|---|
| Phishing | 6 | Cosmic Lynx BEC, Storm-1575 credential harvesting, TA505 vendor compromise |
| Suspicious Login | 6 | AiTM impossible travel, credential stuffing, service account abuse |
| Malware | 5 | QakBot fileless PowerShell, SocGholish drive-by, trojanized installers |
| Data Exfiltration | 4 | OilRig DNS tunneling, insider USB theft |
| Brute Force | 4 | Nobelium-style password spray, SSH brute force |

8 easy / 11 medium / 6 hard. 14 true positives / 11 false positives.

## 3 Tasks

| Task | Difficulty | Budget | What the agent must do |
|---|---|---|---|
| `alert_triage` | Easy | 20 steps | Classify a single alert as TP or FP |
| `full_investigation` | Medium | 20 steps | Classify + assign severity + take correct response actions |
| `multi_alert_triage` | Hard | 45 steps | Handle 3 complex alerts sequentially under time pressure |

All graders are deterministic, return scores in [0.0, 1.0], and use multi-dimensional scoring (classification accuracy, severity distance, response action F1, investigation thoroughness, step efficiency).

## Baseline Scores

| Task | Optimal | GPT-4o-mini | Llama-3-8B |
|---|---|---|---|
| `alert_triage` | 1.00 | 0.45 | 0.52 |
| `full_investigation` | 0.98 | 0.58 | 0.24 |
| `multi_alert_triage` | 0.96 | 0.74 | 0.01 |

The environment clearly differentiates model capability — GPT-4o-mini scores 2.3x higher than Llama-3-8B overall. Frontier models are expected to approach optimal scores (0.96+).

## Reward Shaping

Dense per-step rewards guide agents toward correct SOC workflow:

- **+0.15** correct classification / **-0.10** wrong
- **+0.05** early investigation bonus / **+0.03** relevant evidence
- **+0.10** correct severity / **+0.05** correct response action
- **-0.10** harmful action on false positive (e.g. disabling an innocent user's account)
- **-0.05** response before classifying

All reward constants defined in `server/constants.py`.

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

**Docker:**
```bash
docker build -f server/Dockerfile -t soc-analyst-env .
docker run -p 8000:8000 soc-analyst-env
```

**Tests:** `python -m pytest tests/ -v` (261 passing)

**Validate:** `openenv validate`

## API

| Endpoint | Method | Body |
|---|---|---|
| `/health` | GET | — |
| `/reset` | POST | `{"task_name": "alert_triage"}` |
| `/step` | POST | `{"action": {"action_type": "...", "parameters": {...}}}` |
| `/state` | GET | — |

## Project Structure

```
├── inference.py              # Baseline LLM agent (OpenAI client)
├── models.py                 # SOCAction, SOCObservation, SOCState
├── client.py                 # EnvClient implementation
├── openenv.yaml              # 3 tasks with grader references
├── server/
│   ├── environment.py        # SOCEnvironment (reset/step/state)
│   ├── graders.py            # 3 deterministic grading functions
│   ├── constants.py          # Named reward values
│   ├── scenarios.py          # 25 scenario loader
│   ├── app.py                # FastAPI server
│   └── Dockerfile
└── tests/                    # 261 tests (environment, graders, scenario integrity)
```

## Environment Variables

| Variable | Default | Required |
|---|---|---|
| `API_BASE_URL` | `https://router.huggingface.co/v1` | No |
| `MODEL_NAME` | `meta-llama/Meta-Llama-3-8B-Instruct` | No |
| `HF_TOKEN` | — | Yes |
