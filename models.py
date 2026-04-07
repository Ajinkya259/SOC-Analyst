"""
Pydantic models for the Cybersecurity Threat Response Agent.

Defines the typed Action, Observation, and State that flow between
the agent and the environment via the OpenEnv protocol.
"""

from typing import Any, Dict, List, Optional

from pydantic import Field
from openenv.core.env_server import Action, Observation, State


class SOCAction(Action):
    """An action taken by the SOC analyst agent."""

    action_type: str = ""
    parameters: Dict[str, str] = Field(default_factory=dict)


class SOCObservation(Observation):
    """What the agent sees after each step.

    Inherited from Observation: done (bool), reward (float | None), metadata (dict).
    """

    # Alert context
    ticket_id: str = ""
    alert_summary: str = ""
    alert_type: str = ""
    alert_severity: str = ""
    source_tool: str = ""
    affected_user: str = ""
    affected_device: str = ""
    source_ip: str = ""

    # Accumulated evidence and history
    investigation_results: Dict[str, Any] = Field(default_factory=dict)
    actions_taken: List[str] = Field(default_factory=list)
    available_actions: List[str] = Field(default_factory=list)

    # Progress
    step_number: int = 0
    max_steps: int = 20
    message: str = ""
    task_name: str = ""
    current_alert_index: int = 0
    total_alerts: int = 1


class SOCState(State):
    """Internal episode state tracked by the environment.

    Inherited from State: episode_id (str | None), step_count (int).
    """

    task_name: str = ""
    scenario_id: str = ""
    current_alert_index: int = 0
    total_alerts: int = 1
    classification: Optional[str] = None
    severity_assigned: Optional[str] = None
    response_actions_taken: List[str] = Field(default_factory=list)
    investigation_actions_taken: List[str] = Field(default_factory=list)
    alerts_completed: int = 0
    cumulative_reward: float = 0.0
