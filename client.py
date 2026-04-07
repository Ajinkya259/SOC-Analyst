"""
EnvClient for the Cybersecurity Threat Response Agent.

Used by agents or test scripts to interact with the environment
over HTTP or WebSocket via the standard OpenEnv protocol.
"""

from typing import Any, Dict

from openenv.core import EnvClient
from openenv.core.env_client import StepResult
from models import SOCAction, SOCObservation, SOCState


class SOCAnalystEnv(EnvClient[SOCAction, SOCObservation, SOCState]):
    """Client for the Cybersecurity Threat Response Agent environment."""

    def _step_payload(self, action: SOCAction) -> Dict[str, Any]:
        """Convert typed action to JSON dict for the wire."""
        return {
            "action_type": action.action_type,
            "parameters": action.parameters,
        }

    def _parse_result(self, payload: Dict[str, Any]) -> StepResult[SOCObservation]:
        """Parse the server's JSON response into a typed StepResult.

        Server returns: {"observation": {...}, "reward": float|None, "done": bool}
        """
        obs_data = payload.get("observation", {})
        return StepResult(
            observation=SOCObservation(
                done=payload.get("done", False),
                reward=payload.get("reward"),
                **obs_data,
            ),
            reward=payload.get("reward"),
            done=payload.get("done", False),
        )

    def _parse_state(self, payload: Dict[str, Any]) -> SOCState:
        """Parse the server's JSON state into a typed SOCState."""
        return SOCState(**payload)
