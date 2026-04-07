"""
FastAPI app for the Cybersecurity Threat Response Agent.

Uses a custom server (not create_fastapi_app) because the OpenEnv default HTTP
server is stateless — it creates a new environment per request. Our SOC environment
requires state to persist across reset → step → step → close within an episode.

The serialize_observation format is:
    {"observation": {...custom fields...}, "reward": float|None, "done": bool}
"""

from typing import Any, Dict

from fastapi import Body, FastAPI

from openenv.core.env_server import serialize_observation, deserialize_action
from server.environment import SOCEnvironment
from models import SOCAction

app = FastAPI(title="Cybersecurity Threat Response Agent")

# Session store — maps session_id to a persistent SOCEnvironment instance
_sessions: Dict[str, SOCEnvironment] = {}


def _get_or_create_env(session_id: str = "default") -> SOCEnvironment:
    """Get an existing session or create a new one."""
    if session_id not in _sessions:
        _sessions[session_id] = SOCEnvironment()
    return _sessions[session_id]


@app.get("/")
async def root() -> Dict[str, str]:
    """Root endpoint."""
    return {
        "name": "Cybersecurity Threat Response Agent",
        "status": "running",
        "endpoints": ["/health", "/reset", "/step", "/state"],
    }


@app.get("/health")
async def health() -> Dict[str, str]:
    """Health check."""
    return {"status": "healthy"}


@app.post("/reset")
async def reset(request: Dict[str, Any] = Body(default={})) -> Dict[str, Any]:
    """Reset the environment and return the initial observation."""
    session_id = request.get("session_id", "default")
    env = _get_or_create_env(session_id)

    task_name = request.get("task_name", "alert_triage")
    seed = request.get("seed", None)
    episode_id = request.get("episode_id", None)

    observation = env.reset(seed=seed, episode_id=episode_id, task_name=task_name)
    return serialize_observation(observation)


@app.post("/step")
async def step(request: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    """Execute one action and return the resulting observation."""
    session_id = request.get("session_id", "default")
    env = _get_or_create_env(session_id)

    action_data = request.get("action", request)
    action = deserialize_action(action_data, SOCAction)

    observation = env.step(action)
    return serialize_observation(observation)


@app.get("/state")
async def get_state(session_id: str = "default") -> Dict[str, Any]:
    """Return current episode state."""
    env = _get_or_create_env(session_id)
    return env.state.model_dump()


def main():
    """Run the server with uvicorn."""
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)


if __name__ == "__main__":
    main()
