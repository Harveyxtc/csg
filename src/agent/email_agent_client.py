"""Client used by Flask routes to interact with the email analysis agent."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
AGENT_HOST = os.environ.get("EMAIL_AGENT_HOST", "127.0.0.1")
AGENT_PORT = int(os.environ.get("EMAIL_AGENT_PORT", "8766"))
AGENT_BASE_URL = os.environ.get("EMAIL_AGENT_URL", f"http://{AGENT_HOST}:{AGENT_PORT}")
AGENT_TIMEOUT = float(os.environ.get("EMAIL_AGENT_TIMEOUT", "5"))
AGENT_AUTOSTART = os.environ.get("EMAIL_AGENT_AUTOSTART", "true").strip().lower() not in {
    "0",
    "false",
    "no",
    "off",
}
AGENT_PROCESS: subprocess.Popen | None = None


class EmailAgentError(RuntimeError):
    """Raised when the local email agent cannot serve a request."""


def ensure_agent_running() -> None:
    """Start the local email agent if it is not already answering health checks."""
    global AGENT_PROCESS

    if is_agent_available():
        return

    if not AGENT_AUTOSTART:
        raise EmailAgentError(
            f"Local email agent is not running at {AGENT_BASE_URL}. "
            "Start it with: python -m src.agent.email_agent"
        )

    env = os.environ.copy()
    env["PYTHONPATH"] = PROJECT_DIR + os.pathsep + env.get("PYTHONPATH", "")
    command = [
        sys.executable,
        "-m",
        "src.agent.email_agent",
        "--host",
        AGENT_HOST,
        "--port",
        str(AGENT_PORT),
    ]
    creationflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    AGENT_PROCESS = subprocess.Popen(
        command,
        cwd=PROJECT_DIR,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=creationflags,
    )

    deadline = time.time() + 4
    while time.time() < deadline:
        if is_agent_available():
            return
        time.sleep(0.15)

    raise EmailAgentError("Local email agent did not start")


def is_agent_available() -> bool:
    try:
        request_json("GET", "/health", ensure_running=False, timeout=1)
        return True
    except Exception:
        return False


def request_json(
    method: str,
    path: str,
    payload: dict[str, Any] | None = None,
    username: str | None = None,
    ensure_running: bool = True,
    timeout: float | None = None,
) -> tuple[dict[str, Any], int]:
    if ensure_running:
        ensure_agent_running()

    body = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if username:
        headers["X-PPD-Username"] = username

    request = Request(
        f"{AGENT_BASE_URL}{path}",
        data=body,
        method=method.upper(),
        headers=headers,
    )

    try:
        with urlopen(request, timeout=timeout or AGENT_TIMEOUT) as response:
            response_body = response.read().decode("utf-8")
            return json.loads(response_body or "{}"), response.status
    except HTTPError as error:
        response_body = error.read().decode("utf-8")
        try:
            return json.loads(response_body or "{}"), error.code
        except json.JSONDecodeError:
            return {"success": False, "error": response_body or str(error)}, error.code
    except URLError as error:
        raise EmailAgentError(f"Local email agent is unavailable: {error}") from error

