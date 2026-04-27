"""Client used by Flask routes to interact with the email analysis agent."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
AGENT_HOST = os.environ.get("EMAIL_AGENT_HOST", "127.0.0.1")
AGENT_PORT = int(os.environ.get("EMAIL_AGENT_PORT", "8766"))
AGENT_BASE_URL = os.environ.get("EMAIL_AGENT_URL", f"http://{AGENT_HOST}:{AGENT_PORT}")
AGENT_TIMEOUT = float(os.environ.get("EMAIL_AGENT_TIMEOUT", "5"))
AGENT_STARTUP_TIMEOUT = float(os.environ.get("EMAIL_AGENT_STARTUP_TIMEOUT", "10"))
AGENT_AUTOSTART = os.environ.get("EMAIL_AGENT_AUTOSTART", "true").strip().lower() not in {
    "0",
    "false",
    "no",
    "off",
}
AGENT_LOG_PATH = os.environ.get(
    "EMAIL_AGENT_LOG_PATH",
    os.path.join(tempfile.gettempdir(), "ppd_email_agent.log"),
)
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
    log_dir = os.path.dirname(AGENT_LOG_PATH)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)
    with open(AGENT_LOG_PATH, "a", encoding="utf-8", errors="replace") as log_file:
        log_file.write(f"\n=== Email agent startup attempt {time.strftime('%Y-%m-%d %H:%M:%S')} ===\n")
        AGENT_PROCESS = subprocess.Popen(
            command,
            cwd=PROJECT_DIR,
            env=env,
            stdout=log_file,
            stderr=log_file,
            creationflags=creationflags,
        )

    deadline = time.time() + max(3.0, AGENT_STARTUP_TIMEOUT)
    while time.time() < deadline:
        if is_agent_available():
            return
        if AGENT_PROCESS.poll() is not None:
            break
        time.sleep(0.15)

    exit_code = AGENT_PROCESS.poll()
    if exit_code is not None:
        raise EmailAgentError(
            "Local email agent exited during startup "
            f"(code {exit_code}). Check log: {AGENT_LOG_PATH}"
        )

    raise EmailAgentError(
        "Local email agent did not start within "
        f"{max(3.0, AGENT_STARTUP_TIMEOUT):.1f}s. Check log: {AGENT_LOG_PATH}"
    )


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
