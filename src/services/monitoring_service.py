"""
Monitoring service helpers for background folder scan scheduling and state.
"""

import threading
from flask import current_app
from src.services.malware_event_service import run_monitor_incremental_scan

# mainly used in dir scan w/ live updates w/o refresh or intr)
# monitoring state which is mapped by username
MONITORING_STATE = {}
MONITORING_LOCK = threading.Lock()

def monitor_session_tick(username, session_id):
    ## Will only run monitoring of folder IF open in browser...(best for now)
    with MONITORING_LOCK:
        user_sessions = MONITORING_STATE.get(username, {})
        monitoring = user_sessions.get(session_id)
        if not monitoring or monitoring.get("status") != "active":
            return

    # Run scan work outside the global lock to avoid blocking other sessions.
    run_monitor_incremental_scan(
        session_id=session_id,
        monitoring=monitoring,
        username=username,
    )

def get_user_monitoring_sessions(username):
    """Return session dictionary for current user"""
    if username not in MONITORING_STATE:
        MONITORING_STATE[username] = {}
    return MONITORING_STATE[username]

def get_monitor_job_id(username, session_id):
    safe_user = username.replace(" ", "_")
    return f"monitor_{safe_user}_{session_id}"

def get_scheduler():
    scheduler = getattr(current_app, "apscheduler", None)
    if scheduler is not None:
        return scheduler
    return current_app.extensions.get("apscheduler")

def schedule_monitor_job(username, session_id, interval_seconds):
    """Schedule background scans for session"""
    scheduler = get_scheduler()
    if scheduler is None:
        return False

    seconds = max(3, int(interval_seconds))
    job_id = get_monitor_job_id(username, session_id)

    try:
        scheduler.remove_job(job_id)
    except Exception:
        pass

    scheduler.add_job(
        id=job_id,
        func=monitor_session_tick,
        trigger="interval",
        seconds=seconds,
        args=[username, session_id],
        replace_existing=True,
        max_instances=1,
        coalesce=True,
        misfire_grace_time=max(10, seconds * 2),
    )
    return True

def unschedule_monitor_job(username, session_id):
    """Remove background task """
    scheduler = get_scheduler()
    if scheduler is None:
        return

    try:
        scheduler.remove_job(get_monitor_job_id(username, session_id))
    except Exception:
        pass
