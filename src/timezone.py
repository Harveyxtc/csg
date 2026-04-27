"""Process-wide timezone configuration."""

from __future__ import annotations

import os
import time
from datetime import datetime
from zoneinfo import ZoneInfo


DEFAULT_TIMEZONE = "Australia/Perth"
_TIMEZONE_CACHE: ZoneInfo | None = None


def get_app_timezone() -> ZoneInfo:
    """Return the configured application timezone, defaulting to Perth."""
    global _TIMEZONE_CACHE
    if _TIMEZONE_CACHE is not None:
        return _TIMEZONE_CACHE

    timezone_name = os.environ.get("APP_TIMEZONE", DEFAULT_TIMEZONE)
    try:
        _TIMEZONE_CACHE = ZoneInfo(timezone_name)
    except Exception:
        _TIMEZONE_CACHE = ZoneInfo(DEFAULT_TIMEZONE)
    return _TIMEZONE_CACHE


def perth_now() -> datetime:
    """Return timezone-aware current datetime in the app timezone."""
    return datetime.now(get_app_timezone())


def configure_timezone() -> None:
    """Use Perth local time for process-local timestamps when supported."""
    timezone_name = os.environ.get("APP_TIMEZONE", DEFAULT_TIMEZONE)
    os.environ["TZ"] = timezone_name
    global _TIMEZONE_CACHE
    try:
        _TIMEZONE_CACHE = ZoneInfo(timezone_name)
    except Exception:
        _TIMEZONE_CACHE = ZoneInfo(DEFAULT_TIMEZONE)
    if hasattr(time, "tzset"):
        time.tzset()
