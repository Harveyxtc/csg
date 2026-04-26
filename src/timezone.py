"""Process-wide timezone configuration."""

from __future__ import annotations

import os
import time


DEFAULT_TIMEZONE = "Australia/Perth"


def configure_timezone() -> None:
    """Use Perth local time for process-local timestamps when supported."""
    os.environ["TZ"] = os.environ.get("APP_TIMEZONE", DEFAULT_TIMEZONE)
    if hasattr(time, "tzset"):
        time.tzset()
