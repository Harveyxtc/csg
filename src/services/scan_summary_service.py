"""Runtime malware scan summary aggregation for the active app process."""

from __future__ import annotations

import threading
from src.timezone import perth_now


_SUMMARY_LOCK = threading.Lock()
_APP_STARTED_AT = perth_now()
_RUNTIME_SUMMARY = {
    "total_files_scanned": 0,
    "infected_files": 0,
    "data_scanned_bytes": 0,
    "total_scan_seconds": 0.0,
    "scan_count": 0,
    "engine_version": "-",
    "known_viruses": "-",
    "first_scan_at": None,
    "last_scan_at": None,
}


def _parse_size_to_bytes(size_text):
    if not size_text:
        return 0

    try:
        value_text = str(size_text).split("(", 1)[0].strip()
        number_text, unit = value_text.split(maxsplit=1)
        number = float(number_text)
    except (AttributeError, TypeError, ValueError):
        return 0

    multipliers = {
        "B": 1,
        "KB": 1000,
        "MB": 1000 ** 2,
        "GB": 1000 ** 3,
        "KIB": 1024,
        "MIB": 1024 ** 2,
        "GIB": 1024 ** 3,
    }
    return int(number * multipliers.get(unit.strip().upper(), 1))


def _parse_seconds(duration_text):
    if not duration_text:
        return 0.0

    try:
        return float(str(duration_text).split()[0])
    except (TypeError, ValueError, IndexError):
        return 0.0


def _format_bytes(byte_count):
    units = ["B", "KiB", "MiB", "GiB"]
    value = float(max(0, int(byte_count)))
    for unit in units:
        if value < 1024 or unit == units[-1]:
            if unit == "B":
                return f"{int(value)} {unit}"
            return f"{value:.2f} {unit}"
        value /= 1024
    return "0 B"


def _format_duration(seconds_value):
    seconds_value = max(0.0, float(seconds_value))
    if seconds_value < 1:
        return f"{seconds_value:.3f} sec"
    if seconds_value < 60:
        return f"{seconds_value:.2f} sec"
    minutes = int(seconds_value // 60)
    seconds = seconds_value % 60
    return f"{minutes}m {seconds:04.1f}s"


def record_scan_result(scan_result):
    """Record one completed malware scan result into runtime totals."""
    if not scan_result or not scan_result.get("success"):
        return

    summary = scan_result.get("scan_summary") or {}
    status = str(scan_result.get("status", "")).strip().lower()
    signature = str(scan_result.get("signature", "")).strip().lower()
    infected = status == "infected" or (signature and signature not in {"none", "unknown_signature"})
    timestamp = scan_result.get("timestamp") or perth_now().isoformat()

    with _SUMMARY_LOCK:
        _RUNTIME_SUMMARY["total_files_scanned"] += 1
        _RUNTIME_SUMMARY["infected_files"] += 1 if infected else 0
        _RUNTIME_SUMMARY["data_scanned_bytes"] += _parse_size_to_bytes(summary.get("Data scanned"))
        _RUNTIME_SUMMARY["total_scan_seconds"] += _parse_seconds(summary.get("Time"))
        _RUNTIME_SUMMARY["scan_count"] += 1

        engine_version = summary.get("Engine version")
        known_viruses = summary.get("Known viruses")
        if engine_version:
            _RUNTIME_SUMMARY["engine_version"] = engine_version
        if known_viruses:
            _RUNTIME_SUMMARY["known_viruses"] = str(known_viruses)

        if _RUNTIME_SUMMARY["first_scan_at"] is None:
            _RUNTIME_SUMMARY["first_scan_at"] = timestamp
        _RUNTIME_SUMMARY["last_scan_at"] = timestamp


def get_runtime_scan_summary():
    with _SUMMARY_LOCK:
        scan_count = max(0, int(_RUNTIME_SUMMARY["scan_count"]))
        average_seconds = (_RUNTIME_SUMMARY["total_scan_seconds"] / scan_count) if scan_count else 0.0
        return {
            "Total Files Scanned": str(_RUNTIME_SUMMARY["total_files_scanned"]),
            "Infected Files": str(_RUNTIME_SUMMARY["infected_files"]),
            "Data Scanned": _format_bytes(_RUNTIME_SUMMARY["data_scanned_bytes"]),
            "Engine Version": _RUNTIME_SUMMARY["engine_version"],
            "Known Viruses": _RUNTIME_SUMMARY["known_viruses"],
            "Average Scan Duration": _format_duration(average_seconds),
            "Runtime Started": _APP_STARTED_AT.strftime("%Y-%m-%d %H:%M:%S"),
            "First Scan": _RUNTIME_SUMMARY["first_scan_at"] or "-",
            "Last Scan": _RUNTIME_SUMMARY["last_scan_at"] or "-",
            "Scan Mode": "Runtime aggregate",
            "Scans Recorded": str(scan_count),
        }

