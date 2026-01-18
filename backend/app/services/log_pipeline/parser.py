# parser.py - Reads every messy log and turns it into a clean card with time, service, level, and message.

from __future__ import annotations
import json
import re
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


LEVELS = {"TRACE", "DEBUG", "INFO", "WARN", "WARNING", "ERROR", "FATAL", "CRITICAL"}

# You can think of this as a clean log card, No matter how messy the log is, we force it into this shape.
@dataclass(frozen=True)
class LogRecord:
    timestamp: datetime
    service: str
    level: str
    message: str
    raw: str

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat()
        return d


# Logs write time in different formats, we try with multiple formats and then convert into one standard time.
def _parse_timestamp(ts: str) -> Optional[datetime]:
    """
    Best-effort timestamp parsing:
    - ISO 8601: 2026-01-17T14:32:10Z or 2026-01-17T14:32:10+00:00
    - Common:   2026-01-17 14:32:10
    Returns aware datetime in UTC when possible.
    """
    ts = ts.strip()
    if not ts:
        return None

    # We need to normalize 'Z' to '+00:00' for fromisoformat
    if ts.endswith("Z"):
        ts_iso = ts[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(ts_iso)
            return dt.astimezone(timezone.utc)
        except ValueError:
            pass

    # Next case is trying with pure ISO-8601
    try:
        dt = datetime.fromisoformat(ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except ValueError:
        pass

    # This is the final case "YYYY-mm-dd HH:MM:SS"
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S"):
        try:
            dt = datetime.strptime(ts, fmt).replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue

    return None


# It takes the log line and parse it if JSON else returns None
def _try_parse_json_line(line: str) -> Optional[Dict[str, Any]]:
    line = line.strip()
    if not line or not (line.startswith("{") and line.endswith("}")):
        return None
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        return None

# We extract different information out from a JSON log, if anything is missed we can just return with unknown.
def _extract_from_json(obj: Dict[str, Any], raw_line: str) -> LogRecord:
    # Common key fallbacks
    ts_raw = (
        obj.get("timestamp")
        or obj.get("time")
        or obj.get("@timestamp")
        or obj.get("ts")
        or ""
    )
    lvl = (obj.get("level") or obj.get("severity") or obj.get("log_level") or "UNKNOWN")
    svc = (obj.get("service") or obj.get("svc") or obj.get("app") or obj.get("component") or "unknown")
    msg = (obj.get("message") or obj.get("msg") or obj.get("event") or obj.get("error") or raw_line).strip()

    dt = _parse_timestamp(str(ts_raw)) or datetime.now(timezone.utc)

    lvl = str(lvl).upper()
    if lvl == "WARNING":
        lvl = "WARN"

    return LogRecord(
        timestamp=dt,
        service=str(svc).strip() or "unknown",
        level=lvl,
        message=msg,
        raw=raw_line.rstrip("\n"),
    )


# Plain-text log regex:
# Example: 2026-01-17 14:32:10 ERROR auth-service TokenExpiredException: ...
TEXT_LOG_RE = re.compile(
    r"""
    ^
    (?P<date>\d{4}[-/]\d{2}[-/]\d{2})      # YYYY-mm-dd or YYYY/mm/dd
    [ T]
    (?P<time>\d{2}:\d{2}:\d{2})            # HH:MM:SS
    (?:\.\d+)?                             # optional .ms
    \s+
    (?P<level>[A-Za-z]+)                   # level
    \s+
    (?P<service>[\w\-.\/]+)                # service token
    \s+
    (?P<message>.*)                        # rest
    $
    """,
    re.VERBOSE,
)

# We extract the information from plain text, if regex is failed we still create LogRecord with "unknown"
def _extract_from_text(line: str) -> LogRecord:
    raw = line.rstrip("\n")
    m = TEXT_LOG_RE.match(raw.strip())
    if m:
        ts = f"{m.group('date')} {m.group('time')}"
        dt = _parse_timestamp(ts) or datetime.now(timezone.utc)
        lvl = m.group("level").upper()
        if lvl == "WARNING":
            lvl = "WARN"
        svc = m.group("service").strip() or "unknown"
        msg = (m.group("message") or "").strip() or raw.strip()
        return LogRecord(timestamp=dt, service=svc, level=lvl, message=msg, raw=raw)

    # Try to find a level token anywhere, else UNKNOWN
    tokens = raw.strip().split()
    lvl = "UNKNOWN"
    for t in tokens:
        ut = t.upper()
        if ut in LEVELS:
            lvl = "WARN" if ut == "WARNING" else ut
            break

    return LogRecord(
        timestamp=datetime.now(timezone.utc),
        service="unknown",
        level=lvl,
        message=raw.strip(),
        raw=raw,
    )


# Main reader, reads each log line by line, return the list of LogRecord objects based on JSON or text format.
def parse_logs_from_text(log_text: str) -> List[LogRecord]:
    records: List[LogRecord] = []
    for line in log_text.splitlines():
        if not line.strip():
            continue
        obj = _try_parse_json_line(line)
        if obj is not None and isinstance(obj, dict):
            records.append(_extract_from_json(obj, line))
        else:
            records.append(_extract_from_text(line))
    return records


def parse_logs_from_file(path: str) -> List[LogRecord]:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return parse_logs_from_text(f.read())
