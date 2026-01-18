#grouping.py - Takes clean log cards and puts matching ones into the same pile.

from __future__ import annotations
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Tuple
from .parser import LogRecord


# Normalization rules to create a stable signature:
# Replace UUIDs, numbers, IPs, hex, durations, etc.
DURATION_RE = re.compile(r"\b\d+\s*ms\b", re.IGNORECASE)
UUID_RE = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b")
HEX_RE = re.compile(r"\b0x[0-9a-fA-F]+\b")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
NUMBER_RE = re.compile(r"\b\d+\b")
WHITESPACE_RE = re.compile(r"\s+")

# As an optional: trim very long stack traces or multi-line messages.
MAX_MSG_LEN = 400

# Turns a log message into a stable template signature, with this it helps to group repeated errors that differ only by ids, numbers, etc.
def normalize_message(msg: str) -> str:
    s = msg.strip()
    if not s:
        return "empty_message"

    # Keep it single-line and bounded length for stable signatures
    s = s.replace("\n", " ")
    if len(s) > MAX_MSG_LEN:
        s = s[:MAX_MSG_LEN] + "…"

    s = UUID_RE.sub("<uuid>", s)
    s = IP_RE.sub("<ip>", s)
    s = HEX_RE.sub("<hex>", s)
    s = DURATION_RE.sub("<timeout>", s)
    s = NUMBER_RE.sub("<num>", s)

    s = WHITESPACE_RE.sub(" ", s).strip()
    return s.lower()


# This function is basically extracts the error or short name, it is used to display in UI.
def extract_error_signature(msg: str) -> str:
    """
    Try to extract a compact 'error type' for UI display.
    Example: 'TokenExpiredException: blah' -> 'TokenExpiredException'
    """
    m = re.match(r"^([A-Za-z_]\w*(?:Exception|Error|Fault))\b", msg.strip())
    if m:
        return m.group(1)
    # fallback to first ~6 words
    tokens = msg.strip().split()
    return " ".join(tokens[:6]) if tokens else "unknown_error"


# Bucket of similar logs
@dataclass
class LogGroup:
    group_id: str
    service: str
    level: str
    error_signature: str
    normalized_message: str
    count: int
    timestamps: List[datetime]
    sample_messages: List[str]


def build_group_id(service: str, normalized_message: str) -> str:
    base = f"{service}::{normalized_message}"
    # Keep it filesystem / UI safe (simple)
    return re.sub(r"[^a-zA-Z0-9:_\-]+", "_", base)[:120]


# Sorting the LogRecords by grouping them first.
def group_logs(records: List[LogRecord]) -> List[LogGroup]:
    """
    Grouping:
    key = (service, level_bucket, normalized_message)
    """
    buckets: Dict[Tuple[str, str, str], List[LogRecord]] = {}
    for r in records:
        service = r.service or "unknown"
        level = (r.level or "UNKNOWN").upper()
        # Bucket WARNING into WARN
        if level == "WARNING":
            level = "WARN"

        norm = normalize_message(r.message)
        key = (service, level, norm)
        buckets.setdefault(key, []).append(r)

    groups: List[LogGroup] = []
    for (service, level, norm), items in buckets.items():
        items_sorted = sorted(items, key=lambda x: x.timestamp)
        sig = extract_error_signature(items_sorted[0].message) if items_sorted else "unknown_error"

        # Sample messages: keep up to 3 distinct raw messages
        seen = set()
        samples: List[str] = []
        for it in items_sorted:
            msg = it.message.strip()
            if msg and msg not in seen:
                samples.append(msg[:300])
                seen.add(msg)
            if len(samples) >= 3:
                break

        gid = build_group_id(service, norm)

        groups.append(
            LogGroup(
                group_id=gid,
                service=service,
                level=level,
                error_signature=sig,
                normalized_message=norm,
                count=len(items),
                timestamps=[it.timestamp for it in items_sorted],
                sample_messages=samples,
            )
        )

    # Sort by frequency desc, then recency desc
    groups.sort(key=lambda g: (g.count, max(g.timestamps) if g.timestamps else datetime.min), reverse=True)
    return groups
