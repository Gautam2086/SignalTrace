#summarizer.py - Writes a short report for each problem. Basically we turn the log groups into incident summaries.

from __future__ import annotations
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Any, Dict, List
from .grouping import LogGroup

# This is the final incident card used for UI, backend store.
@dataclass(frozen=True)
class IncidentSummary:
    incident_id: str
    service: str
    level: str
    error: str
    count: int
    first_seen: str
    last_seen: str
    time_window_minutes: int
    sample_messages: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _minutes_between(a: datetime, b: datetime) -> int:
    return max(0, int((b - a).total_seconds() // 60))


# Here, we take the LogGroups and then create IncidentSummary objects.
def summarize_groups(groups: List[LogGroup], top_k: int = 20) -> List[IncidentSummary]:
    summaries: List[IncidentSummary] = []

    for g in groups[:top_k]:
        if not g.timestamps:
            continue

        first_dt = min(g.timestamps)
        last_dt = max(g.timestamps)
        window_mins = _minutes_between(first_dt, last_dt)

        summaries.append(
            IncidentSummary(
                incident_id=g.group_id,
                service=g.service,
                level=g.level,
                error=g.error_signature,
                count=g.count,
                first_seen=first_dt.isoformat(),
                last_seen=last_dt.isoformat(),
                time_window_minutes=window_mins,
                sample_messages=g.sample_messages,
            )
        )

    return summaries
