"""
Pipeline interfaces for log parsing, grouping, and evidence collection.
Converts raw log lines into structured incidents for analysis.
"""
import hashlib
from typing import List, Optional
from datetime import datetime

from app.models.schemas import (
    ParsedLogLine, IncidentGroup, TimeWindow,
    EvidenceBundle, SampleLine, IncidentStats
)
from app.services.log_pipeline import (
    parse_logs_from_text, group_logs, normalize_message
)
from app.services.log_pipeline.parser import LogRecord
from app.services.log_pipeline.grouping import LogGroup

SEVERITY_WEIGHTS = {
    'FATAL': 100,
    'CRITICAL': 90,
    'ERROR': 50,
    'WARN': 20,
    'WARNING': 20,
    'INFO': 5,
    'DEBUG': 1,
    'TRACE': 1,
}


def parse_lines(lines: List[str]) -> List[ParsedLogLine]:
    """
    Parse raw log lines into structured ParsedLogLine objects.
    Supports JSON and plain-text log formats with line number tracking.
    """
    raw_text = "\n".join(lines)
    log_records = parse_logs_from_text(raw_text)
    
    # Build line number mapping for evidence grounding
    line_to_number = {}
    for i, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped:
            line_to_number[stripped] = i
    
    parsed = []
    for record in log_records:
        line_number = line_to_number.get(record.raw.strip(), 0)
        if line_number == 0:
            line_number = len(parsed) + 1
        
        parsed.append(ParsedLogLine(
            line_number=line_number,
            timestamp=record.timestamp.isoformat() if record.timestamp else None,
            service=record.service if record.service != "unknown" else None,
            level=record.level if record.level != "UNKNOWN" else None,
            message=record.message,
            raw_line=record.raw
        ))
    
    return parsed


def group_and_rank(parsed: List[ParsedLogLine]) -> List[IncidentGroup]:
    """
    Group related log entries into incidents and rank by severity and frequency.
    Uses message normalization to cluster similar errors together.
    """
    log_records = []
    
    for p in parsed:
        ts = datetime.utcnow()
        if p.timestamp:
            ts = _parse_timestamp(p.timestamp) or datetime.utcnow()
        
        record = LogRecord(
            timestamp=ts,
            service=p.service or "unknown",
            level=p.level or "UNKNOWN",
            message=p.message,
            raw=p.raw_line
        )
        log_records.append(record)
    
    log_groups = group_logs(log_records)
    
    incidents = []
    for lg in log_groups:
        group_lines = []
        for rec in [r for r in log_records if normalize_message(r.message) == lg.normalized_message 
                    and r.service == lg.service and r.level == lg.level]:
            for p in parsed:
                if p.raw_line == rec.raw:
                    group_lines.append(p)
                    break
        
        seen = set()
        unique_lines = []
        for line in group_lines:
            key = (line.line_number, line.raw_line)
            if key not in seen:
                seen.add(key)
                unique_lines.append(line)
        
        # Build time window
        timestamps = [l.timestamp for l in unique_lines if l.timestamp]
        time_window = TimeWindow()
        if timestamps:
            sorted_ts = sorted(timestamps)
            time_window = TimeWindow(first_seen=sorted_ts[0], last_seen=sorted_ts[-1])
        
        services = list(set(l.service for l in unique_lines if l.service))
        
        incidents.append(IncidentGroup(
            signature=lg.normalized_message,
            lines=unique_lines,
            count=lg.count,
            severity=lg.level,
            time_window=time_window,
            services=services
        ))
    
    # Rank by score (count × severity weight)
    incidents.sort(
        key=lambda x: x.count * SEVERITY_WEIGHTS.get(x.severity, 1),
        reverse=True
    )
    
    return incidents


def build_evidence(group: IncidentGroup, max_samples: int = 8) -> EvidenceBundle:
    """
    Build evidence bundle for an incident group.
    Selects representative sample lines and computes statistics.
    """
    lines = group.lines
    sample_indices = _select_sample_indices(len(lines), max_samples)
    sample_lines = [
        SampleLine(
            line_number=lines[i].line_number,
            timestamp=lines[i].timestamp,
            service=lines[i].service,
            level=lines[i].level,
            message=lines[i].message,
            raw_line=lines[i].raw_line
        )
        for i in sample_indices
    ]

    seen_messages = set()
    top_messages = []
    for line in lines:
        if line.message not in seen_messages and len(top_messages) < 5:
            top_messages.append(line.message)
            seen_messages.add(line.message)

    error_count = sum(1 for line in lines if line.level in ('ERROR', 'FATAL', 'CRITICAL'))
    warn_count = sum(1 for line in lines if line.level in ('WARN', 'WARNING'))

    time_span_seconds = None
    if group.time_window.first_seen and group.time_window.last_seen:
        try:
            first = _parse_timestamp(group.time_window.first_seen)
            last = _parse_timestamp(group.time_window.last_seen)
            if first and last:
                time_span_seconds = (last - first).total_seconds()
        except:
            pass

    stats = IncidentStats(
        total_count=group.count,
        error_count=error_count,
        warn_count=warn_count,
        services=group.services,
        time_span_seconds=time_span_seconds
    )

    return EvidenceBundle(
        sample_lines=sample_lines,
        top_messages=top_messages,
        time_window=group.time_window,
        services=group.services,
        stats=stats
    )


def _select_sample_indices(total: int, max_samples: int) -> List[int]:
    """Select evenly distributed sample indices."""
    if total <= max_samples:
        return list(range(total))

    indices = [0, total - 1]
    remaining = max_samples - 2
    step = total / (remaining + 1)
    for i in range(1, remaining + 1):
        idx = int(i * step)
        if idx not in indices:
            indices.append(idx)

    return sorted(set(indices))[:max_samples]


def _parse_timestamp(ts: str) -> Optional[datetime]:
    """Parse timestamp string to datetime object."""
    formats = [
        '%Y-%m-%dT%H:%M:%S.%f%z',
        '%Y-%m-%dT%H:%M:%S%z',
        '%Y-%m-%dT%H:%M:%S.%fZ',
        '%Y-%m-%dT%H:%M:%SZ',
        '%Y-%m-%dT%H:%M:%S.%f',
        '%Y-%m-%dT%H:%M:%S',
        '%Y-%m-%d %H:%M:%S.%f',
        '%Y-%m-%d %H:%M:%S',
    ]
    for fmt in formats:
        try:
            return datetime.strptime(ts, fmt)
        except ValueError:
            continue
    return None


def _get_signature_hash(signature: str) -> str:
    """Create a short hash for the signature."""
    return hashlib.md5(signature.encode()).hexdigest()[:12]


def generate_incident_id(run_id: str, signature: str, rank: int) -> str:
    """Generate a unique incident ID."""
    sig_hash = _get_signature_hash(signature)
    return f"{run_id[:8]}-{sig_hash}-{rank}"
