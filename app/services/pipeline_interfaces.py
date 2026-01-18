import re
import json
import hashlib
from typing import List, Dict, Optional
from datetime import datetime
from collections import defaultdict
from app.models.schemas import (
    ParsedLogLine, IncidentGroup, TimeWindow,
    EvidenceBundle, SampleLine, IncidentStats
)

# Regex patterns for log parsing
TIMESTAMP_PATTERNS = [
    r'(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)',
    r'(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})',
    r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})',
]

LOG_LEVEL_PATTERN = r'\b(ERROR|WARN(?:ING)?|INFO|DEBUG|FATAL|CRITICAL|TRACE)\b'
SERVICE_PATTERN = r'\[([a-zA-Z0-9_\-\.]+)\]'

# Normalization patterns for signature generation
UUID_PATTERN = r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
HEX_PATTERN = r'\b[0-9a-fA-F]{16,}\b'
IP_PATTERN = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
NUMBER_PATTERN = r'\b\d+\b'
PATH_PATTERN = r'/[a-zA-Z0-9_\-\./]+'

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
    
    Attempts JSON parsing first, then falls back to regex-based parsing.
    This is a placeholder implementation - teammates can improve parsing logic.
    """
    parsed = []
    
    for i, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line:
            continue
        
        parsed_line = _try_parse_json(line, i, raw_line)
        if not parsed_line:
            parsed_line = _parse_with_regex(line, i, raw_line)
        
        parsed.append(parsed_line)
    
    return parsed


def _try_parse_json(line: str, line_number: int, raw_line: str) -> Optional[ParsedLogLine]:
    """Try to parse line as JSON log entry."""
    try:
        data = json.loads(line)
        if not isinstance(data, dict):
            return None
        
        # Extract common JSON log fields
        timestamp = data.get('timestamp') or data.get('time') or data.get('@timestamp') or data.get('ts')
        level = data.get('level') or data.get('severity') or data.get('log_level')
        service = data.get('service') or data.get('app') or data.get('logger') or data.get('name')
        message = data.get('message') or data.get('msg') or data.get('text') or str(data)
        
        if level:
            level = level.upper()
        
        return ParsedLogLine(
            line_number=line_number,
            timestamp=str(timestamp) if timestamp else None,
            service=str(service) if service else None,
            level=level,
            message=str(message),
            raw_line=raw_line
        )
    except (json.JSONDecodeError, TypeError):
        return None


def _parse_with_regex(line: str, line_number: int, raw_line: str) -> ParsedLogLine:
    """Parse line using regex patterns."""
    timestamp = None
    for pattern in TIMESTAMP_PATTERNS:
        match = re.search(pattern, line)
        if match:
            timestamp = match.group(1)
            break
    
    level_match = re.search(LOG_LEVEL_PATTERN, line, re.IGNORECASE)
    level = level_match.group(1).upper() if level_match else None
    
    service_match = re.search(SERVICE_PATTERN, line)
    service = service_match.group(1) if service_match else None
    
    # Message is the remaining content after removing known parts
    message = line
    if timestamp:
        message = message.replace(timestamp, '', 1)
    if level:
        message = re.sub(LOG_LEVEL_PATTERN, '', message, count=1, flags=re.IGNORECASE)
    if service:
        message = message.replace(f'[{service}]', '', 1)
    message = re.sub(r'^[\s\-:]+', '', message).strip()
    
    if not message:
        message = line
    
    return ParsedLogLine(
        line_number=line_number,
        timestamp=timestamp,
        service=service,
        level=level,
        message=message,
        raw_line=raw_line
    )


def _normalize_message(message: str) -> str:
    """Normalize a message to create a grouping signature."""
    normalized = message
    normalized = re.sub(UUID_PATTERN, '{UUID}', normalized)
    normalized = re.sub(HEX_PATTERN, '{HEX}', normalized)
    normalized = re.sub(IP_PATTERN, '{IP}', normalized)
    normalized = re.sub(NUMBER_PATTERN, '{N}', normalized)
    # Truncate for grouping
    return normalized[:200]


def _get_signature_hash(signature: str) -> str:
    """Create a short hash for the signature."""
    return hashlib.md5(signature.encode()).hexdigest()[:12]


def group_and_rank(parsed: List[ParsedLogLine]) -> List[IncidentGroup]:
    """
    Group related log entries into incidents and rank by severity/count.
    
    Groups by normalized message signature, ranks by count × severity weight.
    This is a placeholder implementation - teammates can improve grouping logic.
    """
    groups: Dict[str, List[ParsedLogLine]] = defaultdict(list)
    
    for log in parsed:
        signature = _normalize_message(log.message)
        groups[signature].append(log)
    
    incidents = []
    for signature, lines in groups.items():
        # Determine severity (highest level in group)
        severities = [line.level for line in lines if line.level]
        if severities:
            severity = max(severities, key=lambda s: SEVERITY_WEIGHTS.get(s, 0))
        else:
            severity = 'INFO'
        
        # Collect timestamps for time window
        timestamps = [line.timestamp for line in lines if line.timestamp]
        time_window = TimeWindow()
        if timestamps:
            sorted_ts = sorted(timestamps)
            time_window = TimeWindow(first_seen=sorted_ts[0], last_seen=sorted_ts[-1])
        
        # Collect unique services
        services = list(set(line.service for line in lines if line.service))
        
        incidents.append(IncidentGroup(
            signature=signature,
            lines=lines,
            count=len(lines),
            severity=severity,
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
    This is a placeholder implementation - teammates can improve evidence selection.
    """
    lines = group.lines
    
    # Select sample lines: first, last, and distributed middle points
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
    
    # Top unique messages (deduplicated)
    seen_messages = set()
    top_messages = []
    for line in lines:
        if line.message not in seen_messages and len(top_messages) < 5:
            top_messages.append(line.message)
            seen_messages.add(line.message)
    
    # Compute stats
    error_count = sum(1 for line in lines if line.level in ('ERROR', 'FATAL', 'CRITICAL'))
    warn_count = sum(1 for line in lines if line.level in ('WARN', 'WARNING'))
    
    # Calculate time span
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
    """Select indices for representative samples."""
    if total <= max_samples:
        return list(range(total))
    
    # Always include first and last
    indices = [0, total - 1]
    
    # Add evenly distributed middle points
    remaining = max_samples - 2
    step = total / (remaining + 1)
    for i in range(1, remaining + 1):
        idx = int(i * step)
        if idx not in indices:
            indices.append(idx)
    
    return sorted(set(indices))[:max_samples]


def _parse_timestamp(ts: str) -> Optional[datetime]:
    """Try to parse timestamp string to datetime."""
    formats = [
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


def generate_incident_id(run_id: str, signature: str, rank: int) -> str:
    """Generate a unique incident ID."""
    sig_hash = _get_signature_hash(signature)
    return f"{run_id[:8]}-{sig_hash}-{rank}"
