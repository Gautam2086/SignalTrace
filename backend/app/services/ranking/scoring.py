"""
Ranking and scoring module for incident prioritization.
Implements weighted scoring based on severity, frequency, and recency.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Tuple


class LogLevel(str, Enum):
    """Standard log severity levels."""
    FATAL = "FATAL"
    CRITICAL = "CRITICAL"
    ERROR = "ERROR"
    WARN = "WARN"
    WARNING = "WARNING"
    INFO = "INFO"
    DEBUG = "DEBUG"
    TRACE = "TRACE"
    UNKNOWN = "UNKNOWN"


class Priority(str, Enum):
    """Priority labels for incidents. P0 = highest urgency."""
    P0 = "P0"
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"


# Configurable weights for scoring components
DEFAULT_WEIGHTS: Dict[str, float] = {
    "severity": 0.50,
    "frequency": 0.30,
    "recency": 0.20,
}

# Severity scores - higher = more urgent
SEVERITY_SCORE: Dict[str, float] = {
    "FATAL": 1.0,
    "CRITICAL": 1.0,
    "ERROR": 0.9,
    "WARN": 0.5,
    "WARNING": 0.5,
    "INFO": 0.2,
    "DEBUG": 0.1,
    "TRACE": 0.1,
    "UNKNOWN": 0.2,
}


@dataclass(frozen=True)
class RankingSignals:
    """Transparent inputs to the scoring model."""
    frequency: int
    recency_minutes: float
    time_span_seconds: Optional[float]
    service_count: int


def _parse_timestamp(ts: Optional[str]) -> Optional[datetime]:
    """Parse ISO timestamp string to datetime."""
    if not ts:
        return None
    try:
        # Handle various ISO formats
        if ts.endswith('Z'):
            ts = ts[:-1] + '+00:00'
        dt = datetime.fromisoformat(ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError):
        return None


def _minutes_since(ts: datetime, now: datetime) -> float:
    """Minutes elapsed since timestamp."""
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    return max(0, (now - ts).total_seconds() / 60)


def compute_signals(
    count: int,
    severity: str,
    services: List[str],
    last_seen: Optional[str],
    time_span_seconds: Optional[float],
    now: Optional[datetime] = None
) -> RankingSignals:
    """Extract ranking signals from incident data."""
    now = now or datetime.now(timezone.utc)
    
    recency_minutes = 0.0
    if last_seen:
        last_dt = _parse_timestamp(last_seen)
        if last_dt:
            recency_minutes = _minutes_since(last_dt, now)
    
    return RankingSignals(
        frequency=count,
        recency_minutes=recency_minutes,
        time_span_seconds=time_span_seconds,
        service_count=len(services) if services else 1,
    )


def score_incident(
    severity: str,
    signals: RankingSignals,
    weights: Optional[Dict[str, float]] = None,
) -> float:
    """
    Calculate incident score using weighted components:
    - severity_score: FATAL/ERROR > WARN > INFO
    - frequency_score: log(1 + count) dampens huge counts
    - recency_score: 1 / (1 + minutes) decays over time
    - service_boost: multi-service impact = higher priority
    """
    w = weights or DEFAULT_WEIGHTS
    
    severity_score = SEVERITY_SCORE.get(severity.upper(), 0.2)
    frequency_score = math.log1p(max(0, signals.frequency)) / 5.0  # Normalize
    recency_score = 1.0 / (1.0 + signals.recency_minutes / 60)  # Decay over hours
    
    # Boost for multi-service impact
    service_boost = 1.0 + (0.1 * (signals.service_count - 1)) if signals.service_count > 1 else 1.0
    
    base_score = (
        w["severity"] * severity_score
        + w["frequency"] * frequency_score
        + w["recency"] * recency_score
    )
    
    return float(base_score * service_boost)


def priority_from_score(score: float) -> Priority:
    """Map score to priority label."""
    if score >= 0.75:
        return Priority.P0
    if score >= 0.55:
        return Priority.P1
    if score >= 0.35:
        return Priority.P2
    return Priority.P3


def rank_incidents(
    incidents: List[dict],
    weights: Optional[Dict[str, float]] = None,
) -> List[dict]:
    """
    Rank incidents by computed score.
    
    Input: list of incident dicts with count, severity, services, last_seen, time_span_seconds
    Output: same list sorted by score, with score/priority/rank added
    """
    now = datetime.now(timezone.utc)
    scored: List[Tuple[float, dict]] = []
    
    for inc in incidents:
        signals = compute_signals(
            count=inc.get("count", 1),
            severity=inc.get("severity", "UNKNOWN"),
            services=inc.get("services", []),
            last_seen=inc.get("last_seen"),
            time_span_seconds=inc.get("time_span_seconds"),
            now=now,
        )
        
        score = score_incident(
            severity=inc.get("severity", "UNKNOWN"),
            signals=signals,
            weights=weights,
        )
        
        priority = priority_from_score(score)
        
        enriched = {
            **inc,
            "score": round(score, 4),
            "priority": priority.value,
            "signals": {
                "frequency": signals.frequency,
                "recency_minutes": round(signals.recency_minutes, 1),
                "service_count": signals.service_count,
            },
        }
        scored.append((score, enriched))
    
    # Sort by score descending
    scored.sort(key=lambda x: x[0], reverse=True)
    
    # Assign ranks
    ranked = []
    for i, (_, inc) in enumerate(scored, start=1):
        inc["rank"] = i
        ranked.append(inc)
    
    return ranked


def select_for_llm(ranked_incidents: List[dict], top_n: int = 5) -> List[dict]:
    """Select top N incidents for LLM explanation."""
    return ranked_incidents[:max(0, int(top_n))]

