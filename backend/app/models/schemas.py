from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any, Literal
from datetime import datetime


# ============================================================================
# Log Parsing Models
# ============================================================================

class ParsedLogLine(BaseModel):
    """A single parsed log line."""
    line_number: int
    timestamp: Optional[str] = None
    service: Optional[str] = None
    level: Optional[str] = None
    message: str
    raw_line: str


# ============================================================================
# Incident Grouping Models
# ============================================================================

class TimeWindow(BaseModel):
    """Time range for an incident."""
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None


class IncidentGroup(BaseModel):
    """A group of related log entries forming an incident."""
    signature: str
    lines: List[ParsedLogLine]
    count: int
    severity: str
    time_window: TimeWindow
    services: List[str] = Field(default_factory=list)


# ============================================================================
# Evidence Models
# ============================================================================

class SampleLine(BaseModel):
    """A sample log line for evidence."""
    line_number: int
    timestamp: Optional[str] = None
    service: Optional[str] = None
    level: Optional[str] = None
    message: str
    raw_line: str


class IncidentStats(BaseModel):
    """Statistics for an incident."""
    total_count: int
    error_count: int = 0
    warn_count: int = 0
    services: List[str] = Field(default_factory=list)
    time_span_seconds: Optional[float] = None


class EvidenceBundle(BaseModel):
    """Evidence collected for an incident."""
    sample_lines: List[SampleLine]
    top_messages: List[str] = Field(default_factory=list)
    time_window: TimeWindow
    services: List[str] = Field(default_factory=list)
    stats: IncidentStats


# ============================================================================
# LLM Explanation Models
# ============================================================================

class LikelyCause(BaseModel):
    """A hypothesis about the incident cause."""
    hypothesis: str
    evidence_line_numbers: List[int] = Field(default_factory=list)


class IncidentExplanation(BaseModel):
    """LLM-generated or fallback explanation for an incident."""
    incident_title: str
    what_happened: str
    likely_causes: List[LikelyCause] = Field(default_factory=list)
    recommended_next_steps: List[str] = Field(default_factory=list)
    confidence: Literal["low", "medium", "high"] = "low"
    caveats: List[str] = Field(default_factory=list)
    referenced_line_numbers: List[int] = Field(default_factory=list)


class ValidationResult(BaseModel):
    """Validation metadata for an incident."""
    used_llm: bool
    errors: List[str] = Field(default_factory=list)


# ============================================================================
# API Response Models
# ============================================================================

class IncidentSummary(BaseModel):
    """Incident summary for list views."""
    incident_id: str
    rank: int
    score: float
    priority: str = "P3"  # P0=critical, P1=high, P2=medium, P3=low
    severity: str
    title: str
    count: int
    services: List[str]
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None


class IncidentDetail(BaseModel):
    """Full incident detail for GET /incidents/{id}."""
    incident_id: str
    run_id: str
    signature: str
    rank: int
    score: float
    severity: str
    title: str
    count: int
    stats: IncidentStats
    evidence: EvidenceBundle
    explanation: IncidentExplanation
    validation: ValidationResult


class AnalyzeResponse(BaseModel):
    """Response from POST /api/analyze."""
    run_id: str
    created_at: str
    filename: str
    num_lines: int
    num_incidents: int
    incidents: List[IncidentSummary]


class RunSummary(BaseModel):
    """Run summary for list views."""
    run_id: str
    created_at: str
    filename: str
    num_lines: int
    num_incidents: int


class RunDetail(BaseModel):
    """Run detail with incidents."""
    run_id: str
    created_at: str
    filename: str
    num_lines: int
    num_incidents: int
    incidents: List[IncidentSummary]


class HealthResponse(BaseModel):
    """Health check response."""
    status: str = "ok"
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())


class ErrorResponse(BaseModel):
    """Standard error response."""
    detail: str
    request_id: Optional[str] = None

