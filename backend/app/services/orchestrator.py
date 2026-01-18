import uuid
import time
from datetime import datetime
from typing import Dict, Any, List
from app.core.logging import get_logger
from app.db.crud import create_run, save_incident
from app.models.schemas import AnalyzeResponse, IncidentSummary
from app.services.pipeline_interfaces import (
    parse_lines, group_and_rank, build_evidence, generate_incident_id
)
from app.services.guardrails import get_validated_explanation
from app.services.ranking import priority_from_score, compute_signals, score_incident

logger = get_logger(__name__)


class PipelineTimings:
    """Track timing metrics for pipeline stages."""

    def __init__(self):
        self.start_time = time.time()
        self.parse_ms: float = 0
        self.triage_ms: float = 0
        self.evidence_ms: float = 0
        self.llm_ms: float = 0
        self.persist_ms: float = 0
        self.total_ms: float = 0

    def log_summary(self, request_id: str):
        self.total_ms = (time.time() - self.start_time) * 1000
        logger.info(
            f"[{request_id}] Pipeline completed - "
            f"parse: {self.parse_ms:.1f}ms, "
            f"triage: {self.triage_ms:.1f}ms, "
            f"evidence: {self.evidence_ms:.1f}ms, "
            f"llm: {self.llm_ms:.1f}ms, "
            f"persist: {self.persist_ms:.1f}ms, "
            f"total: {self.total_ms:.1f}ms"
        )


def analyze_log_file(file_bytes: bytes, filename: str) -> AnalyzeResponse:
    """
    Main pipeline orchestration for log file analysis.

    Stages:
    1. Decode and parse lines
    2. Group and rank into incidents
    3. Build evidence for each incident
    4. Get explanation (LLM or fallback)
    5. Persist to database
    6. Return response
    """
    run_id = str(uuid.uuid4())
    request_id = run_id[:8]
    timings = PipelineTimings()

    logger.info(f"[{request_id}] Starting analysis for {filename}")

    try:
        # Stage 1: Decode and parse lines
        t0 = time.time()
        raw_text = _decode_file(file_bytes)
        lines = raw_text.split('\n')
        parsed_lines = parse_lines(lines)
        timings.parse_ms = (time.time() - t0) * 1000

        logger.info(
            f"[{request_id}] Parsed {len(parsed_lines)} lines from {len(lines)} raw lines")

        if not parsed_lines:
            # Empty or unparseable file
            return _create_empty_response(run_id, filename, len(lines))

        # Stage 2: Group and rank into incidents
        t0 = time.time()
        incident_groups = group_and_rank(parsed_lines)
        timings.triage_ms = (time.time() - t0) * 1000

        logger.info(
            f"[{request_id}] Created {len(incident_groups)} incident groups")

        # Stage 3 & 4: Build evidence and get explanations
        t0 = time.time()
        processed_incidents: List[Dict[str, Any]] = []

        for rank, group in enumerate(incident_groups, start=1):
            evidence = build_evidence(group)
            timings.evidence_ms += (time.time() - t0) * 1000

            # Get explanation with LLM or fallback
            t_llm = time.time()
            explanation, used_llm, validation_errors = get_validated_explanation(
                evidence, group.signature
            )
            timings.llm_ms += (time.time() - t_llm) * 1000

            incident_id = generate_incident_id(run_id, group.signature, rank)

            # Calculate score using ranking module
            signals = compute_signals(
                count=group.count,
                severity=group.severity,
                services=group.services,
                last_seen=group.time_window.last_seen,
                time_span_seconds=evidence.stats.time_span_seconds,
            )
            score = score_incident(group.severity, signals)
            priority = priority_from_score(score)

            processed_incidents.append({
                'incident_id': incident_id,
                'run_id': run_id,
                'rank': rank,
                'signature': group.signature,
                'score': round(score, 4),
                'priority': priority.value,
                'severity': group.severity,
                'title': explanation.incident_title,
                'count': group.count,
                'services': group.services,
                'first_seen': group.time_window.first_seen,
                'last_seen': group.time_window.last_seen,
                'stats': evidence.stats.model_dump(),
                'evidence': evidence.model_dump(),
                'explanation': explanation.model_dump(),
                'used_llm': used_llm,
                'validation_errors': validation_errors
            })

            t0 = time.time()  # Reset for next evidence build

        # Stage 5: Persist to database
        t0 = time.time()
        _persist_run(run_id, filename, len(lines), processed_incidents)
        timings.persist_ms = (time.time() - t0) * 1000

        # Log timing summary
        timings.log_summary(request_id)

        # Stage 6: Build response
        return AnalyzeResponse(
            run_id=run_id,
            created_at=datetime.utcnow().isoformat(),
            filename=filename,
            num_lines=len(lines),
            num_incidents=len(processed_incidents),
            incidents=[
    IncidentSummary(
                    incident_id=inc['incident_id'],
                    rank=inc['rank'],
                    score=inc['score'],
                    priority=inc['priority'],
                    severity=inc['severity'],
                    title=inc['title'],
                    count=inc['count'],
                    services=inc['services'],
                    first_seen=inc['first_seen'],
                    last_seen=inc['last_seen']
                )
                for inc in processed_incidents
            ]
        )

    except Exception as e:
        logger.error(f"[{request_id}] Pipeline failed: {e}", exc_info=True)
        raise


def _decode_file(file_bytes: bytes) -> str:
    """Decode file bytes to string with fallback encodings."""
    encodings = ['utf-8', 'utf-8-sig', 'latin-1', 'cp1252']

    for encoding in encodings:
        try:
            return file_bytes.decode(encoding)
        except UnicodeDecodeError:
            continue

    # Last resort: decode with replacement
    return file_bytes.decode('utf-8', errors='replace')


# _calculate_score removed - now using ranking module


def _persist_run(
    run_id: str,
    filename: str,
    num_lines: int,
    incidents: List[Dict[str, Any]]
) -> None:
    """Persist run and incidents to database."""
    # Create run record
    create_run(
        run_id=run_id,
        filename=filename,
        num_lines=num_lines,
        num_incidents=len(incidents)
    )

    # Save each incident
    for inc in incidents:
        save_incident(
            incident_id=inc['incident_id'],
            run_id=run_id,
            rank=inc['rank'],
            signature=inc['signature'],
            score=inc['score'],
            priority=inc['priority'],
            severity=inc['severity'],
            title=inc['title'],
            count=inc['count'],
            services=inc['services'],
            first_seen=inc['first_seen'],
            last_seen=inc['last_seen'],
            stats=inc['stats'],
            evidence=inc['evidence'],
            explanation=inc['explanation'],
            used_llm=inc['used_llm'],
            validation_errors=inc['validation_errors']
        )


def _create_empty_response(run_id: str, filename: str, num_lines: int) -> AnalyzeResponse:
    """Create response for empty/unparseable files."""
    # Still persist the run
    create_run(
        run_id=run_id,
        filename=filename,
        num_lines=num_lines,
        num_incidents=0
    )

    return AnalyzeResponse(
        run_id=run_id,
        created_at=datetime.utcnow().isoformat(),
        filename=filename,
        num_lines=num_lines,
        num_incidents=0,
        incidents=[]
    )
