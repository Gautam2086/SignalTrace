from fastapi import APIRouter, UploadFile, File, HTTPException
from typing import List
from app.models.schemas import (
    AnalyzeResponse, RunSummary, RunDetail, IncidentDetail,
    IncidentSummary, IncidentStats, EvidenceBundle, SampleLine,
    TimeWindow, IncidentExplanation, LikelyCause, ValidationResult,
    HealthResponse, ErrorResponse
)
from app.services.orchestrator import analyze_log_file
from app.db.crud import get_run, get_incident, list_runs, list_incidents_for_run
from app.core.logging import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/api", tags=["api"])


@router.post(
    "/analyze",
    response_model=AnalyzeResponse,
    responses={
        400: {"model": ErrorResponse, "description": "Invalid file"},
        500: {"model": ErrorResponse, "description": "Processing error"}
    }
)
async def analyze_logs(file: UploadFile = File(...)):
    """
    Upload and analyze a log file.

    Accepts multipart file upload, processes through the pipeline,
    and returns incident analysis results.
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided")

    try:
        # Read file bytes
        file_bytes = await file.read()

        if len(file_bytes) == 0:
            raise HTTPException(status_code=400, detail="Empty file")

        logger.info(
            f"Received file: {file.filename}, size: {len(file_bytes)} bytes")

        # Run analysis pipeline
        response = analyze_log_file(file_bytes, file.filename)

        return response

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Analysis failed: {e}", exc_info=True)
        raise HTTPException(
            status_code=500, detail=f"Analysis failed: {str(e)}")


@router.get(
    "/runs",
    response_model=List[RunSummary],
    responses={
        500: {"model": ErrorResponse, "description": "Database error"}
    }
)
async def get_runs():
    """
    List recent analysis runs.

    Returns up to 50 most recent runs ordered by creation time.
    """
    try:
        runs = list_runs(limit=50)
        return [
            RunSummary(
                run_id=run['run_id'],
                created_at=run['created_at'],
                filename=run['filename'],
                num_lines=run['num_lines'],
                num_incidents=run['num_incidents']
            )
            for run in runs
        ]
    except Exception as e:
        logger.error(f"Failed to list runs: {e}", exc_info=True)
        raise HTTPException(
            status_code=500, detail=f"Failed to list runs: {str(e)}")


@router.get(
    "/runs/{run_id}",
    response_model=RunDetail,
    responses={
        404: {"model": ErrorResponse, "description": "Run not found"},
        500: {"model": ErrorResponse, "description": "Database error"}
    }
)
async def get_run_detail(run_id: str):
    """
    Get run details with incident summary.

    Returns run metadata and list of incidents ordered by rank.
    """
    try:
        run = get_run(run_id)
        if not run:
            raise HTTPException(
                status_code=404, detail=f"Run not found: {run_id}")

        incidents = list_incidents_for_run(run_id)

        return RunDetail(
            run_id=run['run_id'],
            created_at=run['created_at'],
            filename=run['filename'],
            num_lines=run['num_lines'],
            num_incidents=run['num_incidents'],
            incidents=[
                IncidentSummary(
                    incident_id=inc['incident_id'],
                    rank=inc['rank'],
                    score=inc['score'],
                    priority=inc.get('priority', 'P3'),
                    severity=inc['severity'],
                    title=inc['title'],
                    count=inc['count'],
                    services=inc.get('services', []),
                    first_seen=inc.get('first_seen'),
                    last_seen=inc.get('last_seen')
                )
                for inc in incidents
            ]
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get run {run_id}: {e}", exc_info=True)
        raise HTTPException(
            status_code=500, detail=f"Failed to get run: {str(e)}")


@router.get(
    "/runs/{run_id}/incidents/{incident_id}",
    response_model=IncidentDetail,
    responses={
        404: {"model": ErrorResponse, "description": "Incident not found"},
        500: {"model": ErrorResponse, "description": "Database error"}
    }
)
async def get_incident_detail(run_id: str, incident_id: str):
    """
    Get full incident details with evidence and explanation.

    Returns complete incident data including sample logs, statistics,
    LLM or fallback explanation, and validation metadata.
    """
    try:
        incident = get_incident(incident_id)

        if not incident:
            raise HTTPException(
                status_code=404, detail=f"Incident not found: {incident_id}")

        if incident['run_id'] != run_id:
            raise HTTPException(
                status_code=404, detail=f"Incident not found in run: {run_id}")

        # Parse stored JSON data
        stats_data = incident.get('stats_json', {})
        evidence_data = incident.get('evidence_json', {})
        explanation_data = incident.get('explanation_json', {})
        validation_errors = incident.get('validation_errors_json', [])

        # Build response models
        stats = IncidentStats(
            total_count=stats_data.get('total_count', incident['count']),
            error_count=stats_data.get('error_count', 0),
            warn_count=stats_data.get('warn_count', 0),
            services=stats_data.get('services', []),
            time_span_seconds=stats_data.get('time_span_seconds')
        )

        # Build sample lines
        sample_lines = [
            SampleLine(
                line_number=line.get('line_number', 0),
                timestamp=line.get('timestamp'),
                service=line.get('service'),
                level=line.get('level'),
                message=line.get('message', ''),
                raw_line=line.get('raw_line', '')
            )
            for line in evidence_data.get('sample_lines', [])
        ]

        # Build time window
        time_window_data = evidence_data.get('time_window', {})
        time_window = TimeWindow(
            first_seen=time_window_data.get('first_seen'),
            last_seen=time_window_data.get('last_seen')
        )

        evidence = EvidenceBundle(
            sample_lines=sample_lines,
            top_messages=evidence_data.get('top_messages', []),
            time_window=time_window,
            services=evidence_data.get('services', []),
            stats=stats
        )

        # Build likely causes
        likely_causes = [
            LikelyCause(
                hypothesis=cause.get('hypothesis', ''),
                evidence_line_numbers=cause.get('evidence_line_numbers', [])
            )
            for cause in explanation_data.get('likely_causes', [])
        ]

        explanation = IncidentExplanation(
            incident_title=explanation_data.get(
                'incident_title', incident['title']),
            what_happened=explanation_data.get('what_happened', ''),
            likely_causes=likely_causes,
            recommended_next_steps=explanation_data.get(
                'recommended_next_steps', []),
            confidence=explanation_data.get('confidence', 'low'),
            caveats=explanation_data.get('caveats', []),
            referenced_line_numbers=explanation_data.get(
                'referenced_line_numbers', [])
        )

        validation = ValidationResult(
            used_llm=incident.get('used_llm', False),
            errors=validation_errors if validation_errors else []
        )

        return IncidentDetail(
            incident_id=incident['incident_id'],
            run_id=incident['run_id'],
            signature=incident['signature'],
            rank=incident['rank'],
            score=incident['score'],
            severity=incident['severity'],
            title=incident['title'],
            count=incident['count'],
            stats=stats,
            evidence=evidence,
            explanation=explanation,
            validation=validation
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            f"Failed to get incident {incident_id}: {e}", exc_info=True)
        raise HTTPException(
            status_code=500, detail=f"Failed to get incident: {str(e)}")


@router.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint."""
    return HealthResponse()
