import json
from typing import Optional, List, Dict, Any
from datetime import datetime
from app.db.database import get_db_connection
from app.core.logging import get_logger

logger = get_logger(__name__)


def create_run(
    run_id: str,
    filename: str,
    num_lines: int,
    num_incidents: int
) -> None:
    """Create a new run record."""
    with get_db_connection() as conn:
        conn.execute(
            """
            INSERT INTO runs (run_id, created_at, filename, num_lines, num_incidents)
            VALUES (?, ?, ?, ?, ?)
            """,
            (run_id, datetime.utcnow().isoformat(),
             filename, num_lines, num_incidents)
        )
        conn.commit()
    logger.info(f"Created run {run_id} for file {filename}")


def save_incident(
    incident_id: str,
    run_id: str,
    rank: int,
    signature: str,
    score: float,
    priority: str,
    severity: str,
    title: str,
    count: int,
    services: List[str],
    first_seen: Optional[str],
    last_seen: Optional[str],
    stats: Dict[str, Any],
    evidence: Dict[str, Any],
    explanation: Dict[str, Any],
    used_llm: bool,
    validation_errors: Optional[List[str]] = None
) -> None:
    """Save an incident to the database."""
    with get_db_connection() as conn:
        conn.execute(
            """
            INSERT INTO incidents (
                incident_id, run_id, rank, signature, score, priority, severity, title,
                count, services_json, first_seen, last_seen, stats_json,
                evidence_json, explanation_json, used_llm, validation_errors_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                incident_id, run_id, rank, signature, score, priority, severity, title,
                count, json.dumps(services), first_seen, last_seen,
                json.dumps(stats), json.dumps(evidence), json.dumps(explanation),
                1 if used_llm else 0,
                json.dumps(validation_errors) if validation_errors else None
            )
        )
        conn.commit()
    logger.debug(f"Saved incident {incident_id} for run {run_id}")


def get_run(run_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve a run by ID."""
    with get_db_connection() as conn:
        row = conn.execute(
            "SELECT * FROM runs WHERE run_id = ?",
            (run_id,)
        ).fetchone()

        if not row:
            return None

        return dict(row)


def get_run_with_incidents(run_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve a run with its incidents."""
    run = get_run(run_id)
    if not run:
        return None

    incidents = list_incidents_for_run(run_id)
    run['incidents'] = incidents

    return run


def get_incident(incident_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve an incident by ID with full details."""
    with get_db_connection() as conn:
        row = conn.execute(
            "SELECT * FROM incidents WHERE incident_id = ?",
            (incident_id,)
        ).fetchone()

        if not row:
            return None

        incident = dict(row)

        # Parse JSON fields
        for field in ['services_json', 'stats_json', 'evidence_json',
                      'explanation_json', 'validation_errors_json']:
            if incident.get(field):
                incident[field] = json.loads(incident[field])

        # Convert used_llm to boolean
        incident['used_llm'] = bool(incident['used_llm'])

        return incident


def list_incidents_for_run(run_id: str) -> List[Dict[str, Any]]:
    """List all incidents for a run, ordered by rank."""
    with get_db_connection() as conn:
        rows = conn.execute(
            """
            SELECT incident_id, run_id, rank, score, priority, severity, title, count,
                   services_json, first_seen, last_seen
            FROM incidents
            WHERE run_id = ?
            ORDER BY rank ASC
            """,
            (run_id,)
        ).fetchall()

        incidents = []
        for row in rows:
            incident = dict(row)
            if incident.get('services_json'):
                incident['services'] = json.loads(incident['services_json'])
                del incident['services_json']
            incidents.append(incident)

        return incidents


def list_runs(limit: int = 50) -> List[Dict[str, Any]]:
    """List recent runs."""
    with get_db_connection() as conn:
        rows = conn.execute(
            """
            SELECT run_id, created_at, filename, num_lines, num_incidents
            FROM runs
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (limit,)
        ).fetchall()

        return [dict(row) for row in rows]
