from typing import List
from app.models.schemas import (
    EvidenceBundle, IncidentExplanation, LikelyCause
)


def generate_fallback_explanation(
    evidence: EvidenceBundle,
    signature: str
) -> IncidentExplanation:
    """
    Generate a deterministic fallback explanation when LLM is unavailable or fails.
    
    This ensures the system works without an LLM key and provides demo safety.
    """
    # Generate title from signature
    title = _generate_title(signature, evidence)
    
    # Generate what happened description
    what_happened = _generate_what_happened(evidence, signature)
    
    # Generate likely causes based on patterns
    likely_causes = _generate_likely_causes(evidence)
    
    # Generate next steps
    next_steps = _generate_next_steps(evidence)
    
    # Collect all referenced line numbers
    referenced_lines = [line.line_number for line in evidence.sample_lines]
    
    return IncidentExplanation(
        incident_title=title,
        what_happened=what_happened,
        likely_causes=likely_causes,
        recommended_next_steps=next_steps,
        confidence="low",
        caveats=[
            "This is an automated analysis without LLM assistance",
            "Manual review recommended for accurate root cause identification"
        ],
        referenced_line_numbers=referenced_lines
    )


def _generate_title(signature: str, evidence: EvidenceBundle) -> str:
    """Generate a short title for the incident."""
    severity = "Error" if evidence.stats.error_count > 0 else "Warning" if evidence.stats.warn_count > 0 else "Issue"
    
    # Extract key phrase from signature
    key_phrase = signature[:60]
    if len(signature) > 60:
        key_phrase += "..."
    
    # Clean up placeholder markers
    key_phrase = key_phrase.replace('{N}', 'N').replace('{UUID}', 'ID').replace('{IP}', 'IP').replace('{HEX}', 'hex')
    
    services_str = ""
    if evidence.services:
        services_str = f" in {', '.join(evidence.services[:2])}"
    
    return f"{severity}: {key_phrase}{services_str}"


def _generate_what_happened(evidence: EvidenceBundle, signature: str) -> str:
    """Generate a description of what happened."""
    stats = evidence.stats
    
    parts = [
        f"Detected {stats.total_count} occurrence(s) of this pattern."
    ]
    
    if stats.error_count > 0:
        parts.append(f"{stats.error_count} were ERROR level.")
    if stats.warn_count > 0:
        parts.append(f"{stats.warn_count} were WARNING level.")
    
    if stats.services:
        parts.append(f"Affected services: {', '.join(stats.services)}.")
    
    if stats.time_span_seconds is not None:
        if stats.time_span_seconds < 60:
            parts.append(f"Time span: {stats.time_span_seconds:.1f} seconds.")
        elif stats.time_span_seconds < 3600:
            parts.append(f"Time span: {stats.time_span_seconds / 60:.1f} minutes.")
        else:
            parts.append(f"Time span: {stats.time_span_seconds / 3600:.1f} hours.")
    
    if evidence.time_window.first_seen:
        parts.append(f"First seen: {evidence.time_window.first_seen}.")
    
    return " ".join(parts)


def _generate_likely_causes(evidence: EvidenceBundle) -> List[LikelyCause]:
    """Generate likely causes based on log patterns."""
    causes = []
    sample_lines = evidence.sample_lines
    line_numbers = [line.line_number for line in sample_lines]
    
    # Check for common error patterns
    all_messages = " ".join(line.message.lower() for line in sample_lines)
    
    if any(kw in all_messages for kw in ['connection', 'connect', 'timeout', 'refused']):
        causes.append(LikelyCause(
            hypothesis="Network connectivity issue or service unavailable",
            evidence_line_numbers=line_numbers[:2]
        ))
    
    if any(kw in all_messages for kw in ['memory', 'heap', 'oom', 'out of memory']):
        causes.append(LikelyCause(
            hypothesis="Memory exhaustion or memory leak",
            evidence_line_numbers=line_numbers[:2]
        ))
    
    if any(kw in all_messages for kw in ['null', 'undefined', 'none', 'nil']):
        causes.append(LikelyCause(
            hypothesis="Null reference or missing data",
            evidence_line_numbers=line_numbers[:2]
        ))
    
    if any(kw in all_messages for kw in ['permission', 'denied', 'forbidden', 'unauthorized', '403', '401']):
        causes.append(LikelyCause(
            hypothesis="Permission or authentication issue",
            evidence_line_numbers=line_numbers[:2]
        ))
    
    if any(kw in all_messages for kw in ['disk', 'storage', 'space', 'quota']):
        causes.append(LikelyCause(
            hypothesis="Storage capacity or disk issue",
            evidence_line_numbers=line_numbers[:2]
        ))
    
    if any(kw in all_messages for kw in ['database', 'sql', 'query', 'db']):
        causes.append(LikelyCause(
            hypothesis="Database connectivity or query issue",
            evidence_line_numbers=line_numbers[:2]
        ))
    
    # Default cause if no patterns matched
    if not causes:
        causes.append(LikelyCause(
            hypothesis="Application error requiring manual investigation",
            evidence_line_numbers=line_numbers[:2] if line_numbers else []
        ))
    
    return causes[:3]  # Limit to top 3 causes


def _generate_next_steps(evidence: EvidenceBundle) -> List[str]:
    """Generate recommended next steps."""
    steps = []
    
    # Always recommend reviewing logs
    steps.append("Review the sample log entries for detailed error context")
    
    if evidence.services:
        steps.append(f"Check health and metrics for: {', '.join(evidence.services)}")
    
    if evidence.stats.error_count > 10:
        steps.append("High error count - consider immediate investigation")
    
    if evidence.stats.time_span_seconds and evidence.stats.time_span_seconds < 60:
        steps.append("Rapid occurrence - check for cascading failures")
    
    steps.append("Search for related incidents in monitoring systems")
    steps.append("Correlate with recent deployments or configuration changes")
    
    return steps[:5]  # Limit to 5 steps
