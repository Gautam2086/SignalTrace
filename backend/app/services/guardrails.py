import json
from typing import Tuple, List, Optional, Dict, Any
from pydantic import ValidationError
from app.models.schemas import EvidenceBundle, IncidentExplanation, LikelyCause
from app.services.llm_client import explain_incident, fix_json_with_llm
from app.services.fallback import generate_fallback_explanation
from app.core.logging import get_logger

logger = get_logger(__name__)


def get_validated_explanation(
    evidence: EvidenceBundle,
    signature: str
) -> Tuple[IncidentExplanation, bool, List[str]]:
    """
    Get a validated incident explanation.

    Attempts LLM call with validation and retry, falls back to deterministic if needed.

    Returns:
        Tuple of (explanation, used_llm, validation_errors)
    """
    validation_errors: List[str] = []

    # Try LLM explanation
    raw_response = explain_incident(evidence, signature)

    if raw_response is None:
        # LLM not available or failed - use fallback
        logger.info("LLM not available, using fallback explanation")
        explanation = generate_fallback_explanation(evidence, signature)
        return explanation, False, ["LLM not available"]

    # Validate the response
    explanation, errors = _validate_explanation(raw_response, evidence)

    if explanation:
        logger.info("LLM explanation validated successfully")
        return explanation, True, []

    # Validation failed - try to fix with retry
    validation_errors.extend(errors)
    logger.warning(f"LLM response validation failed: {errors}")

    # Retry with fix prompt
    fixed_response = fix_json_with_llm(
        json.dumps(raw_response), "\n".join(errors))

    if fixed_response:
        explanation, retry_errors = _validate_explanation(
            fixed_response, evidence)
        if explanation:
            logger.info("LLM explanation fixed and validated on retry")
            # Include original errors for logging
            return explanation, True, validation_errors
        validation_errors.extend(retry_errors)

    # All attempts failed - use fallback
    logger.warning("LLM validation failed after retry, using fallback")
    explanation = generate_fallback_explanation(evidence, signature)
    validation_errors.append(
        "Fell back to deterministic explanation after validation failures")

    return explanation, False, validation_errors


def _validate_explanation(
    raw: Dict[str, Any],
    evidence: EvidenceBundle
) -> Tuple[Optional[IncidentExplanation], List[str]]:
    """
    Validate raw LLM response against schema and evidence.

    Returns:
        Tuple of (validated_explanation or None, list of error messages)
    """
    errors: List[str] = []
    valid_line_numbers = {line.line_number for line in evidence.sample_lines}

    # Check required fields
    required_fields = ["incident_title", "what_happened", "likely_causes",
                       "recommended_next_steps", "confidence", "referenced_line_numbers"]

    for field in required_fields:
        if field not in raw:
            errors.append(f"Missing required field: {field}")

    if errors:
        return None, errors

    # Validate confidence value
    if raw.get("confidence") not in ["low", "medium", "high"]:
        errors.append(f"Invalid confidence value: {raw.get('confidence')}")

    # Validate and collect cited line numbers
    cited_line_numbers = set()

    likely_causes = raw.get("likely_causes", [])
    if not isinstance(likely_causes, list):
        errors.append("likely_causes must be a list")
    else:
        for i, cause in enumerate(likely_causes):
            if not isinstance(cause, dict):
                errors.append(f"likely_causes[{i}] must be an object")
                continue

            if "hypothesis" not in cause:
                errors.append(f"likely_causes[{i}] missing hypothesis")

            evidence_lines = cause.get("evidence_line_numbers", [])
            if not isinstance(evidence_lines, list):
                errors.append(
                    f"likely_causes[{i}].evidence_line_numbers must be a list")
            else:
                for line_num in evidence_lines:
                    if not isinstance(line_num, int):
                        errors.append(
                            f"likely_causes[{i}] has non-integer line number: {line_num}")
                    elif line_num not in valid_line_numbers:
                        errors.append(
                            f"likely_causes[{i}] cites invalid line number {line_num} (valid: {sorted(valid_line_numbers)})")
                    else:
                        cited_line_numbers.add(line_num)

    # Validate referenced_line_numbers contains all cited lines
    referenced = set(raw.get("referenced_line_numbers", []))
    if not isinstance(raw.get("referenced_line_numbers"), list):
        errors.append("referenced_line_numbers must be a list")
    else:
        missing_refs = cited_line_numbers - referenced
        if missing_refs:
            errors.append(
                f"referenced_line_numbers missing cited lines: {sorted(missing_refs)}")

        # Check referenced lines are valid
        invalid_refs = referenced - valid_line_numbers
        if invalid_refs:
            errors.append(
                f"referenced_line_numbers contains invalid lines: {sorted(invalid_refs)}")

    if errors:
        return None, errors

    # Try Pydantic validation
    try:
        # Convert likely_causes to proper structure
        validated_causes = [
            LikelyCause(
                hypothesis=cause["hypothesis"],
                evidence_line_numbers=cause.get("evidence_line_numbers", [])
            )
            for cause in likely_causes
        ]

        explanation = IncidentExplanation(
            incident_title=raw["incident_title"],
            what_happened=raw["what_happened"],
            likely_causes=validated_causes,
            recommended_next_steps=raw.get("recommended_next_steps", []),
            confidence=raw["confidence"],
            caveats=raw.get("caveats", []),
            referenced_line_numbers=list(raw["referenced_line_numbers"])
        )

        return explanation, []

    except ValidationError as e:
        for error in e.errors():
            errors.append(
                f"Pydantic validation: {error['loc']} - {error['msg']}")
        return None, errors
