import json
from typing import Optional, Dict, Any
from openai import OpenAI
from app.core.config import settings
from app.core.logging import get_logger
from app.models.schemas import EvidenceBundle

logger = get_logger(__name__)

# JSON schema for LLM response validation
EXPLANATION_SCHEMA = {
    "type": "object",
    "required": ["incident_title", "what_happened", "likely_causes", "recommended_next_steps", "confidence", "referenced_line_numbers"],
    "properties": {
        "incident_title": {"type": "string", "description": "Short descriptive title for the incident"},
        "what_happened": {"type": "string", "description": "Clear explanation of what occurred"},
        "likely_causes": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["hypothesis", "evidence_line_numbers"],
                "properties": {
                    "hypothesis": {"type": "string"},
                    "evidence_line_numbers": {"type": "array", "items": {"type": "integer"}}
                }
            }
        },
        "recommended_next_steps": {"type": "array", "items": {"type": "string"}},
        "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
        "caveats": {"type": "array", "items": {"type": "string"}},
        "referenced_line_numbers": {"type": "array", "items": {"type": "integer"}}
    }
}

SYSTEM_PROMPT = """You are a senior site reliability engineer analyzing log incidents. 
Your task is to explain what happened and suggest next steps based ONLY on the evidence provided.

CRITICAL RULES:
1. Output ONLY valid JSON matching the required schema - no markdown, no explanation outside JSON
2. Base ALL conclusions on the evidence provided - no speculation
3. Every hypothesis MUST cite specific evidence_line_numbers from the sample logs
4. referenced_line_numbers must include ALL line numbers you cite anywhere
5. Be concise and actionable

JSON Schema you MUST follow:
{schema}"""

USER_PROMPT_TEMPLATE = """Analyze this log incident:

INCIDENT SIGNATURE: {signature}

STATISTICS:
- Total occurrences: {total_count}
- Error count: {error_count}
- Warning count: {warn_count}
- Services affected: {services}
- Time window: {time_window}

SAMPLE LOG LINES (cite these line numbers in your analysis):
{sample_lines}

Respond with ONLY a valid JSON object matching the schema. Do not include any text outside the JSON."""


def get_llm_client() -> Optional[OpenAI]:
    """Get configured OpenAI client for OpenRouter."""
    if not settings.has_llm_key:
        return None

    return OpenAI(
        api_key=settings.openai_api_key,
        base_url=settings.openai_base_url
    )


def explain_incident(evidence: EvidenceBundle, signature: str) -> Optional[Dict[str, Any]]:
    """
    Call LLM to generate incident explanation.

    Returns raw dict for validation, or None if LLM unavailable/fails.
    """
    client = get_llm_client()
    if not client:
        logger.info("LLM client not available - no API key configured")
        return None

    try:
        # Build prompts
        system_prompt = SYSTEM_PROMPT.format(
            schema=json.dumps(EXPLANATION_SCHEMA, indent=2))

        # Format sample lines
        sample_lines_text = "\n".join(
            f"[Line {line.line_number}] {line.raw_line}"
            for line in evidence.sample_lines
        )

        # Format time window
        time_window = "Unknown"
        if evidence.time_window.first_seen and evidence.time_window.last_seen:
            time_window = f"{evidence.time_window.first_seen} to {evidence.time_window.last_seen}"
        elif evidence.time_window.first_seen:
            time_window = f"From {evidence.time_window.first_seen}"

        user_prompt = USER_PROMPT_TEMPLATE.format(
            signature=signature,
            total_count=evidence.stats.total_count,
            error_count=evidence.stats.error_count,
            warn_count=evidence.stats.warn_count,
            services=", ".join(
                evidence.services) if evidence.services else "Unknown",
            time_window=time_window,
            sample_lines=sample_lines_text
        )

        logger.debug(f"Calling LLM for incident explanation...")

        response = client.chat.completions.create(
            model=settings.openai_model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.1,
            max_tokens=1500
        )

        content = response.choices[0].message.content
        if not content:
            logger.warning("LLM returned empty response")
            return None

        # Parse JSON from response
        result = _extract_json(content)
        if result:
            logger.info("LLM explanation generated successfully")
        else:
            logger.warning(
                f"Failed to parse LLM response as JSON: {content[:200]}")

        return result

    except Exception as e:
        logger.error(f"LLM call failed: {e}")
        return None


def fix_json_with_llm(invalid_json: str, errors: str) -> Optional[Dict[str, Any]]:
    """
    Attempt to fix invalid JSON using a follow-up LLM call.
    """
    client = get_llm_client()
    if not client:
        return None

    try:
        fix_prompt = f"""The following JSON is invalid or doesn't match the required schema.

ORIGINAL JSON:
{invalid_json}

ERRORS:
{errors}

REQUIRED SCHEMA:
{json.dumps(EXPLANATION_SCHEMA, indent=2)}

Please output ONLY the corrected valid JSON with no other text."""

        response = client.chat.completions.create(
            model=settings.openai_model,
            messages=[
                {"role": "system", "content": "You are a JSON repair assistant. Output ONLY valid JSON."},
                {"role": "user", "content": fix_prompt}
            ],
            temperature=0,
            max_tokens=1500
        )

        content = response.choices[0].message.content
        if not content:
            return None

        return _extract_json(content)

    except Exception as e:
        logger.error(f"JSON fix LLM call failed: {e}")
        return None


def _extract_json(text: str) -> Optional[Dict[str, Any]]:
    """Extract JSON from LLM response text."""
    # Try direct parse first
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Try to find JSON object in text
    text = text.strip()

    # Remove markdown code blocks if present
    if text.startswith("```"):
        lines = text.split("\n")
        lines = [l for l in lines if not l.startswith("```")]
        text = "\n".join(lines)

    # Find JSON object boundaries
    start = text.find("{")
    end = text.rfind("}") + 1

    if start != -1 and end > start:
        try:
            return json.loads(text[start:end])
        except json.JSONDecodeError:
            pass

    return None
