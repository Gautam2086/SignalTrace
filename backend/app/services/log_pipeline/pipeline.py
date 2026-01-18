#pipeline.py - Orchestrates the full log-processing flow.

from __future__ import annotations
from typing import Any, Dict, List
from .parser import parse_logs_from_text
from .grouping import group_logs
from .summarizer import summarize_groups

# This is the main function that follows the order: raw logs -> parser.py -> grouping.py -> summarizer.py -> incident summaries.
def process_logs(raw_log_text: str, top_k: int = 20) -> List[Dict[str, Any]]:
    """
    Main entrypoint:
    raw_log_text (string) -> list of incident summaries (dicts)
    """
    records = parse_logs_from_text(raw_log_text)
    groups = group_logs(records)
    incidents = summarize_groups(groups, top_k=top_k)
    return [i.to_dict() for i in incidents]
