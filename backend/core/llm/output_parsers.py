"""
backend/core/llm/output_parsers.py
Robust extraction of structured data from raw LLM output.

LLMs often wrap JSON in markdown fences, add preambles, or produce
slightly malformed JSON. This module handles all those cases gracefully.
"""

import json
import logging
import re
from typing import Any

log = logging.getLogger("output_parsers")


def extract_json(raw: str) -> dict | list:
    """
    Extract a JSON object or array from raw LLM output.

    Tries in order:
      1. Direct parse
      2. Strip ``` fences then parse
      3. Regex-find first { ... } or [ ... ] block then parse
      4. Raise ValueError with the raw output for debugging
    """
    # 1. Direct
    try:
        return json.loads(raw.strip())
    except json.JSONDecodeError:
        pass

    # 2. Strip fences
    cleaned = re.sub(r"```(?:json)?", "", raw).replace("```", "").strip()
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass

    # 3. Find first JSON object or array
    for pattern in (r"\{.*\}", r"\[.*\]"):
        m = re.search(pattern, cleaned, re.DOTALL)
        if m:
            try:
                return json.loads(m.group())
            except json.JSONDecodeError:
                continue

    raise ValueError(
        f"Could not extract valid JSON from LLM output.\n"
        f"Raw (first 500 chars): {raw[:500]}"
    )


def extract_float(raw: str, key: str = "score", default: float = 0.5) -> float:
    """
    Extract a float from JSON output. Falls back to regex search then default.
    """
    try:
        data = extract_json(raw)
        if isinstance(data, dict) and key in data:
            return float(data[key])
    except (ValueError, KeyError, TypeError):
        pass

    # Regex fallback: look for "score": 0.75 pattern
    m = re.search(rf'"{key}"\s*:\s*([0-9.]+)', raw)
    if m:
        try:
            return float(m.group(1))
        except ValueError:
            pass

    return default


def extract_claims(raw: str) -> list[dict]:
    """
    Extract the 'claims' list from a CLAIM_EXTRACTION_PROMPT response.
    Returns empty list on failure.
    """
    try:
        data = extract_json(raw)
        if isinstance(data, dict):
            return data.get("claims", [])
        if isinstance(data, list):
            return data
    except ValueError:
        log.warning("Could not parse claim extraction response.")
    return []


def extract_confidence(raw: str) -> tuple[str, float]:
    """
    Split a generation that ends with 'CONFIDENCE: 0.XX' into
    (content, confidence). Falls back to (raw, 0.5).
    """
    lines = raw.strip().splitlines()
    for i in range(len(lines) - 1, max(len(lines) - 5, -1), -1):
        m = re.match(r"CONFIDENCE:\s*([0-9.]+)", lines[i].strip(), re.IGNORECASE)
        if m:
            try:
                conf = float(m.group(1))
                conf = max(0.0, min(1.0, conf))
                content = "\n".join(lines[:i]).strip()
                return content, conf
            except ValueError:
                pass
    return raw.strip(), 0.5


def safe_str(value: Any, max_len: int = 500) -> str:
    """Safely convert any value to a truncated string for prompt injection."""
    return str(value)[:max_len]
