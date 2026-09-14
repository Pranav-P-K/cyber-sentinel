"""
backend/core/llm/client.py
Async Ollama / LangChain wrapper.

Both laptops use this same file — the model is driven by .env:
  Your machine  → LLM_MODEL=llama3.2
  Teammate      → LLM_MODEL=llama3   (+ 8GB GPU via OLLAMA_NUM_GPU=1)
"""

import json
import logging
import re

from langchain_ollama import ChatOllama
from langchain_core.messages import HumanMessage, SystemMessage

from backend.config import get_settings

log = logging.getLogger("llm.client")


class LLMClient:
    """
    Thin async wrapper around ChatOllama.

    All evaluation runs use temperature=0 for deterministic, reproducible
    output (critical for RAGAS metrics).
    """

    def __init__(self, model: str | None = None, temperature: float = 0.0):
        settings = get_settings()
        self.model = model or settings.llm_model   # reads llama3.2 / llama3 from .env
        self.temperature = temperature
        self.llm = ChatOllama(
            model=self.model,
            temperature=self.temperature,
            base_url=settings.ollama_base_url,
        )
        log.info("LLMClient ready — model=%s  temperature=%.1f", self.model, temperature)

    async def generate(self, system: str, user: str) -> str:
        """Single async generation call. Returns raw string content."""
        msgs = [SystemMessage(content=system), HumanMessage(content=user)]
        response = await self.llm.ainvoke(msgs)
        return response.content

    async def generate_json(self, system: str, user: str) -> dict:
        """
        Generate and parse JSON. Strips markdown code fences if present.
        Raises ValueError if the output cannot be parsed as JSON after cleaning.
        """
        raw = await self.generate(system, user + "\n\nRespond ONLY with valid JSON. No explanation.")
        return _parse_json(raw)

    async def generate_with_confidence(self, system: str, user: str) -> tuple[str, float]:
        """
        Generate text and ask the model to self-report a confidence score.
        Returns (content, confidence_float).
        Used by CGAR as one signal in the HRSS composite scorer.
        """
        conf_suffix = (
            "\n\nAfter your response, on a NEW LINE write exactly: "
            "CONFIDENCE: <float between 0.0 and 1.0>"
        )
        raw = await self.generate(system, user + conf_suffix)
        return _split_confidence(raw)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _parse_json(raw: str) -> dict:
    """Strip markdown fences and parse JSON. Raises ValueError on failure."""
    # Remove ```json ... ``` or ``` ... ``` wrappers
    clean = re.sub(r"```(?:json)?", "", raw).replace("```", "").strip()
    try:
        return json.loads(clean)
    except json.JSONDecodeError as e:
        raise ValueError(f"LLM did not return valid JSON.\nRaw output:\n{raw}") from e


def _split_confidence(raw: str) -> tuple[str, float]:
    """
    Extract the CONFIDENCE line from end of LLM output.
    Returns (content_without_confidence_line, confidence_float).
    Falls back to 0.5 if the line is missing or malformed.
    """
    lines = raw.strip().splitlines()
    confidence = 0.5
    content_lines = lines

    for i in range(len(lines) - 1, max(len(lines) - 4, -1), -1):
        m = re.match(r"CONFIDENCE:\s*([0-9.]+)", lines[i].strip(), re.IGNORECASE)
        if m:
            try:
                confidence = float(m.group(1))
                confidence = max(0.0, min(1.0, confidence))
            except ValueError:
                confidence = 0.5
            content_lines = lines[:i]
            break

    return "\n".join(content_lines).strip(), confidence
