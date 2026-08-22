"""
frontend/utils/api_client.py
Async HTTP client for the CyberSentinel FastAPI backend.

All calls go through this module so that URL, auth, and error handling
are centralised and the Streamlit pages stay clean.
"""

import os
from typing import Any

import httpx

BACKEND_URL = os.environ.get("BACKEND_URL", "http://localhost:8000").rstrip("/")
TIMEOUT     = httpx.Timeout(timeout=120.0, connect=10.0)


# ── Health ────────────────────────────────────────────────────────────────────

async def get_health() -> dict:
    """Check backend liveness. Returns the /health JSON payload."""
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        resp = await client.get(f"{BACKEND_URL}/health")
        resp.raise_for_status()
        return resp.json()


# ── Analysis pipeline ─────────────────────────────────────────────────────────

async def analyze_alerts(alerts: list[dict]) -> dict:
    """
    POST a list of alert dicts to /api/v1/analyze and return the pipeline result.

    Expected response shape (once pipeline is implemented):
    {
        "sessions":  [...],          # DBASC cluster results
        "kill_chains": [...],        # TKCI reconstructed chains
        "narratives": [...],         # LLM-generated incident reports
        "verification": [...],       # PFGL claim-level results
        "wts": float,                # Weighted Trust Score
        "severity_index": float,     # Composite Severity Index
    }
    """
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        resp = await client.post(
            f"{BACKEND_URL}/api/v1/analyze",
            json={"alerts": alerts},
        )
        resp.raise_for_status()
        return resp.json()


async def get_kb_stats() -> dict:
    """Return ChromaDB collection stats from /api/v1/kb/stats."""
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        resp = await client.get(f"{BACKEND_URL}/api/v1/kb/stats")
        resp.raise_for_status()
        return resp.json()


# ── Sync wrappers (for Streamlit which is not always async) ──────────────────

def sync_health() -> dict | None:
    """Synchronous health check — safe to call from Streamlit button handlers."""
    import asyncio
    try:
        return asyncio.run(get_health())
    except Exception as exc:
        return {"error": str(exc)}


def sync_analyze(alerts: list[dict]) -> dict | None:
    """Synchronous pipeline call — safe to call from Streamlit."""
    import asyncio
    try:
        return asyncio.run(analyze_alerts(alerts))
    except httpx.HTTPStatusError as exc:
        return {"error": f"HTTP {exc.response.status_code}: {exc.response.text}"}
    except httpx.ConnectError:
        return {"error": f"Cannot connect to backend at {BACKEND_URL}"}
    except Exception as exc:
        return {"error": str(exc)}
