"""
frontend/utils/api_client.py
Async HTTP client for the CyberSentinel FastAPI backend.

All calls go through this module so that URL, auth, and error handling
are centralised and the Streamlit pages stay clean.
"""

import os
from typing import Any

import httpx

def get_backend_url(custom_url: str | None = None) -> str:
    """Resolve backend URL from argument, environment variable, or default."""
    if custom_url and custom_url.strip():
        return custom_url.strip().rstrip("/")
    return os.environ.get("BACKEND_URL", "http://localhost:8000").rstrip("/")


BACKEND_URL     = get_backend_url()
HEALTH_TIMEOUT  = httpx.Timeout(timeout=15.0, connect=5.0)
ANALYZE_TIMEOUT = httpx.Timeout(timeout=600.0, connect=30.0)


# ── Health ────────────────────────────────────────────────────────────────────

async def get_health(backend_url: str | None = None) -> dict:
    """Check backend liveness. Returns the /health JSON payload."""
    url = get_backend_url(backend_url)
    async with httpx.AsyncClient(timeout=HEALTH_TIMEOUT) as client:
        resp = await client.get(f"{url}/health")
        resp.raise_for_status()
        return resp.json()


# ── Analysis pipeline ─────────────────────────────────────────────────────────

async def analyze_alerts(alerts: list[dict], backend_url: str | None = None) -> dict:
    """
    POST a list of alert dicts to /api/v1/analyze and return the pipeline result.

    Expected response shape:
    {
        "analysis_id":   str,
        "total_alerts":  int,
        "session_count": int,
        "noise_alerts":  int,
        "sessions":      [...],      # SessionReport items
        "processing_ms": int,
    }
    """
    url = get_backend_url(backend_url)
    async with httpx.AsyncClient(timeout=ANALYZE_TIMEOUT) as client:
        resp = await client.post(
            f"{url}/api/v1/analyze",
            json={"alerts": alerts},
        )
        resp.raise_for_status()
        return resp.json()


async def get_kb_stats(backend_url: str | None = None) -> dict:
    """Return ChromaDB collection stats from /api/v1/kb/stats."""
    url = get_backend_url(backend_url)
    async with httpx.AsyncClient(timeout=HEALTH_TIMEOUT) as client:
        resp = await client.get(f"{url}/api/v1/kb/stats")
        resp.raise_for_status()
        return resp.json()


# ── Sync wrappers (for Streamlit which is not always async) ──────────────────

def sync_health(backend_url: str | None = None) -> dict | None:
    """Synchronous health check — safe to call from Streamlit button handlers."""
    import asyncio
    try:
        return asyncio.run(get_health(backend_url))
    except Exception as exc:
        return {"error": str(exc)}


def sync_analyze(alerts: list[dict], backend_url: str | None = None) -> dict | None:
    """Synchronous pipeline call — safe to call from Streamlit."""
    import asyncio
    url = get_backend_url(backend_url)
    try:
        return asyncio.run(analyze_alerts(alerts, backend_url=url))
    except httpx.HTTPStatusError as exc:
        return {"error": f"HTTP {exc.response.status_code}: {exc.response.text}"}
    except httpx.ConnectError:
        return {"error": f"Cannot connect to backend at {url}"}
    except httpx.TimeoutException:
        return {
            "error": (
                "Analysis timed out after 600 seconds. "
                "The pipeline is running on CPU and needs more time — check the backend terminal."
            )
        }
    except Exception as exc:
        return {"error": str(exc)}

