"""
backend/api/routes/alerts.py
POST /api/v1/analyze — main CyberSentinel analysis endpoint.
"""

import logging

from fastapi import APIRouter, Depends, HTTPException, status

from backend.api.schemas.alert import AnalyzeRequest
from backend.api.schemas.report import AnalyzeResponse
from backend.core.pipeline import CyberSentinelPipeline, get_pipeline

log = logging.getLogger("api.alerts")

router = APIRouter(prefix="/api/v1", tags=["analysis"])


@router.post(
    "/analyze",
    response_model=AnalyzeResponse,
    summary="Analyze a batch of IDS alerts",
    description=(
        "Submit 1–500 IDS alerts. The pipeline runs NLP → CGAR → TKCI → LLM narrative "
        "and returns per-session attack chains, Severity Index, Kill Chain Velocity, "
        "HRSS score, and a grounded incident narrative."
    ),
)
async def analyze_alerts(
    body: AnalyzeRequest,
    pipeline: CyberSentinelPipeline = Depends(get_pipeline),
) -> AnalyzeResponse:
    """
    Main analysis endpoint.

    - Accepts a JSON array of IDS alerts
    - Runs the full CyberSentinel pipeline
    - Returns structured per-session reports
    """
    alerts = [a.model_dump() for a in body.alerts]
    log.info("POST /api/v1/analyze — %d alerts", len(alerts))

    try:
        result = await pipeline.analyze(alerts)
    except Exception as exc:
        log.exception("Pipeline failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Pipeline error: {str(exc)}",
        )

    return AnalyzeResponse(**result)
