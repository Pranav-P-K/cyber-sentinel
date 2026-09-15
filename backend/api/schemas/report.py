"""
backend/api/schemas/report.py
Pydantic v2 response schemas for the analysis report.
"""

from __future__ import annotations
from typing import Optional
from pydantic import BaseModel, Field


class SessionReport(BaseModel):
    """Report for a single DBASC-clustered attack session."""
    session_id:       str
    attacker_ips:     list[str]
    victim_ips:       list[str]
    time_start:       Optional[str]
    time_end:         Optional[str]
    ordered_chain:    list[str]              # ["TA0043", "TA0006", ...]
    chain_labels:     list[str]              # ["Reconnaissance", "Credential Access", ...]
    kcv:              float = Field(description="Kill Chain Velocity (phases/hour)")
    kcv_label:        str   = Field(description="'automated/scripted' or 'manual/APT-patterned'")
    severity_index:   float = Field(description="Severity Index 0–100")
    hrss:             float = Field(description="HRSS retrieval confidence score")
    round2_triggered: bool  = Field(description="Whether CGAR triggered Round 2 retrieval")
    narrative:        str   = Field(description="LLM-generated grounded incident narrative")
    alert_count:      int


class AnalyzeResponse(BaseModel):
    """Full response from POST /api/v1/analyze."""
    analysis_id:   str
    total_alerts:  int
    session_count: int
    noise_alerts:  int                       # alerts DBSCAN labelled as noise
    sessions:      list[SessionReport]
    processing_ms: Optional[int] = None      # wall-clock latency
