"""
backend/api/schemas/alert.py
Pydantic v2 input/output schemas for alert submission.
"""

from __future__ import annotations
from typing import Optional
from pydantic import BaseModel, Field, field_validator


class AlertInput(BaseModel):
    """Single IDS alert as submitted to POST /api/v1/analyze."""

    alert_id:    Optional[str]   = Field(None, description="Original alert ID from IDS")
    src_ip:      Optional[str]   = Field(None, description="Source IP address")
    dst_ip:      Optional[str]   = Field(None, description="Destination IP address")
    dst_port:    Optional[int]   = Field(None, ge=0, le=65535)
    protocol:    Optional[str]   = Field("TCP", description="Layer-4 protocol")
    attack_type: Optional[str]   = Field(None, description="IDS label, e.g. 'SSH-Patator'")
    timestamp:   Optional[str]   = Field(None, description="ISO 8601 timestamp")
    cisa_hit:    Optional[bool]  = Field(False, description="True if a CISA KEV CVE is involved")
    raw_features: Optional[dict] = Field(None, description="Any extra IDS feature fields")

    @field_validator("protocol", mode="before")
    @classmethod
    def upper_protocol(cls, v):
        return v.upper() if isinstance(v, str) else v


class AnalyzeRequest(BaseModel):
    """Payload for POST /api/v1/analyze."""
    alerts: list[AlertInput] = Field(..., min_length=1, max_length=500)

    model_config = {"json_schema_extra": {
        "example": {
            "alerts": [
                {"src_ip": "172.16.0.5", "dst_port": 22, "protocol": "TCP",
                 "attack_type": "SSH-Patator", "timestamp": "2017-07-04T09:00:00"},
                {"src_ip": "172.16.0.5", "dst_port": 443, "protocol": "TCP",
                 "attack_type": "Infiltration", "timestamp": "2017-07-04T09:15:00"},
            ]
        }
    }}
