"""
backend/db/models.py
SQLAlchemy ORM models for CyberSentinel.

Tables:
  users     — auth users (future)
  analyses  — each /api/v1/analyze call
  alerts    — individual alerts belonging to an analysis
  reports   — generated narratives + WTS results
"""

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean, DateTime, Float, ForeignKey, Integer, JSON, String, Text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _now() -> datetime:
    return datetime.utcnow()


def _uuid4() -> str:
    return str(uuid.uuid4())


class Base(DeclarativeBase):
    pass


# ── User ──────────────────────────────────────────────────────────────────────

class User(Base):
    __tablename__ = "users"

    id:           Mapped[str]  = mapped_column(String(36), primary_key=True, default=_uuid4)
    username:     Mapped[str]  = mapped_column(String(64), unique=True, nullable=False)
    email:        Mapped[str]  = mapped_column(String(128), unique=True, nullable=False)
    hashed_pw:    Mapped[str]  = mapped_column(String(256), nullable=False)
    is_active:    Mapped[bool] = mapped_column(Boolean, default=True)
    created_at:   Mapped[datetime] = mapped_column(DateTime, default=_now)

    analyses: Mapped[list["Analysis"]] = relationship("Analysis", back_populates="user")


# ── Analysis ──────────────────────────────────────────────────────────────────

class Analysis(Base):
    """
    One analysis run = one call to POST /api/v1/analyze.
    Contains the full results of CGAR → TKCI → PFGL pipeline.
    """
    __tablename__ = "analyses"

    id:            Mapped[str]   = mapped_column(String(36), primary_key=True, default=_uuid4)
    user_id:       Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
    created_at:    Mapped[datetime]   = mapped_column(DateTime, default=_now)
    alert_count:   Mapped[int]        = mapped_column(Integer, default=0)
    session_count: Mapped[int]        = mapped_column(Integer, default=0)

    # Composite scores
    severity_index: Mapped[float | None] = mapped_column(Float, nullable=True)
    wts:            Mapped[float | None] = mapped_column(Float, nullable=True)  # Weighted Trust Score
    kcv:            Mapped[float | None] = mapped_column(Float, nullable=True)  # Kill Chain Velocity

    # Full structured result (pipeline output)
    result_json:   Mapped[dict | None] = mapped_column(JSON, nullable=True)

    user:    Mapped["User | None"]    = relationship("User", back_populates="analyses")
    alerts:  Mapped[list["Alert"]]    = relationship("Alert", back_populates="analysis", cascade="all, delete")
    reports: Mapped[list["Report"]]   = relationship("Report", back_populates="analysis", cascade="all, delete")


# ── Alert ─────────────────────────────────────────────────────────────────────

class Alert(Base):
    """
    One row per IDS alert submitted in an analysis.
    Stores raw values + NLP-derived fields after preprocessing.
    """
    __tablename__ = "alerts"

    id:          Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid4)
    analysis_id: Mapped[str] = mapped_column(String(36), ForeignKey("analyses.id"), nullable=False)
    alert_id:    Mapped[str | None] = mapped_column(String(64), nullable=True)   # original ID from CSV/JSON

    # Raw fields
    src_ip:       Mapped[str | None]   = mapped_column(String(45), nullable=True)
    dst_ip:       Mapped[str | None]   = mapped_column(String(45), nullable=True)
    dst_port:     Mapped[int | None]   = mapped_column(Integer, nullable=True)
    protocol:     Mapped[str | None]   = mapped_column(String(16), nullable=True)
    attack_type:  Mapped[str | None]   = mapped_column(String(128), nullable=True)
    timestamp:    Mapped[str | None]   = mapped_column(String(32), nullable=True)

    # NLP-derived
    mitre_tactic:     Mapped[str | None]   = mapped_column(String(8), nullable=True)   # e.g. TA0006
    tactic_confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    session_label:    Mapped[int | None]   = mapped_column(Integer, nullable=True)     # DBASC cluster ID

    analysis: Mapped["Analysis"] = relationship("Analysis", back_populates="alerts")


# ── Report ────────────────────────────────────────────────────────────────────

class Report(Base):
    """
    One report per TKCI session. Contains the LLM narrative + PFGL verification.
    """
    __tablename__ = "reports"

    id:          Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid4)
    analysis_id: Mapped[str] = mapped_column(String(36), ForeignKey("analyses.id"), nullable=False)
    session_id:  Mapped[str | None] = mapped_column(String(64), nullable=True)

    # TKCI output
    kill_chain:       Mapped[list | None] = mapped_column(JSON, nullable=True)    # ["TA0043", "TA0006", ...]
    kill_chain_labels: Mapped[list | None] = mapped_column(JSON, nullable=True)
    attacker_ips:     Mapped[list | None] = mapped_column(JSON, nullable=True)
    kcv:              Mapped[float | None] = mapped_column(Float, nullable=True)
    severity_index:   Mapped[float | None] = mapped_column(Float, nullable=True)

    # CGAR
    hrss:             Mapped[float | None] = mapped_column(Float, nullable=True)
    round2_triggered: Mapped[bool]         = mapped_column(Boolean, default=False)

    # LLM narrative
    narrative:        Mapped[str | None]  = mapped_column(Text, nullable=True)

    # PFGL verification
    wts:               Mapped[float | None] = mapped_column(Float, nullable=True)
    claims_json:       Mapped[list | None]  = mapped_column(JSON, nullable=True)
    verified_count:    Mapped[int]          = mapped_column(Integer, default=0)
    unverified_count:  Mapped[int]          = mapped_column(Integer, default=0)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    analysis: Mapped["Analysis"] = relationship("Analysis", back_populates="reports")
