"""
backend/main.py
CyberSentinel FastAPI application entry point.

Responsibilities:
  - App factory with lifespan (startup / shutdown hooks)
  - CORS middleware
  - /health endpoint
  - Router registration (routes added incrementally as pipeline layers are built)
"""

from contextlib import asynccontextmanager
import logging

import chromadb
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.config import get_settings

logger = logging.getLogger("cybersentinel")
logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(name)s | %(message)s")

# ── Lifespan ─────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown logic executed once per process."""
    settings = get_settings()
    logger.info("CyberSentinel starting up …")

    # Initialise persistent ChromaDB client and attach to app state
    chroma_client = chromadb.PersistentClient(path=settings.chroma_persist_dir)
    app.state.chroma_client = chroma_client
    app.state.settings = settings

    # Verify the knowledge-base collection is present (warn if not yet ingested)
    try:
        col = chroma_client.get_collection(settings.chroma_collection_name)
        count = col.count()
        logger.info(
            "ChromaDB collection '%s' ready — %d documents indexed",
            settings.chroma_collection_name,
            count,
        )
    except Exception:
        logger.warning(
            "ChromaDB collection '%s' not found — run ingestion scripts first.",
            settings.chroma_collection_name,
        )

    logger.info("Startup complete. LLM backend: %s", settings.ollama_base_url)
    yield

    # ── Shutdown ─────────────────────────────────────────────────────────────
    logger.info("CyberSentinel shutting down.")


# ── App factory ──────────────────────────────────────────────────────────────

def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title="CyberSentinel",
        description=(
            "Explainable LLM-Powered IDS Alert Triage "
            "with Confidence-Guided Adaptive Retrieval & Hallucination Verification"
        ),
        version="0.1.0",
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # ── CORS ─────────────────────────────────────────────────────────────────
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── Core endpoints ───────────────────────────────────────────────────────

    @app.get("/health", tags=["meta"], summary="Liveness check")
    async def health():
        """Returns service status and basic configuration info."""
        s = get_settings()
        chroma_client: chromadb.PersistentClient = app.state.chroma_client
        try:
            col = chroma_client.get_collection(s.chroma_collection_name)
            kb_docs = col.count()
        except Exception:
            kb_docs = 0

        return {
            "status": "ok",
            "llm_model": s.llm_model,
            "embedding_model": s.embedding_model,
            "chroma_collection": s.chroma_collection_name,
            "kb_documents_indexed": kb_docs,
            "confidence_threshold": s.confidence_threshold,
            "max_retrieval_rounds": s.max_retrieval_rounds,
        }

    # ── Future routers (registered here as pipeline layers are implemented) ──
    # from backend.api import alerts, pipeline, reports
    # app.include_router(alerts.router,   prefix="/alerts",   tags=["alerts"])
    # app.include_router(pipeline.router, prefix="/pipeline", tags=["pipeline"])
    # app.include_router(reports.router,  prefix="/reports",  tags=["reports"])

    return app


app = create_app()


# ── Dev entry point ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "backend.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info",
    )
