"""
backend/config.py
Centralised settings — reads from .env via pydantic-settings.
All other modules should import `get_settings()` rather than reading
os.environ directly, so the app has a single source of truth.
"""

from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── LLM / Ollama ────────────────────────────────────────────────────────
    ollama_base_url: str = Field("http://localhost:11434", alias="OLLAMA_BASE_URL")
    llm_model: str = Field("llama3", alias="LLM_MODEL")
    embedding_model: str = Field("all-MiniLM-L6-v2", alias="EMBEDDING_MODEL")

    # ── Database ─────────────────────────────────────────────────────────────
    database_url: str = Field(
        "sqlite+aiosqlite:///./data/cybersentinel.db", alias="DATABASE_URL"
    )

    # ── ChromaDB ─────────────────────────────────────────────────────────────
    chroma_persist_dir: str = Field("./data/chroma_db", alias="CHROMA_PERSIST_DIR")
    chroma_collection_name: str = Field(
        "cybersentinel_kb", alias="CHROMA_COLLECTION_NAME"
    )

    # ── Redis ────────────────────────────────────────────────────────────────
    redis_url: str = Field("redis://localhost:6379", alias="REDIS_URL")

    # ── Auth ─────────────────────────────────────────────────────────────────
    secret_key: str = Field(
        "replace-this-with-a-64-char-random-string", alias="SECRET_KEY"
    )
    algorithm: str = Field("HS256", alias="ALGORITHM")
    access_token_expire_minutes: int = Field(60, alias="ACCESS_TOKEN_EXPIRE_MINUTES")

    # ── CGAR / RAG ───────────────────────────────────────────────────────────
    rag_top_k: int = Field(5, alias="RAG_TOP_K")
    confidence_threshold: float = Field(0.70, alias="CONFIDENCE_THRESHOLD")
    max_retrieval_rounds: int = Field(2, alias="MAX_RETRIEVAL_ROUNDS")

    # ── App ──────────────────────────────────────────────────────────────────
    debug: bool = Field(True, alias="DEBUG")
    allowed_origins: str = Field("http://localhost:8501", alias="ALLOWED_ORIGINS")

    @property
    def allowed_origins_list(self) -> list[str]:
        """Split comma-separated ALLOWED_ORIGINS into a Python list."""
        return [o.strip() for o in self.allowed_origins.split(",") if o.strip()]


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return cached Settings instance (reads .env once at startup)."""
    return Settings()
