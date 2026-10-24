"""Configuration settings for SecuRAG loaded from environment and .env."""

from functools import lru_cache
from typing import Literal
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """SecuRAG configuration settings backed by .env."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # LLM Settings
    llm_provider: str = Field(default="openai", alias="LLM_PROVIDER")
    llm_api_key: str = Field(default="", alias="LLM_API_KEY")
    llm_model_main: str = Field(default="gpt-4o-mini", alias="LLM_MODEL_MAIN")
    llm_model_fast: str = Field(default="gpt-4o-mini", alias="LLM_MODEL_FAST")
    llm_base_url: str | None = Field(default=None, alias="LLM_BASE_URL")

    # Pinecone
    pinecone_api_key: str = Field(default="", alias="PINECONE_API_KEY")
    pinecone_index: str = Field(default="securag", alias="PINECONE_INDEX")
    pinecone_cloud: str = Field(default="aws", alias="PINECONE_CLOUD")
    pinecone_region: str = Field(default="us-east-1", alias="PINECONE_REGION")

    # Neo4j Graph Database
    neo4j_uri: str = Field(default="bolt://localhost:7687", alias="NEO4J_URI")
    neo4j_user: str = Field(default="neo4j", alias="NEO4J_USER")
    neo4j_password: str = Field(default="", alias="NEO4J_PASSWORD")

    # Embedding and Reranking Models
    embed_model: str = Field(default="BAAI/bge-m3", alias="EMBED_MODEL")
    embed_dim: int = Field(default=1024, alias="EMBED_DIM")
    rerank_model: str = Field(default="BAAI/bge-reranker-v2-m3", alias="RERANK_MODEL")
    device: str = Field(default="cuda", alias="DEVICE")
    embed_batch_size: int = Field(default=16, alias="EMBED_BATCH_SIZE")

    # Data Slice
    data_years: str = Field(default="2024,2025", alias="DATA_YEARS")
    cve_max: int = Field(default=20000, alias="CVE_MAX")

    # Agent Limits
    max_rewrite_rounds: int = Field(default=3, alias="MAX_REWRITE_ROUNDS")
    recursion_limit: int = Field(default=50, alias="RECURSION_LIMIT")
    retrieval_top_k: int = Field(default=20, alias="RETRIEVAL_TOP_K")
    rerank_top_n: int = Field(default=6, alias="RERANK_TOP_N")
    novelty_cosine_threshold: float = Field(default=0.90, alias="NOVELTY_COSINE_THRESHOLD")

    # Observability & Tracing
    langsmith_tracing: bool = Field(default=False, alias="LANGSMITH_TRACING")
    langsmith_api_key: str = Field(default="", alias="LANGSMITH_API_KEY")
    langsmith_project: str = Field(default="securag", alias="LANGSMITH_PROJECT")

    # Web Fallback
    web_search_provider: str = Field(default="", alias="WEB_SEARCH_PROVIDER")
    web_search_api_key: str = Field(default="", alias="WEB_SEARCH_API_KEY")

    # Feature Flags for Pipeline & Ablation (Section 7 of build_agent.md)
    use_bm25: bool = Field(default=True, alias="USE_BM25")
    use_query_expansion: bool = Field(default=False, alias="USE_QUERY_EXPANSION")
    use_hyde: bool = Field(default=False, alias="USE_HYDE")
    use_cross_encoder: bool = Field(default=True, alias="USE_CROSS_ENCODER")
    use_graph_retrieval: bool = Field(default=True, alias="USE_GRAPH_RETRIEVAL")
    use_graph_rerank: bool = Field(default=True, alias="USE_GRAPH_RERANK")
    use_crag_loop: bool = Field(default=True, alias="USE_CRAG_LOOP")
    use_router: bool = Field(default=True, alias="USE_ROUTER")
    use_reflection: bool = Field(default=True, alias="USE_REFLECTION")

    @property
    def parsed_years(self) -> list[str]:
        """Return list of years parsed from DATA_YEARS string."""
        return [y.strip() for y in self.data_years.split(",") if y.strip()]


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return cached application settings singleton."""
    return Settings()
