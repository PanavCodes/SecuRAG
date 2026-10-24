"""Client factories and connection management for Neo4j, Pinecone, Embeddings, Reranker, and LLMs."""

from functools import lru_cache
from typing import Any, TYPE_CHECKING
import logging
from neo4j import GraphDatabase, Driver

from securag.config import get_settings

if TYPE_CHECKING:
    from sentence_transformers import SentenceTransformer, CrossEncoder
    from langchain_core.language_models.chat_models import BaseChatModel
    from pinecone import Pinecone

logger = logging.getLogger(__name__)

# Global driver singleton
_neo4j_driver: Driver | None = None


def get_neo4j_driver() -> Driver:
    """Return the global Neo4j driver singleton."""
    global _neo4j_driver
    settings = get_settings()
    if _neo4j_driver is None:
        _neo4j_driver = GraphDatabase.driver(
            settings.neo4j_uri,
            auth=(settings.neo4j_user, settings.neo4j_password),
        )
    return _neo4j_driver


def close_neo4j_driver() -> None:
    """Close the active Neo4j driver connection."""
    global _neo4j_driver
    if _neo4j_driver is not None:
        _neo4j_driver.close()
        _neo4j_driver = None


def get_pinecone_client() -> Any:
    """Return a Pinecone client instance using configured API key."""
    from pinecone import Pinecone

    settings = get_settings()
    if not settings.pinecone_api_key:
        raise ValueError("PINECONE_API_KEY is not configured in .env")
    return Pinecone(api_key=settings.pinecone_api_key)


def get_pinecone_index() -> Any:
    """Return or initialize the Pinecone index handle for SecuRAG.

    Ensures the index exists with 1024 dimensions and cosine metric as per spec.
    """
    from pinecone import ServerlessSpec

    settings = get_settings()
    pc = get_pinecone_client()
    index_name = settings.pinecone_index

    # Check if index exists; if not, create serverless index
    existing_indexes = [idx.name for idx in pc.list_indexes()]
    if index_name not in existing_indexes:
        logger.info("Creating Pinecone index '%s' (dim=%d, metric=cosine)...", index_name, settings.embed_dim)
        pc.create_index(
            name=index_name,
            dimension=settings.embed_dim,
            metric="cosine",
            spec=ServerlessSpec(
                cloud=settings.pinecone_cloud,
                region=settings.pinecone_region,
            ),
        )

    return pc.Index(index_name)


@lru_cache(maxsize=1)
def get_embedder() -> Any:
    """Return cached SentenceTransformer embedding model (BAAI/bge-m3)."""
    from sentence_transformers import SentenceTransformer

    settings = get_settings()
    logger.info("Loading embedder model '%s' on device '%s'...", settings.embed_model, settings.device)
    return SentenceTransformer(settings.embed_model, device=settings.device)


@lru_cache(maxsize=1)
def get_reranker() -> Any:
    """Return cached CrossEncoder reranking model (BAAI/bge-reranker-v2-m3)."""
    from sentence_transformers import CrossEncoder

    settings = get_settings()
    logger.info("Loading reranker model '%s' on device '%s'...", settings.rerank_model, settings.device)
    return CrossEncoder(settings.rerank_model, device=settings.device)


def get_llm(model_name: str, temperature: float = 0.0) -> Any:
    """Return a configured LangChain ChatModel instance."""
    from langchain_openai import ChatOpenAI

    settings = get_settings()
    provider = settings.llm_provider.lower().strip()

    if not settings.llm_api_key:
        raise ValueError(
            f"LLM_API_KEY is not configured in .env for provider '{provider}'. "
            "Please provide a valid API key in .env"
        )

    kwargs: dict[str, Any] = {
        "model": model_name,
        "temperature": temperature,
        "api_key": settings.llm_api_key,
        "timeout": 25.0,
        "max_retries": 2,
    }
    if settings.llm_base_url:
        kwargs["base_url"] = settings.llm_base_url

    return ChatOpenAI(**kwargs)


def get_main_llm() -> Any:
    """Return main LLM model used for synthesis, answer generation, and reflection."""
    settings = get_settings()
    return get_llm(model_name=settings.llm_model_main, temperature=0.0)


def get_fast_llm() -> Any:
    """Return fast LLM model used for routing and CRAG document grading."""
    settings = get_settings()
    return get_llm(model_name=settings.llm_model_fast, temperature=0.0)
