"""SecuRAG FastAPI Service for CVE and Threat-Intel Triage."""

import logging
import time
import uuid
from typing import Any
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from securag.agent.graph import get_agent
from securag.config import get_settings
from securag.clients import get_neo4j_driver

logger = logging.getLogger(__name__)

app = FastAPI(
    title="SecuRAG API",
    description="Agentic Hybrid GraphRAG for CVE / Threat-Intel Triage (LangGraph + Neo4j + Pinecone)",
    version="1.0.0",
)

# Enable CORS for all origins in development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class AskRequest(BaseModel):
    question: str = Field(..., description="Cybersecurity or triage query", min_length=1)
    config_overrides: dict[str, Any] | None = Field(
        default=None,
        description="Optional dictionary of pipeline config flags (e.g. use_graph_retrieval, use_bm25)",
    )


class AskResponse(BaseModel):
    answer: str = Field(..., description="Generated answer with bracketed citations")
    citations: list[str] = Field(default_factory=list, description="Verified cited entity tags")
    route: str = Field(..., description="Classification route: simple, multi_hop, or out_of_kb")
    rounds: int = Field(default=0, description="Number of query rewriting rounds executed")
    latency_ms: float = Field(..., description="Total end-to-end execution latency in milliseconds")
    trace_url: str | None = Field(default=None, description="Observability trace URL if enabled")
    graph_paths: list[dict[str, Any]] = Field(default_factory=list, description="Extracted knowledge graph paths")
    context: list[dict[str, Any]] = Field(default_factory=list, description="Retrieved context chunks")


@app.get("/health", summary="Health Check")
def health() -> dict[str, Any]:
    """Check connectivity to Neo4j and backend readiness."""
    try:
        driver = get_neo4j_driver()
        with driver.session() as session:
            res = session.run("RETURN 1 AS ok LIMIT 1").single()
            neo4j_ok = bool(res and res["ok"] == 1)
    except Exception as exc:
        logger.warning("Neo4j health check failed: %s", exc)
        neo4j_ok = False

    return {
        "status": "healthy" if neo4j_ok else "degraded",
        "neo4j": neo4j_ok,
        "version": "1.0.0",
    }


@app.get("/config", summary="Current Configuration Flags")
def get_current_config() -> dict[str, Any]:
    """Return active default pipeline feature flags."""
    settings = get_settings()
    has_web = bool(settings.web_search_provider and settings.web_search_api_key)
    return {
        "use_bm25": settings.use_bm25,
        "use_cross_encoder": settings.use_cross_encoder,
        "use_graph_retrieval": settings.use_graph_retrieval,
        "use_graph_rerank": settings.use_graph_rerank,
        "use_crag_loop": settings.use_crag_loop,
        "use_router": settings.use_router,
        "use_reflection": settings.use_reflection,
        "use_query_expansion": settings.use_query_expansion,
        "use_hyde": settings.use_hyde,
        "use_web_fallback": has_web,
    }


@app.post("/ask", response_model=AskResponse, summary="Query SecuRAG Pipeline")
def ask(req: AskRequest) -> AskResponse:
    """Triage a CVE or threat intelligence query through the SecuRAG agent."""
    settings = get_settings()
    agent = get_agent()
    has_web = bool(settings.web_search_provider and settings.web_search_api_key)

    # Build effective configuration
    effective_config = {
        "use_bm25": settings.use_bm25,
        "use_cross_encoder": settings.use_cross_encoder,
        "use_graph_retrieval": settings.use_graph_retrieval,
        "use_graph_rerank": settings.use_graph_rerank,
        "use_crag_loop": settings.use_crag_loop,
        "use_router": settings.use_router,
        "use_reflection": settings.use_reflection,
        "use_query_expansion": settings.use_query_expansion,
        "use_hyde": settings.use_hyde,
        "use_web_fallback": has_web,
    }
    if req.config_overrides:
        effective_config.update(req.config_overrides)

    initial_state = {
        "question": req.question,
        "config": effective_config,
        "rewrite_round": 0,
        "queries_tried": [],
        "candidates": [],
        "graph_paths": [],
        "context": [],
        "citations": [],
    }

    t0 = time.time()
    thread_id = f"api_{uuid.uuid4().hex[:10]}"
    try:
        out = agent.invoke(
            initial_state,
            config={"configurable": {"thread_id": thread_id}, "recursion_limit": 50},
        )
    except Exception as exc:
        logger.exception("Error executing SecuRAG agent: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Agent execution failed: {str(exc)}",
        ) from exc

    latency_ms = (time.time() - t0) * 1000.0

    return AskResponse(
        answer=out.get("answer") or "No answer generated.",
        citations=out.get("citations", []),
        route=out.get("route", "simple"),
        rounds=out.get("rewrite_round", 0),
        latency_ms=round(latency_ms, 2),
        trace_url=None,
        graph_paths=out.get("graph_paths", []),
        context=out.get("context", []),
    )
