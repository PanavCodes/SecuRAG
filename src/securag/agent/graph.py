"""LangGraph StateGraph assembly, conditional edges, and checkpointer for SecuRAG."""

import logging
from typing import Literal, Any
from langgraph.graph import StateGraph, START, END
from langgraph.checkpoint.memory import MemorySaver

from securag.agent.state import AgentState
from securag.agent.nodes import (
    route_query_node,
    retrieve_hybrid_node,
    retrieve_graph_node,
    rerank_node,
    grade_documents_node,
    refine_context_node,
    rewrite_query_node,
    web_fallback_node,
    generate_node,
    reflect_node,
)
from securag.config import get_settings

logger = logging.getLogger(__name__)


def route_decision(state: AgentState) -> Literal["web_fallback", "retrieve_graph", "retrieve_hybrid"]:
    """Conditional edge after route_query."""
    route = state.get("route", "simple")
    if route == "out_of_kb":
        return "web_fallback"
    elif route == "multi_hop":
        return "retrieve_graph"
    return "retrieve_hybrid"


def grade_decision(state: AgentState) -> Literal["refine_context", "rewrite_query", "web_fallback"]:
    """Conditional edge after grade_documents."""
    settings = get_settings()
    cfg = state.get("config", {})
    verdict = state.get("verdict", "correct")
    rounds = state.get("rewrite_round", 0)
    max_rounds = cfg.get("max_rewrite_rounds", settings.max_rewrite_rounds)
    use_crag = cfg.get("use_crag_loop", settings.use_crag_loop)

    if verdict in ["correct", "ambiguous"]:
        return "refine_context"

    # Verdict is incorrect: check if CRAG loop is enabled and rounds remain
    if use_crag and rounds < max_rounds:
        return "rewrite_query"

    return "web_fallback"


def build_agent_graph(checkpointer: Any = None) -> Any:
    """Build and compile the full SecuRAG LangGraph StateGraph."""
    builder = StateGraph(AgentState)

    # 1. Add all nodes
    builder.add_node("route_query", route_query_node)
    builder.add_node("retrieve_graph", retrieve_graph_node)
    builder.add_node("retrieve_hybrid", retrieve_hybrid_node)
    builder.add_node("rerank", rerank_node)
    builder.add_node("grade_documents", grade_documents_node)
    builder.add_node("refine_context", refine_context_node)
    builder.add_node("rewrite_query", rewrite_query_node)
    builder.add_node("web_fallback", web_fallback_node)
    builder.add_node("generate", generate_node)
    builder.add_node("reflect", reflect_node)

    # 2. Add control flow edges
    builder.add_edge(START, "route_query")

    builder.add_conditional_edges(
        "route_query",
        route_decision,
        {
            "web_fallback": "web_fallback",
            "retrieve_graph": "retrieve_graph",
            "retrieve_hybrid": "retrieve_hybrid",
        },
    )

    # Multi-hop branches to graph retrieval first, then hybrid
    builder.add_edge("retrieve_graph", "retrieve_hybrid")
    builder.add_edge("retrieve_hybrid", "rerank")
    builder.add_edge("rerank", "grade_documents")

    builder.add_conditional_edges(
        "grade_documents",
        grade_decision,
        {
            "refine_context": "refine_context",
            "rewrite_query": "rewrite_query",
            "web_fallback": "web_fallback",
        },
    )

    # Rewrite loop loops back to retrieve_hybrid
    builder.add_edge("rewrite_query", "retrieve_hybrid")

    # Final answer synthesis & reflection
    builder.add_edge("refine_context", "generate")
    builder.add_edge("web_fallback", "generate")
    builder.add_edge("generate", "reflect")
    builder.add_edge("reflect", END)

    memory = checkpointer or MemorySaver()
    return builder.compile(checkpointer=memory)


_agent_instance: Any = None


def get_agent() -> Any:
    """Return the global compiled SecuRAG agent."""
    global _agent_instance
    if _agent_instance is None:
        _agent_instance = build_agent_graph()
    return _agent_instance
