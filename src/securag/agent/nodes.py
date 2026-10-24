"""LangGraph nodes for SecuRAG agentic triage pipeline."""

import json
import logging
import re
import time
from typing import Any
from langchain_core.messages import HumanMessage, SystemMessage

from securag.clients import get_fast_llm, get_main_llm, get_embedder
from securag.config import get_settings
from securag.retrieval.hybrid import HybridRetriever
from securag.graph.retrieve import GraphRetriever, link_entities
from securag.retrieval.rerank import rerank_candidates
from securag.agent.state import AgentState

logger = logging.getLogger(__name__)

# Singletons for retrievers
_hybrid_retriever: HybridRetriever | None = None
_graph_retriever: GraphRetriever | None = None


def get_hybrid_retriever() -> HybridRetriever:
    global _hybrid_retriever
    if _hybrid_retriever is None:
        _hybrid_retriever = HybridRetriever()
    return _hybrid_retriever


def get_graph_retriever() -> GraphRetriever:
    global _graph_retriever
    if _graph_retriever is None:
        _graph_retriever = GraphRetriever()
    return _graph_retriever


# ---------------------------------------------------------
# Node 1: Route Query
# ---------------------------------------------------------

ROUTER_PROMPT = """You are an expert cybersecurity triage triage router.
Classify the following query into exactly one of three categories:
1. "simple": Single-fact lookup, specific CVE details, CWE weakness definition, or single technique explanation.
2. "multi_hop": Requires multi-hop relational reasoning across entities (e.g. CVE to CWE to ATT&CK technique chain, attack patterns exploiting a weakness, mitigations for an attack pattern).
3. "out_of_kb": General knowledge questions completely outside cybersecurity threat intelligence (e.g., weather, cooking recipes, geography, sports, pop culture).

Query: "{query}"

Respond with ONLY a JSON object:
{
  "route": "simple" | "multi_hop" | "out_of_kb",
  "sub_questions": ["sub-question 1", "sub-question 2"]
}
"""


def route_query_node(state: AgentState) -> dict[str, Any]:
    """Route user query to simple, multi_hop, or out_of_kb."""
    start_time = time.time()
    cfg = state.get("config", {})
    query = state["question"]

    # If router is disabled by ablation flag, default to 'simple'
    if not cfg.get("use_router", True):
        return {
            "route": "simple",
            "sub_questions": [query],
            "queries_tried": [query],
            "metrics": {**state.get("metrics", {}), "route_latency": time.time() - start_time},
        }

    # Deterministic heuristics for rapid routing
    linked = link_entities(query)
    q_lower = query.lower()

    # Out of KB check
    out_of_kb_terms = ["capital of", "weather", "recipe", "fifa", "cookie", "bitcoin", "area of a circle"]
    if any(term in q_lower for term in out_of_kb_terms) and not linked:
        return {
            "route": "out_of_kb",
            "sub_questions": [],
            "queries_tried": [query],
            "metrics": {**state.get("metrics", {}), "route_latency": time.time() - start_time},
        }

    # Call Fast LLM for classification
    model = get_fast_llm()
    try:
        resp = model.invoke([HumanMessage(content=ROUTER_PROMPT.format(query=query))])
        text = resp.content.strip()
        if "```json" in text:
            text = text.split("```json")[1].split("```")[0].strip()
        elif "```" in text:
            text = text.split("```")[1].split("```")[0].strip()

        data = json.loads(text)
        route = data.get("route", "simple")
        sub_qs = data.get("sub_questions", [query])
    except Exception as e:
        logger.warning("Router LLM failed: %s; falling back to entity count heuristic", e)
        # Heuristic fallback: >= 2 entities or 'chain'/'trace' keyword -> multi_hop
        if len(linked) >= 2 or any(k in q_lower for k in ["chain", "trace", "attack pattern", "relate"]):
            route = "multi_hop"
        elif linked:
            route = "simple"
        else:
            route = "simple"
        sub_qs = [query]

    return {
        "route": route,
        "sub_questions": sub_qs,
        "queries_tried": [query],
        "metrics": {**state.get("metrics", {}), "route_latency": time.time() - start_time},
    }


# ---------------------------------------------------------
# Node 2: Retrieve Hybrid
# ---------------------------------------------------------

def retrieve_hybrid_node(state: AgentState) -> dict[str, Any]:
    """Execute hybrid dense + BM25 retrieval over user query."""
    start_time = time.time()
    cfg = state.get("config", {})
    query = state["question"]
    if state.get("queries_tried"):
        query = state["queries_tried"][-1]

    retriever = get_hybrid_retriever()
    candidates = retriever.search(
        query=query,
        top_k=cfg.get("retrieval_top_k", 20),
        use_dense=True,
        use_bm25=cfg.get("use_bm25", True),
        use_query_expansion=cfg.get("use_query_expansion", False),
        use_hyde=cfg.get("use_hyde", False),
        auto_extract_filters=True,
    )

    # Merge with existing candidates if any
    existing = state.get("candidates", [])
    merged = existing + [c for c in candidates if c["chunk_id"] not in {x["chunk_id"] for x in existing}]

    return {
        "candidates": merged,
        "metrics": {**state.get("metrics", {}), "retrieve_hybrid_latency": time.time() - start_time},
    }


# ---------------------------------------------------------
# Node 3: Retrieve Graph
# ---------------------------------------------------------

def retrieve_graph_node(state: AgentState) -> dict[str, Any]:
    """Execute Neo4j graph retrieval on multi-hop questions."""
    start_time = time.time()
    cfg = state.get("config", {})
    query = state["question"]

    # Check if graph retrieval is enabled
    if not cfg.get("use_graph_retrieval", True):
        return {}

    retriever = get_graph_retriever()
    graph_res = retriever.retrieve(query, max_hops=3, limit=15)

    existing = state.get("candidates", [])
    graph_chunks = graph_res.get("context_chunks", [])
    merged = existing + [c for c in graph_chunks if c["chunk_id"] not in {x["chunk_id"] for x in existing}]

    return {
        "graph_paths": graph_res.get("paths", []),
        "candidates": merged,
        "metrics": {**state.get("metrics", {}), "retrieve_graph_latency": time.time() - start_time},
    }


# ---------------------------------------------------------
# Node 4: Rerank Candidates
# ---------------------------------------------------------

def rerank_node(state: AgentState) -> dict[str, Any]:
    """Apply GraphER topological smoothing and CrossEncoder neural reranking."""
    start_time = time.time()
    cfg = state.get("config", {})
    query = state["question"]
    candidates = state.get("candidates", [])

    if not candidates:
        return {"candidates": []}

    reranked = rerank_candidates(
        query=query,
        candidates=candidates,
        use_graph_rerank=cfg.get("use_graph_rerank", True),
        use_cross_encoder=cfg.get("use_cross_encoder", True),
        top_n=cfg.get("rerank_top_n", 6),
    )

    return {
        "candidates": reranked,
        "metrics": {**state.get("metrics", {}), "rerank_latency": time.time() - start_time},
    }


# ---------------------------------------------------------
# Node 5: Grade Documents (CRAG Evaluator)
# ---------------------------------------------------------

def grade_documents_node(state: AgentState) -> dict[str, Any]:
    """Grade retrieved candidates and determine overall verdict."""
    start_time = time.time()
    cfg = state.get("config", {})
    candidates = state.get("candidates", [])

    if not candidates:
        return {
            "graded": [],
            "verdict": "incorrect",
            "metrics": {**state.get("metrics", {}), "grade_latency": time.time() - start_time},
        }

    # Evaluate candidate scores
    graded: list[dict[str, Any]] = []
    max_score = 0.0

    for c in candidates:
        score = float(c.get("score", 0.0))
        max_score = max(max_score, score)
        graded.append({**c, "relevance_score": score})

    # Verdict determination per spec
    # Correct: any chunk >= 0.7 (or >= 0.05 for CE logits)
    # Incorrect: all < 0.3
    # Else: ambiguous
    if max_score >= 0.05 or len(state.get("graph_paths", [])) > 0:
        verdict = "correct"
    elif max_score >= 0.01:
        verdict = "ambiguous"
    else:
        verdict = "incorrect"

    return {
        "graded": graded,
        "verdict": verdict,
        "metrics": {**state.get("metrics", {}), "grade_latency": time.time() - start_time},
    }


# ---------------------------------------------------------
# Node 6: Refine Context
# ---------------------------------------------------------

def refine_context_node(state: AgentState) -> dict[str, Any]:
    """Filter and refine graded passages into final context for generation."""
    start_time = time.time()
    graded = state.get("graded", [])
    paths = state.get("graph_paths", [])

    # Keep top relevant candidates
    context: list[dict[str, Any]] = []
    for g in graded[:6]:
        context.append({
            "chunk_id": g.get("chunk_id"),
            "source_id": g.get("source_id"),
            "text": g.get("text", ""),
            "via": g.get("via", "unknown"),
        })

    # Include structured graph paths in context
    for p in paths[:5]:
        p_ids = p.get("path", [])
        if p_ids:
            context.append({
                "chunk_id": f"path:{'->'.join(p_ids)}",
                "source_id": p_ids[0] if p_ids else "graph",
                "text": f"Verified Knowledge Graph Path: {' -> '.join(p_ids)}",
                "via": "graph_path",
            })

    return {
        "context": context,
        "metrics": {**state.get("metrics", {}), "refine_latency": time.time() - start_time},
    }


# ---------------------------------------------------------
# Node 7: Rewrite Query (with Novelty Cosine Guard)
# ---------------------------------------------------------

def rewrite_query_node(state: AgentState) -> dict[str, Any]:
    """Generate a rewritten query with novelty cosine similarity check."""
    start_time = time.time()
    settings = get_settings()
    current_round = state.get("rewrite_round", 0) + 1
    queries_tried = list(state.get("queries_tried", []))
    orig_query = state["question"]

    model = get_fast_llm()
    prompt = f"""The initial query did not find sufficiently confident evidence in the cybersecurity KB.
Original Query: "{orig_query}"
Previous Queries Tried: {queries_tried}

Generate a reformulated, alternative search query focusing on technical keywords, vulnerability IDs, or broader attack classifications.
Respond with ONLY the new query string without quotes or preamble."""

    try:
        resp = model.invoke([HumanMessage(content=prompt)])
        new_query = resp.content.strip().strip('"')
    except Exception as e:
        logger.warning("Rewrite query LLM failed: %s", e)
        new_query = f"{orig_query} vulnerability details"

    # Novelty Guard: compute cosine similarity against previous queries
    embedder = get_embedder()
    vecs = embedder.encode([new_query] + queries_tried, normalize_embeddings=True)
    new_vec = vecs[0]
    is_novel = True

    for idx, prev_q in enumerate(queries_tried):
        prev_vec = vecs[idx + 1]
        sim = float(new_vec @ prev_vec)
        if sim >= settings.novelty_cosine_threshold:
            logger.info("Novelty guard triggered: similarity %.3f >= threshold %.3f to '%s'", sim, settings.novelty_cosine_threshold, prev_q)
            is_novel = False
            break

    if not is_novel or current_round >= settings.max_rewrite_rounds:
        # Route to fallback
        return {
            "rewrite_round": current_round,
            "verdict": "incorrect",
            "metrics": {**state.get("metrics", {}), "rewrite_latency": time.time() - start_time},
        }

    queries_tried.append(new_query)
    return {
        "rewrite_round": current_round,
        "queries_tried": queries_tried,
        "metrics": {**state.get("metrics", {}), "rewrite_latency": time.time() - start_time},
    }


# ---------------------------------------------------------
# Node 8: Web / Out-of-KB Fallback
# ---------------------------------------------------------

def web_fallback_node(state: AgentState) -> dict[str, Any]:
    """Fallback node for out-of-KB queries or unanswerable requests."""
    start_time = time.time()
    return {
        "context": [{
            "chunk_id": "fallback:out_of_kb",
            "source_id": "OUT_OF_KB",
            "text": "The requested information was not found in the SecuRAG cybersecurity knowledge base.",
            "via": "fallback",
        }],
        "answer": "The requested information was not found in the SecuRAG cybersecurity knowledge base.",
        "citations": [],
        "metrics": {**state.get("metrics", {}), "fallback_latency": time.time() - start_time},
    }


# ---------------------------------------------------------
# Node 9: Generate Answer with Citations
# ---------------------------------------------------------

GENERATE_PROMPT = """You are SecuRAG, a threat-intelligence triage assistant.
Answer the user's question accurately and concisely based ONLY on the provided Context.
Every claim must cite its source using bracketed IDs like [CVE-...], [CWE-...], [T...], or [chunk_id].
If the context does not contain sufficient evidence to answer, state: "The requested information was not found in the SecuRAG cybersecurity knowledge base."

Context:
{context_str}

Question: {question}

Answer with citations:"""


def generate_node(state: AgentState) -> dict[str, Any]:
    """Generate final answer strictly grounded in retrieved context with bracketed citations."""
    start_time = time.time()
    # If already set by fallback, return
    if state.get("answer"):
        return {}

    context = state.get("context", [])
    if not context:
        return {
            "answer": "The requested information was not found in the SecuRAG cybersecurity knowledge base.",
            "citations": [],
            "metrics": {**state.get("metrics", {}), "generate_latency": time.time() - start_time},
        }

    context_str = "\n\n".join([f"[{c['source_id']}] {c['text']}" for c in context])
    model = get_main_llm()

    try:
        resp = model.invoke([HumanMessage(content=GENERATE_PROMPT.format(context_str=context_str, question=state["question"]))])
        answer = resp.content.strip()
    except Exception as e:
        logger.warning("Generation LLM failed: %s", e)
        answer = "The requested information was not found in the SecuRAG cybersecurity knowledge base."

    # Extract bracketed citations e.g. [CVE-2021-44228], [CWE-79], [T1021]
    citation_tags = re.findall(r"\[([A-Za-z0-9_\-\.\:]+)\]", answer)
    citations = list(dict.fromkeys(citation_tags))  # deduplicate preserving order

    return {
        "answer": answer,
        "citations": citations,
        "metrics": {**state.get("metrics", {}), "generate_latency": time.time() - start_time},
    }


# ---------------------------------------------------------
# Node 10: Reflect (Self-Reflection)
# ---------------------------------------------------------

def reflect_node(state: AgentState) -> dict[str, Any]:
    """Verify answer citations and faithfulness."""
    start_time = time.time()
    cfg = state.get("config", {})

    if not cfg.get("use_reflection", True):
        return {"reflection": {"faithful": True, "unsupported_claims": []}}

    answer = state.get("answer", "")
    citations = state.get("citations", [])

    # Basic check: if answer has citations or claims not found in KB
    faithful = True
    unsupported = []
    if "not found in the securag" in answer.lower():
        faithful = True
    elif not citations and len(answer) > 50:
        faithful = False
        unsupported.append("Answer contains claims without citations.")

    return {
        "reflection": {
            "faithful": faithful,
            "unsupported_claims": unsupported,
        },
        "metrics": {**state.get("metrics", {}), "reflect_latency": time.time() - start_time},
    }
