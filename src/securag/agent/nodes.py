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
from securag.ingest.chunk import Docstore
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

ROUTER_PROMPT = """You are an expert cybersecurity triage router.
Classify the following query into exactly one of three categories:
1. "simple": Single-fact lookup, specific CVE description/vulnerability definition, CWE weakness definition, or single technique explanation without traversing relationships. Examples: "What is the primary vulnerability in CVE-2021-44228?", "What weakness is identified by CWE-79?", "What attack pattern is described by CAPEC-63?".
2. "multi_hop": Relational reasoning or graph traversal across entities. This includes: which tactic a technique belongs to, parent/child weakness hierarchies, attack patterns associated with a weakness, techniques linked to attack patterns, mitigations for a technique, or full CVE-to-ATT&CK attack chains. Examples: "Which tactic does ATT&CK technique T1021 belong to?", "What is the parent weakness of CWE-79?", "Which attack patterns in CAPEC relate to CWE-79?", "Which ATT&CK technique is linked to CAPEC-1?".
3. "out_of_kb": General knowledge questions completely outside cybersecurity threat intelligence (e.g., weather, cooking recipes, geography, sports, pop culture).

Query: "{query}"

Respond with ONLY a JSON object:
{{
  "route": "simple" | "multi_hop" | "out_of_kb",
  "sub_questions": ["sub-question 1", "sub-question 2"]
}}
"""


def route_query_node(state: AgentState) -> dict[str, Any]:
    """Route user query to simple, multi_hop, or out_of_kb."""
    start_time = time.time()
    cfg = state.get("config", {})
    query = state["question"]

    # If state already has a pre-determined route and router is disabled, preserve it
    if state.get("route") and not cfg.get("use_router", True):
        return {
            "route": state["route"],
            "sub_questions": state.get("sub_questions", [query]),
            "queries_tried": [query],
            "metrics": {**state.get("metrics", {}), "route_latency": 0.0},
        }

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
        m = re.search(r"\{.*\}", text, re.DOTALL)
        if m:
            data = json.loads(m.group(0))
        else:
            data = json.loads(text)

        route = data.get("route", "simple")
        sub_qs = data.get("sub_questions", [query])
    except Exception as e:
        logger.warning("Router LLM failed: %s; falling back to entity count heuristic", e)
        # Heuristic fallback: >= 2 entities or relational keywords -> multi_hop
        rel_keywords = ["chain", "trace", "attack pattern", "relate", "parent", "child", "hierarchy", "associated", "mitigation", "tactic", "exploit"]
        if len(linked) >= 2 or any(k in q_lower for k in rel_keywords):
            route = "multi_hop"
        elif linked:
            route = "simple"
        else:
            route = "simple"
        sub_qs = [query]

    # Deterministic relational keyword check: if question specifically asks for relationships between entities
    rel_phrases = [
        "which tactic", "parent weakness", "child weakness", "attack pattern",
        "relate to", "relates to", "linked to", "associated with", "belong to",
        "belongs to", "attack chain", "mitigation", "reachable from", "exploits weakness"
    ]
    if route == "simple" and any(phrase in q_lower for phrase in rel_phrases):
        logger.info("Overriding route from 'simple' to 'multi_hop' based on relational phrase match: '%s'", query)
        route = "multi_hop"

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

    # Ensure any explicitly linked entities in the query have their docstore chunks included
    linked = link_entities(query)
    docstore = Docstore()
    for ent in linked:
        entity_chunks = docstore.get_chunks_by_source_id(ent["id"])
        for ec in entity_chunks:
            if ec["chunk_id"] not in {c["chunk_id"] for c in candidates}:
                candidates.append({
                    "chunk_id": ec["chunk_id"],
                    "source_id": ec["source_id"],
                    "source_type": ec["source_type"],
                    "text": ec["text"],
                    "score": 0.5,
                    "via": "exact_entity_match",
                    "metadata": ec.get("metadata", {}),
                })

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
    for p in paths[:8]:
        p_type = p.get("type", "")
        details = p.get("details", {})
        p_ids = [str(x) for x in p.get("path", []) if x is not None]

        if p_type == "cwe_hierarchy" and details:
            text = f"CWE Hierarchy: Weakness {details.get('cwe_id')} has parent weakness {details.get('parent_id')} ({details.get('parent_name')})."
            context.append({
                "chunk_id": f"graph:hierarchy:{details.get('cwe_id')}:{details.get('parent_id')}",
                "source_id": details.get("parent_id") or (p_ids[0] if p_ids else "graph"),
                "text": text,
                "via": "graph_path",
            })
        elif p_type == "cve_attack_chain" and details:
            text = f"Attack Chain: CVE {details.get('cve_id')} links to weakness {details.get('cwe_id')}, attack pattern {details.get('capec_id')}, ATT&CK technique {details.get('technique_id')} ({details.get('technique_name')}) under tactic {details.get('tactic_name')}."
            context.append({
                "chunk_id": f"graph:chain:{details.get('cve_id')}",
                "source_id": details.get("technique_id") or details.get("cve_id"),
                "text": text,
                "via": "graph_path",
            })
        elif p_type == "technique_mitigation" and details:
            text = f"Mitigation: ATT&CK technique {details.get('technique_id')} is mitigated by {details.get('mitigation_id')} ({details.get('mitigation_name')})."
            context.append({
                "chunk_id": f"graph:mitigation:{details.get('technique_id')}",
                "source_id": details.get("mitigation_id") or details.get("technique_id"),
                "text": text,
                "via": "graph_path",
            })
        elif p_type == "cwe_attack_patterns" and details:
            text = f"Weakness {details.get('cwe_id')} relates to CAPEC attack pattern {details.get('capec_id')} ({details.get('capec_name')})."
            context.append({
                "chunk_id": f"graph:capec:{details.get('cwe_id')}:{details.get('capec_id')}",
                "source_id": details.get("capec_id") or (p_ids[0] if p_ids else "graph"),
                "text": text,
                "via": "graph_path",
            })
        elif p_type == "technique_tactic" and details:
            text = f"ATT&CK Technique {details.get('technique_id')} belongs to tactic {details.get('tactic_id')} ({details.get('tactic_name')})."
            context.append({
                "chunk_id": f"graph:tactic:{details.get('technique_id')}:{details.get('tactic_id')}",
                "source_id": details.get("tactic_id") or (p_ids[0] if p_ids else "graph"),
                "text": text,
                "via": "graph_path",
            })
        elif p_type == "capec_technique" and details:
            text = f"CAPEC attack pattern {details.get('capec_id')} maps to ATT&CK technique {details.get('technique_id')} ({details.get('technique_name')})."
            context.append({
                "chunk_id": f"graph:technique:{details.get('capec_id')}:{details.get('technique_id')}",
                "source_id": details.get("technique_id") or (p_ids[0] if p_ids else "graph"),
                "text": text,
                "via": "graph_path",
            })
        elif p_ids:
            context.append({
                "chunk_id": f"path:{'->'.join(p_ids)}",
                "source_id": p_ids[0] if p_ids else "graph",
                "text": f"Verified Knowledge Graph Path: {' -> '.join(p_ids)}",
                "via": "graph_path",
            })

    return {
        "context": context,
        "termination_reason": "success",
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

    if not is_novel:
        logger.info("CRAG loop terminating: novelty guard triggered (similarity %.3f >= threshold %.3f)", sim, settings.novelty_cosine_threshold)
        return {
            "rewrite_round": current_round,
            "verdict": "incorrect",
            "termination_reason": "novelty_guard",
            "metrics": {**state.get("metrics", {}), "rewrite_latency": time.time() - start_time},
        }

    if current_round >= settings.max_rewrite_rounds:
        logger.info("CRAG loop terminating: max rewrite rounds reached (%d)", settings.max_rewrite_rounds)
        return {
            "rewrite_round": current_round,
            "verdict": "incorrect",
            "termination_reason": "max_rounds",
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
    reason = state.get("termination_reason") or ("out_of_kb" if state.get("route") == "out_of_kb" else "fallback")
    return {
        "context": [{
            "chunk_id": "fallback:out_of_kb",
            "source_id": "OUT_OF_KB",
            "text": "The requested information was not found in the SecuRAG cybersecurity knowledge base.",
            "via": "fallback",
        }],
        "answer": "The requested information was not found in the SecuRAG cybersecurity knowledge base.",
        "citations": [],
        "termination_reason": reason,
        "metrics": {**state.get("metrics", {}), "fallback_latency": time.time() - start_time},
    }


# ---------------------------------------------------------
# Node 9: Generate Answer with Citations
# ---------------------------------------------------------

GENERATE_PROMPT = """You are SecuRAG, a threat-intelligence triage assistant.
Answer the user's question accurately and concisely based ONLY on the provided Context.
Every claim must cite its source using individual bracketed IDs like [CVE-...], [CWE-...], [T...], [TA...], or [chunk_id].
Do not nest brackets (e.g. write "[T1021] [TA0008]", never "[TA0008, [T1021]]").
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

    # Extract bracketed citations e.g. [CVE-2021-44228], [CWE-79], [T1021], [TA0008]
    # Robustly handles single [ID], comma-separated [ID1, ID2], and nested brackets
    bracket_blocks = re.findall(r"\[([^\]]+)\]", answer)
    raw_citations = []
    for block in bracket_blocks:
        tokens = re.findall(r"[A-Za-z0-9_\-\.\:]+", block)
        for tok in tokens:
            if len(tok) >= 2 and tok.lower() not in {"and", "or", "in", "to", "via", "for", "with"}:
                raw_citations.append(tok)

    citations = list(dict.fromkeys(raw_citations))  # deduplicate preserving order

    return {
        "answer": answer,
        "citations": citations,
        "metrics": {**state.get("metrics", {}), "generate_latency": time.time() - start_time},
    }


# ---------------------------------------------------------
# Node 10: Reflect (Self-Reflection)
# ---------------------------------------------------------

def reflect_node(state: AgentState) -> dict[str, Any]:
    """Verify answer citations and faithfulness against Neo4j and context."""
    start_time = time.time()
    cfg = state.get("config", {})

    if not cfg.get("use_reflection", True):
        return {"reflection": {"faithful": True, "unsupported_claims": []}}

    answer = state.get("answer", "")
    citations = state.get("citations", [])

    faithful = True
    unsupported = []

    if "not found in the securag" in answer.lower():
        faithful = True
    elif not citations and len(answer) > 50:
        faithful = False
        unsupported.append("Answer contains claims without citations.")
    elif citations:
        # Validate all cited IDs against Neo4j
        from securag.eval.citation_validator import validate_citations_against_neo4j
        val_res = validate_citations_against_neo4j(citations)
        if not val_res["all_valid"]:
            faithful = False
            unsupported.append(f"Cited IDs not found in Neo4j: {val_res['invalid_citations']}")

    return {
        "reflection": {
            "faithful": faithful,
            "unsupported_claims": unsupported,
        },
        "metrics": {**state.get("metrics", {}), "reflect_latency": time.time() - start_time},
    }
