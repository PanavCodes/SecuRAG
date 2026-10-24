"""GraphER topological reranker implemented from arXiv:2603.24925 (Miao et al., Oracle AI).

Paper: "GraphER: Graph-Enhanced Reranking via Query-Time Graph Smoothing"
No public implementation exists.
Implementation: Relation key extraction from candidates + Graph Cohesive Smoothing.
Simplifications documented in NOTES.md.
"""

import logging
from typing import Any

logger = logging.getLogger(__name__)


def extract_relation_keys(candidate: dict[str, Any]) -> set[str]:
    """Extract relation keys (CWE, Technique, CAPEC, Product) from candidate metadata and text."""
    keys: set[str] = set()

    meta = candidate.get("metadata", {})
    if not isinstance(meta, dict):
        meta = {}

    # 1. Source ID itself
    sid = candidate.get("source_id") or meta.get("source_id")
    if sid:
        keys.add(str(sid).strip().upper())

    # 2. CWE IDs
    cwe_ids = meta.get("cwe_ids") or []
    if isinstance(cwe_ids, list):
        for cwe in cwe_ids:
            if cwe:
                keys.add(str(cwe).strip().upper())

    # 3. Technique IDs
    tech_ids = meta.get("technique_ids") or []
    if isinstance(tech_ids, list):
        for tech in tech_ids:
            if tech:
                keys.add(str(tech).strip().upper())

    # 4. CAPEC IDs
    capec_ids = meta.get("capec_ids") or []
    if isinstance(capec_ids, list):
        for capec in capec_ids:
            if capec:
                keys.add(str(capec).strip().upper())

    # 5. Affected Products
    products = meta.get("affected_products") or []
    if isinstance(products, list):
        for prod in products:
            if prod:
                keys.add(f"PROD:{str(prod).strip().lower()}")

    return keys


def build_candidate_graph(candidates: list[dict[str, Any]]) -> list[set[int]]:
    """Build candidate graph where edges connect candidates sharing at least one relation key."""
    n = len(candidates)
    candidate_keys = [extract_relation_keys(c) for c in candidates]
    neighbors: list[set[int]] = [set() for _ in range(n)]

    for i in range(n):
        for j in range(i + 1, n):
            common = candidate_keys[i].intersection(candidate_keys[j])
            if common:
                neighbors[i].add(j)
                neighbors[j].add(i)

    return neighbors


def graph_cohesive_smoothing(
    candidates: list[dict[str, Any]],
    alpha: float = 0.7,
    iterations: int = 2,
) -> list[dict[str, Any]]:
    """Run Graph Cohesive Smoothing over candidate initial scores.

    Score update rule:
        score_i^(t+1) = alpha * score_i^(0) + (1 - alpha) * mean_{j in N(i)}(score_j^(t))
    If candidate has no neighbors, initial score is retained.
    """
    if not candidates:
        return []

    n = len(candidates)
    neighbors = build_candidate_graph(candidates)

    initial_scores = [float(c.get("score", 0.0)) for c in candidates]
    current_scores = list(initial_scores)

    for _ in range(iterations):
        next_scores = list(current_scores)
        for i in range(n):
            nbrs = neighbors[i]
            if nbrs:
                mean_nbr = sum(current_scores[j] for j in nbrs) / len(nbrs)
                next_scores[i] = alpha * initial_scores[i] + (1.0 - alpha) * mean_nbr
            else:
                next_scores[i] = current_scores[i]
        current_scores = next_scores

    # Build reranked candidates with updated smoothed scores
    smoothed_candidates: list[dict[str, Any]] = []
    for idx, c in enumerate(candidates):
        item = dict(c)
        item["pre_graph_score"] = initial_scores[idx]
        item["score"] = current_scores[idx]
        item["via"] = f"{c.get('via', 'unknown')}+grapher"
        smoothed_candidates.append(item)

    # Sort descending by smoothed score
    smoothed_candidates.sort(key=lambda x: x["score"], reverse=True)
    return smoothed_candidates
