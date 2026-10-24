"""Acceptance tests for Step 8: GraphER topological smoothing and CrossEncoder reranking."""

import pytest

from securag.retrieval.graph_rerank import (
    extract_relation_keys,
    build_candidate_graph,
    graph_cohesive_smoothing,
)
from securag.retrieval.rerank import cross_encoder_rerank, rerank_candidates


def test_grapher_smoothing_boosts_connected_candidate():
    """Verify GraphER cohesive smoothing boosts a low-scored candidate sharing keys with high-scored ones."""
    candidates = [
        {
            "chunk_id": "c1",
            "source_id": "CVE-2024-0001",
            "score": 0.90,
            "text": "Critical flaw in web portal",
            "metadata": {"cwe_ids": ["CWE-79"], "technique_ids": ["T1059"]},
        },
        {
            "chunk_id": "c2",
            "source_id": "CVE-2024-0002",
            "score": 0.85,
            "text": "Cross-site scripting in form input",
            "metadata": {"cwe_ids": ["CWE-79"]},
        },
        {
            "chunk_id": "c3",
            "source_id": "CVE-2024-0003",
            "score": 0.20,  # Initially very low score (rank 4)
            "text": "Secondary script injection vector",
            "metadata": {"cwe_ids": ["CWE-79"], "technique_ids": ["T1059"]},  # Shares keys with c1 and c2!
        },
        {
            "chunk_id": "c4",
            "source_id": "CVE-2024-0004",
            "score": 0.45,  # Higher than c3 initially (rank 3), but completely isolated
            "text": "SQL injection in reporting database",
            "metadata": {"cwe_ids": ["CWE-89"]},  # No common keys with c1, c2, c3
        },
    ]

    # Verify initial ranks: c1 (0.90), c2 (0.85), c4 (0.45), c3 (0.20)
    initial_order = [c["chunk_id"] for c in sorted(candidates, key=lambda x: x["score"], reverse=True)]
    assert initial_order == ["c1", "c2", "c4", "c3"], f"Expected initial order, got {initial_order}"

    # Apply GraphER smoothing with alpha=0.5
    smoothed = graph_cohesive_smoothing(candidates, alpha=0.5, iterations=2)
    smoothed_map = {c["chunk_id"]: c for c in smoothed}
    smoothed_order = [c["chunk_id"] for c in smoothed]

    print("\n--- GraphER Candidate Smoothing Results ---")
    for idx, c in enumerate(smoothed, 1):
        print(f"  {idx}. [{c['chunk_id']}] Initial: {c['pre_graph_score']:.2f} -> Smoothed: {c['score']:.4f}")
    print("-------------------------------------------")

    # 1. c3 must receive a significant score boost from neighbors c1 and c2
    assert smoothed_map["c3"]["score"] > 0.45, (
        f"Expected c3 score to exceed 0.45, got {smoothed_map['c3']['score']:.4f}"
    )

    # 2. c3 must move UP in rank ahead of isolated candidate c4
    assert smoothed_order.index("c3") < smoothed_order.index("c4"), (
        f"Expected c3 to rank higher than c4 after smoothing, got order: {smoothed_order}"
    )


def test_cross_encoder_rerank():
    """Verify CrossEncoder scores relevant security candidate higher than irrelevant text."""
    query = "Apache Log4j remote code execution vulnerability"
    candidates = [
        {
            "chunk_id": "c_relevant",
            "source_id": "CVE-2021-44228",
            "score": 0.1,  # Lower dense score
            "text": "Apache Log4j2 JNDI features used in configuration do not protect against attacker controlled LDAP.",
            "via": "dense",
        },
        {
            "chunk_id": "c_irrelevant",
            "source_id": "RECIPE-1",
            "score": 0.9,  # Artificially high dense score
            "text": "Bake delicious double chocolate chip cookies at 350 degrees for 12 minutes.",
            "via": "dense",
        },
    ]

    reranked = cross_encoder_rerank(query, candidates, top_n=2)
    print("\n--- CrossEncoder Rerank Results ---")
    for idx, c in enumerate(reranked, 1):
        print(f"  {idx}. [{c['chunk_id']}] CE Score: {c['cross_encoder_score']:.4f} - {c['text'][:50]}...")
    print("-----------------------------------")

    assert len(reranked) == 2
    assert reranked[0]["chunk_id"] == "c_relevant", (
        f"Expected relevant chunk at rank 1, got {reranked[0]['chunk_id']}"
    )
    assert reranked[0]["cross_encoder_score"] > reranked[1]["cross_encoder_score"]


def test_independent_flags_toggle():
    """Verify rerank flags (GraphER and CrossEncoder) toggle independently."""
    candidates = [
        {
            "chunk_id": "c1",
            "source_id": "CVE-1",
            "score": 0.3,
            "text": "Flaw A",
            "metadata": {"cwe_ids": ["CWE-1"]},
        },
        {
            "chunk_id": "c2",
            "source_id": "CVE-2",
            "score": 0.8,
            "text": "Flaw B",
            "metadata": {"cwe_ids": ["CWE-1"]},
        },
    ]

    # 1. GraphER ON, CrossEncoder OFF
    res_graph_only = rerank_candidates(
        "query", candidates, use_graph_rerank=True, use_cross_encoder=False, top_n=2
    )
    assert any("grapher" in c.get("via", "") for c in res_graph_only)
    assert not any("cross_encoder" in c.get("via", "") for c in res_graph_only)

    # 2. GraphER OFF, CrossEncoder ON
    res_ce_only = rerank_candidates(
        "query", candidates, use_graph_rerank=False, use_cross_encoder=True, top_n=2
    )
    assert not any("grapher" in c.get("via", "") for c in res_ce_only)
    assert any("cross_encoder" in c.get("via", "") for c in res_ce_only)

    # 3. Both OFF
    res_none = rerank_candidates(
        "query", candidates, use_graph_rerank=False, use_cross_encoder=False, top_n=2
    )
    assert not any("grapher" in c.get("via", "") for c in res_none)
    assert not any("cross_encoder" in c.get("via", "") for c in res_none)
