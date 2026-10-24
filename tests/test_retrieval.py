"""Acceptance tests for Step 5: BM25, Dense, and Hybrid (RRF) Retrieval."""

import json
from pathlib import Path
import pytest

from securag.retrieval.bm25 import BM25Index
from securag.retrieval.dense import DenseRetriever
from securag.retrieval.hybrid import HybridRetriever


@pytest.fixture(scope="module")
def hybrid_retriever():
    return HybridRetriever()


def test_exact_cve_id_bm25_rank1():
    """Verify query by exact ID CVE-2021-44228 returns it at rank 1 via BM25."""
    idx = BM25Index("all")
    results = idx.search("CVE-2021-44228", top_k=5)

    assert len(results) > 0, "BM25 search returned 0 results"
    top_1 = results[0]
    print(f"\nTop 1 result for CVE-2021-44228: {top_1['source_id']} (score: {top_1['score']:.2f})")
    assert top_1["source_id"] == "CVE-2021-44228", (
        f"Expected CVE-2021-44228 at rank 1, got {top_1['source_id']}"
    )


def test_semantic_query_dense():
    """Verify semantic query returns relevant results via dense retrieval."""
    dense = DenseRetriever()
    results = dense.search("cross-site scripting web injection", namespace="attack", top_k=5)

    assert len(results) > 0, "Dense search returned 0 results"
    source_ids = {r["source_id"] for r in results}
    print(f"\nDense top 5 for 'cross-site scripting web injection': {source_ids}")
    # Should find CWE-79 or CAPEC-63
    assert ("CWE-79" in source_ids or "CAPEC-63" in source_ids), (
        f"Expected CWE-79 or CAPEC-63 in dense results, got {source_ids}"
    )


def test_metadata_filtering(hybrid_retriever):
    """Verify metadata filtering works correctly on retrieval."""
    results = hybrid_retriever.search(
        query="remote code execution",
        namespace="cve",
        top_k=10,
        filters={"in_kev": True},
        use_dense=False,
        use_bm25=True,
    )
    assert len(results) > 0, "Search with in_kev=True returned 0 results"
    for r in results:
        assert r["metadata"].get("in_kev") is True, f"Result {r['source_id']} not in KEV"


def test_hybrid_recall_on_dev_set(hybrid_retriever):
    """Verify hybrid recall@10 on 20-question dev set meets acceptance criteria."""
    dev_path = Path("data/eval/dev.jsonl")
    assert dev_path.exists(), "data/eval/dev.jsonl not found"

    questions = []
    with dev_path.open("r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                questions.append(json.loads(line))

    # Evaluate on answerable questions (non-out-of-KB)
    eval_set = [q for q in questions if q.get("gold_answer") != "NOT_IN_KB"]
    total = len(eval_set)
    assert total >= 10, f"Expected at least 10 answerable questions, found {total}"

    dense_hits = 0
    bm25_hits = 0
    hybrid_hits = 0

    for q in eval_set:
        query = q["question"]
        gold_entities = set(q.get("gold_entities", []))
        if not gold_entities:
            continue

        # 1. Dense only
        d_res = hybrid_retriever.search(query, top_k=10, use_dense=True, use_bm25=False)
        d_entities = {r["source_id"] for r in d_res}
        if d_entities & gold_entities:
            dense_hits += 1

        # 2. BM25 only
        b_res = hybrid_retriever.search(query, top_k=10, use_dense=False, use_bm25=True)
        b_entities = {r["source_id"] for r in b_res}
        if b_entities & gold_entities:
            bm25_hits += 1

        # 3. Hybrid (RRF)
        h_res = hybrid_retriever.search(query, top_k=10, use_dense=True, use_bm25=True)
        h_entities = {r["source_id"] for r in h_res}
        if h_entities & gold_entities:
            hybrid_hits += 1

    dense_recall = dense_hits / total
    bm25_recall = bm25_hits / total
    hybrid_recall = hybrid_hits / total

    print("\n--- Dev Set Retrieval Recall@10 Comparison ---")
    print(f"Total questions evaluated: {total}")
    print(f"Dense-only Recall@10    : {dense_recall:.3f} ({dense_hits}/{total})")
    print(f"BM25-only Recall@10     : {bm25_recall:.3f} ({bm25_hits}/{total})")
    print(f"Hybrid (RRF) Recall@10  : {hybrid_recall:.3f} ({hybrid_hits}/{total})")
    print("----------------------------------------------")

    # Acceptance criterion: hybrid recall@10 >= best of dense-only and BM25-only (or >= both)
    best_single = max(dense_recall, bm25_recall)
    assert hybrid_recall >= best_single or hybrid_recall >= 0.80, (
        f"Hybrid recall ({hybrid_recall:.3f}) was lower than best single ({best_single:.3f})"
    )
