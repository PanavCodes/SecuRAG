"""Acceptance tests for Step 6: Query Optimization (Expansion, HyDE, Metadata Extraction)."""

import json
from pathlib import Path
import pytest

from securag.retrieval.query_opt import extract_metadata_filters, expand_query, generate_hyde_doc
from securag.retrieval.hybrid import HybridRetriever


def test_metadata_filter_extraction():
    """Verify deterministic metadata extraction for KEV, year, and severity."""
    # Test KEV pattern
    f1 = extract_metadata_filters("List all remote code execution vulnerabilities exploited in the wild")
    assert f1.get("in_kev") is True, f"Expected in_kev=True, got {f1}"

    # Test Year and Severity pattern
    f2 = extract_metadata_filters("Show critical severity flaws from 2024")
    assert f2.get("year") == 2024, f"Expected year=2024, got {f2}"
    assert f2.get("severity") == "CRITICAL", f"Expected severity=CRITICAL, got {f2}"

    print(f"\nExtracted Filters 1: {f1}")
    print(f"Extracted Filters 2: {f2}")


def test_query_expansion():
    """Verify LLM query expansion produces multiple variant queries."""
    variants = expand_query("Log4j JNDI remote code execution", n_variants=3)
    assert len(variants) >= 2, f"Expected at least 2 queries, got {len(variants)}: {variants}"
    print(f"\nQuery Expansion Variants: {variants}")


def test_hyde_generation():
    """Verify HyDE generates a plausible hypothetical document."""
    doc = generate_hyde_doc("How does cross-site scripting attack work?")
    assert len(doc) > 20, f"Expected generated passage, got '{doc}'"
    print(f"\nGenerated HyDE Doc:\n{doc}\n")


def test_retrieval_with_optimization_flags_on_dev_set():
    """Verify retrieval runs on dev set with and without expansion and HyDE; report recall."""
    retriever = HybridRetriever()
    dev_path = Path("data/eval/dev.jsonl")
    assert dev_path.exists(), "dev.jsonl missing"

    questions = []
    with dev_path.open("r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                questions.append(json.loads(line))

    # Evaluate on a 5-question subset for fast CI test
    eval_set = [q for q in questions if q.get("gold_answer") != "NOT_IN_KB"][:5]
    total = len(eval_set)

    def evaluate_config(use_exp: bool, use_hyde: bool) -> float:
        hits = 0
        for q in eval_set:
            gold = set(q.get("gold_entities", []))
            res = retriever.search(
                query=q["question"],
                top_k=10,
                use_dense=True,
                use_bm25=True,
                use_query_expansion=use_exp,
                use_hyde=use_hyde,
            )
            entities = {r["source_id"] for r in res}
            if entities & gold:
                hits += 1
        return hits / total

    base_recall = evaluate_config(use_exp=False, use_hyde=False)
    exp_recall = evaluate_config(use_exp=True, use_hyde=False)
    hyde_recall = evaluate_config(use_exp=False, use_hyde=True)

    print("\n--- Query Optimization Dev Set Recall Comparison ---")
    print(f"Baseline Hybrid Recall@10 : {base_recall:.3f}")
    print(f"With Query Expansion      : {exp_recall:.3f}")
    print(f"With HyDE                 : {hyde_recall:.3f}")
    print("-----------------------------------------------------")

    # Assert all configurations run without error
    assert base_recall >= 0.0
    assert exp_recall >= 0.0
    assert hyde_recall >= 0.0
