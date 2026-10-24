"""Acceptance test for Step 12: Observability and runtime metrics logging."""

import json
from pathlib import Path
import pytest

from securag.agent.graph import build_agent_graph
from securag.eval.metrics_logger import log_query_metrics, compute_metrics_summary


@pytest.fixture(scope="module")
def agent():
    return build_agent_graph()


def test_twenty_query_metrics_logging_and_p50_p95(agent):
    """Run all 20 dev questions, verify CSV output, and compute P50/P95 latencies.

    Mandated by Step 12 acceptance criteria:
    'after a 20-query run, a CSV results/runtime_metrics.csv exists with P50 / P95 latency
    computed by a script scripts/summarize_metrics.py.'
    """
    dev_path = Path("data/eval/dev.jsonl")
    assert dev_path.exists(), "dev.jsonl not found"

    questions = []
    with dev_path.open("r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                questions.append(json.loads(line))

    assert len(questions) == 20, f"Expected 20 questions in dev set, got {len(questions)}"

    csv_path = Path("results/runtime_metrics.csv")
    # Clean previous run if exists
    if csv_path.exists():
        csv_path.unlink()

    print(f"\n--- Running 20-Query Observability Evaluation ---", flush=True)

    for idx, q in enumerate(questions, 1):
        q_id = q["id"]
        q_text = q["question"]

        initial_state = {
            "question": q_text,
            "config": {
                "use_router": True,
                "use_crag_loop": True,
                "use_reflection": True,
                "use_cross_encoder": True,
                "use_graph_retrieval": True,
                "use_graph_rerank": True,
            },
            "rewrite_round": 0,
            "queries_tried": [],
            "candidates": [],
            "graph_paths": [],
            "context": [],
            "citations": [],
        }

        config = {"configurable": {"thread_id": f"metrics_eval_{q_id}"}, "recursion_limit": 50}
        out = agent.invoke(initial_state, config=config)

        # Log metrics to CSV
        rec = log_query_metrics(out, csv_path=csv_path, query_id=q_id)

        print(
            f"[{idx}/20] {q_id} ({rec['route']}): total={rec['total_latency_ms']}ms, "
            f"tokens_in={rec['tokens_in']}, tokens_out={rec['tokens_out']}",
            flush=True,
        )

    # Acceptance assertions
    assert csv_path.exists(), "runtime_metrics.csv was not created"

    summary = compute_metrics_summary(csv_path)
    assert summary["query_count"] == 20, f"Expected 20 logged query records, got {summary['query_count']}"

    total_stats = summary["latency_ms"]["total"]
    assert total_stats["p50"] > 0, "P50 latency must be positive"
    assert total_stats["p95"] > 0, "P95 latency must be positive"
    assert total_stats["p95"] >= total_stats["p50"], "P95 must be >= P50"

    print("\n" + "=" * 60)
    print("Step 12 Observability Acceptance: SUMMARY RESULTS")
    print("=" * 60)
    print(f"Total Queries: {summary['query_count']}")
    print(f"Routes: {summary['routes']}")
    print(f"P50 Total Latency: {total_stats['p50']} ms")
    print(f"P95 Total Latency: {total_stats['p95']} ms")
    print(f"Mean Latency: {total_stats['mean']} ms")
    print(f"Total Tokens: {summary['tokens']['total_tokens_in'] + summary['tokens']['total_tokens_out']}")
    print(f"Total Estimated Cost: ${summary['cost_usd']['total_cost']:.6f} USD")
    print("=" * 60)
