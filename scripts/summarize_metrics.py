"""Summarize runtime metrics from results/runtime_metrics.csv (P50, P95 latencies, tokens, costs)."""

import sys
from pathlib import Path

# Add src to pythonpath
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from securag.eval.metrics_logger import compute_metrics_summary


def main():
    csv_path = Path("results/runtime_metrics.csv")
    if not csv_path.exists():
        print(f"Error: {csv_path} does not exist. Run queries first.")
        sys.exit(1)

    summary = compute_metrics_summary(csv_path)

    print("=" * 60)
    print("SecuRAG Runtime Performance & Observability Summary")
    print("=" * 60)
    print(f"Total Queries Evaluated: {summary['query_count']}")
    print(f"Route Breakdown: {summary['routes']}")
    print("-" * 60)
    print("LATENCY STATISTICS (ms):")
    total = summary["latency_ms"]["total"]
    print(f"  Total Pipeline Latency: Mean={total['mean']}ms | P50={total['p50']}ms | P95={total['p95']}ms (Min={total['min']}ms, Max={total['max']}ms)")
    for node, stats in summary["latency_ms"].items():
        if node != "total":
            print(f"  - Node '{node}': P50={stats['p50']}ms | P95={stats['p95']}ms")
    print("-" * 60)
    print("TOKEN & COST METRICS:")
    tok = summary["tokens"]
    print(f"  Tokens: Avg In={tok['mean_tokens_in']} | Avg Out={tok['mean_tokens_out']} | Total={tok['total_tokens_in'] + tok['total_tokens_out']}")
    cost = summary["cost_usd"]
    print(f"  Cost: Total=${cost['total_cost']:.6f} USD | Avg/Query=${cost['mean_cost_per_query']:.6f} USD")
    print("=" * 60)


if __name__ == "__main__":
    main()
