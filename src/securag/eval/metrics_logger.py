"""Metrics logger for SecuRAG: captures per-node latency, tokens in/out, estimated cost, and route statistics."""

import csv
import logging
from pathlib import Path
from typing import Any
import numpy as np

from securag.agent.state import AgentState
from securag.config import get_settings

logger = logging.getLogger(__name__)

_ENCODER = None


def get_token_encoder() -> Any:
    """Return tiktoken encoder for cl100k_base."""
    global _ENCODER
    if _ENCODER is None:
        try:
            import tiktoken
            _ENCODER = tiktoken.get_encoding("cl100k_base")
        except Exception:
            _ENCODER = None
    return _ENCODER


def count_tokens(text: str) -> int:
    """Estimate token count for a text string using tiktoken or heuristic fallback."""
    if not text:
        return 0
    enc = get_token_encoder()
    if enc is not None:
        try:
            return len(enc.encode(text))
        except Exception:
            pass
    # Fallback heuristic: 1 token ≈ 4 characters
    return max(1, len(text) // 4)


CSV_COLUMNS = [
    "query_id",
    "question",
    "route",
    "rewrite_rounds",
    "total_latency_ms",
    "route_latency_ms",
    "retrieve_hybrid_latency_ms",
    "retrieve_graph_latency_ms",
    "rerank_latency_ms",
    "grade_latency_ms",
    "refine_latency_ms",
    "rewrite_latency_ms",
    "generate_latency_ms",
    "reflect_latency_ms",
    "fallback_latency_ms",
    "tokens_in",
    "tokens_out",
    "estimated_cost_usd",
]


def extract_metrics_record(state: AgentState, query_id: str = "") -> dict[str, Any]:
    """Extract metrics record dictionary from completed agent state."""
    settings = get_settings()
    node_metrics = state.get("metrics", {})

    route_lat = float(node_metrics.get("route_latency", 0.0)) * 1000.0
    hybrid_lat = float(node_metrics.get("retrieve_hybrid_latency", 0.0)) * 1000.0
    graph_lat = float(node_metrics.get("retrieve_graph_latency", 0.0)) * 1000.0
    rerank_lat = float(node_metrics.get("rerank_latency", 0.0)) * 1000.0
    grade_lat = float(node_metrics.get("grade_latency", 0.0)) * 1000.0
    refine_lat = float(node_metrics.get("refine_latency", 0.0)) * 1000.0
    rewrite_lat = float(node_metrics.get("rewrite_latency", 0.0)) * 1000.0
    gen_lat = float(node_metrics.get("generate_latency", 0.0)) * 1000.0
    reflect_lat = float(node_metrics.get("reflect_latency", 0.0)) * 1000.0
    fallback_lat = float(node_metrics.get("fallback_latency", 0.0)) * 1000.0

    total_lat = (
        route_lat
        + hybrid_lat
        + graph_lat
        + rerank_lat
        + grade_lat
        + refine_lat
        + rewrite_lat
        + gen_lat
        + reflect_lat
        + fallback_lat
    )

    # Token counting
    question = state.get("question", "")
    context = state.get("context", [])
    context_text = "\n".join([f"[{c.get('source_id', '')}] {c.get('text', '')}" for c in context])
    queries_tried = " ".join(state.get("queries_tried", []))

    tokens_in = count_tokens(question) + count_tokens(context_text) + count_tokens(queries_tried)
    answer = state.get("answer", "")
    tokens_out = count_tokens(answer)

    # Estimated cost calculation
    cost = (
        (tokens_in / 1_000_000.0) * settings.cost_per_1m_input_tokens
        + (tokens_out / 1_000_000.0) * settings.cost_per_1m_output_tokens
    )

    return {
        "query_id": query_id,
        "question": question,
        "route": state.get("route", "unknown"),
        "rewrite_rounds": state.get("rewrite_round", 0),
        "total_latency_ms": round(total_lat, 2),
        "route_latency_ms": round(route_lat, 2),
        "retrieve_hybrid_latency_ms": round(hybrid_lat, 2),
        "retrieve_graph_latency_ms": round(graph_lat, 2),
        "rerank_latency_ms": round(rerank_lat, 2),
        "grade_latency_ms": round(grade_lat, 2),
        "refine_latency_ms": round(refine_lat, 2),
        "rewrite_latency_ms": round(rewrite_lat, 2),
        "generate_latency_ms": round(gen_lat, 2),
        "reflect_latency_ms": round(reflect_lat, 2),
        "fallback_latency_ms": round(fallback_lat, 2),
        "tokens_in": tokens_in,
        "tokens_out": tokens_out,
        "estimated_cost_usd": round(cost, 6),
    }


def log_query_metrics(state: AgentState, csv_path: str | Path = "results/runtime_metrics.csv", query_id: str = "") -> dict[str, Any]:
    """Append a query's runtime metrics to the specified CSV file."""
    path = Path(csv_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    record = extract_metrics_record(state, query_id=query_id)
    write_header = not path.exists() or path.stat().st_size == 0

    with path.open("a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        if write_header:
            writer.writeheader()
        writer.writerow(record)

    return record


def compute_metrics_summary(csv_path: str | Path = "results/runtime_metrics.csv") -> dict[str, Any]:
    """Compute summary statistics including P50 and P95 latency from CSV."""
    path = Path(csv_path)
    if not path.exists():
        raise FileNotFoundError(f"Metrics CSV file not found: {path}")

    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            records.append(row)

    if not records:
        return {"query_count": 0}

    total_latencies = [float(r["total_latency_ms"]) for r in records]
    route_latencies = [float(r["route_latency_ms"]) for r in records]
    retrieve_hybrid_latencies = [float(r["retrieve_hybrid_latency_ms"]) for r in records]
    retrieve_graph_latencies = [float(r["retrieve_graph_latency_ms"]) for r in records]
    rerank_latencies = [float(r["rerank_latency_ms"]) for r in records]
    generate_latencies = [float(r["generate_latency_ms"]) for r in records]
    tokens_in = [int(r["tokens_in"]) for r in records]
    tokens_out = [int(r["tokens_out"]) for r in records]
    costs = [float(r["estimated_cost_usd"]) for r in records]

    routes: dict[str, int] = {}
    for r in records:
        rt = r.get("route", "unknown")
        routes[rt] = routes.get(rt, 0) + 1

    summary = {
        "query_count": len(records),
        "routes": routes,
        "latency_ms": {
            "total": {
                "mean": round(float(np.mean(total_latencies)), 2),
                "p50": round(float(np.percentile(total_latencies, 50)), 2),
                "p95": round(float(np.percentile(total_latencies, 95)), 2),
                "min": round(float(np.min(total_latencies)), 2),
                "max": round(float(np.max(total_latencies)), 2),
            },
            "route": {
                "p50": round(float(np.percentile(route_latencies, 50)), 2),
                "p95": round(float(np.percentile(route_latencies, 95)), 2),
            },
            "retrieve_hybrid": {
                "p50": round(float(np.percentile(retrieve_hybrid_latencies, 50)), 2),
                "p95": round(float(np.percentile(retrieve_hybrid_latencies, 95)), 2),
            },
            "retrieve_graph": {
                "p50": round(float(np.percentile(retrieve_graph_latencies, 50)), 2),
                "p95": round(float(np.percentile(retrieve_graph_latencies, 95)), 2),
            },
            "rerank": {
                "p50": round(float(np.percentile(rerank_latencies, 50)), 2),
                "p95": round(float(np.percentile(rerank_latencies, 95)), 2),
            },
            "generate": {
                "p50": round(float(np.percentile(generate_latencies, 50)), 2),
                "p95": round(float(np.percentile(generate_latencies, 95)), 2),
            },
        },
        "tokens": {
            "mean_tokens_in": round(float(np.mean(tokens_in)), 1),
            "mean_tokens_out": round(float(np.mean(tokens_out)), 1),
            "total_tokens_in": sum(tokens_in),
            "total_tokens_out": sum(tokens_out),
        },
        "cost_usd": {
            "total_cost": round(sum(costs), 6),
            "mean_cost_per_query": round(float(np.mean(costs)), 6),
        },
    }

    return summary
