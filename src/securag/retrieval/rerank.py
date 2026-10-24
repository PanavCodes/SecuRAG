"""Cross-encoder neural reranker (BGE-Reranker-v2-m3) and integrated rerank pipeline."""

import logging
from typing import Any

from securag.clients import get_reranker
from securag.config import get_settings
from securag.retrieval.graph_rerank import graph_cohesive_smoothing

logger = logging.getLogger(__name__)


def cross_encoder_rerank(
    query: str,
    candidates: list[dict[str, Any]],
    top_n: int = 6,
    reranker: Any = None,
) -> list[dict[str, Any]]:
    """Score query-document candidate pairs using BGE-Reranker-v2-m3 CrossEncoder."""
    if not candidates:
        return []

    model = reranker or get_reranker()
    pairs = [(query, c.get("text", "")) for c in candidates]

    # Predict cross-encoder relevance scores
    scores = model.predict(pairs)

    reranked: list[dict[str, Any]] = []
    for idx, c in enumerate(candidates):
        item = dict(c)
        score_val = float(scores[idx])
        item["cross_encoder_score"] = score_val
        item["score"] = score_val
        item["via"] = f"{c.get('via', 'unknown')}+cross_encoder"
        reranked.append(item)

    # Sort descending by cross-encoder score
    reranked.sort(key=lambda x: x["score"], reverse=True)
    return reranked[:top_n]


def rerank_candidates(
    query: str,
    candidates: list[dict[str, Any]],
    use_graph_rerank: bool | None = None,
    use_cross_encoder: bool | None = None,
    alpha: float = 0.7,
    top_n: int | None = None,
) -> list[dict[str, Any]]:
    """Execute reranking pipeline with independent GraphER and CrossEncoder toggles."""
    settings = get_settings()

    enable_graph = settings.use_graph_rerank if use_graph_rerank is None else use_graph_rerank
    enable_ce = settings.use_cross_encoder if use_cross_encoder is None else use_cross_encoder
    keep_n = settings.rerank_top_n if top_n is None else top_n

    current_candidates = list(candidates)

    # 1. GraphER topological smoothing (if enabled)
    if enable_graph and current_candidates:
        current_candidates = graph_cohesive_smoothing(current_candidates, alpha=alpha)

    # 2. CrossEncoder neural reranking (if enabled)
    if enable_ce and current_candidates:
        current_candidates = cross_encoder_rerank(query, current_candidates, top_n=keep_n)
    else:
        current_candidates = current_candidates[:keep_n]

    return current_candidates
