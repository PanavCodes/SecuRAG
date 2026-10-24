"""Hybrid retriever fusing Dense (Pinecone) and Sparse (BM25) via Reciprocal Rank Fusion (RRF)."""

import logging
from typing import Any

from securag.ingest.chunk import Docstore
from securag.retrieval.bm25 import BM25Index
from securag.retrieval.dense import DenseRetriever
from securag.retrieval.query_opt import expand_query, generate_hyde_doc, extract_metadata_filters

logger = logging.getLogger(__name__)


def reciprocal_rank_fusion(
    ranked_lists: list[list[dict[str, Any]]],
    k: int = 60,
    top_n: int = 20,
) -> list[dict[str, Any]]:
    """Compute Reciprocal Rank Fusion (RRF) scores across multiple ranked lists.

    RRF(d) = sum_{m} 1 / (k + rank_m(d))
    """
    rrf_scores: dict[str, float] = {}
    item_map: dict[str, dict[str, Any]] = {}
    vias: dict[str, set[str]] = {}

    for ranked in ranked_lists:
        for rank, item in enumerate(ranked, 1):
            cid = item["chunk_id"]
            if cid not in item_map:
                item_map[cid] = item
                vias[cid] = set()

            vias[cid].add(item.get("via", "unknown"))
            rrf_scores[cid] = rrf_scores.get(cid, 0.0) + (1.0 / (k + rank))

    # Sort candidates by combined RRF score
    sorted_ids = sorted(rrf_scores.keys(), key=lambda x: rrf_scores[x], reverse=True)
    fused_results: list[dict[str, Any]] = []

    for cid in sorted_ids[:top_n]:
        res = dict(item_map[cid])
        res["score"] = rrf_scores[cid]
        res["via"] = "+".join(sorted(list(vias[cid])))
        fused_results.append(res)

    return fused_results


class HybridRetriever:
    """Combines BM25 and Dense retrieval with Reciprocal Rank Fusion."""

    def __init__(self, docstore: Docstore | None = None):
        self.docstore = docstore or Docstore()
        self.dense_retriever = DenseRetriever(docstore=self.docstore)
        self._bm25_indices: dict[str, BM25Index] = {}

    def get_bm25_index(self, namespace: str) -> BM25Index:
        if namespace not in self._bm25_indices:
            idx = BM25Index(namespace=namespace)
            if not idx.load():
                idx.build_from_docstore(self.docstore)
            self._bm25_indices[namespace] = idx
        return self._bm25_indices[namespace]

    def search(
        self,
        query: str,
        namespace: str = "all",
        top_k: int = 20,
        filters: dict[str, Any] | None = None,
        use_dense: bool = True,
        use_bm25: bool = True,
        use_query_expansion: bool = False,
        use_hyde: bool = False,
        auto_extract_filters: bool = False,
        rrf_k: int = 60,
    ) -> list[dict[str, Any]]:
        """Execute hybrid search using dense, BM25, or RRF fusion with optional query optimization."""
        effective_filters = dict(filters or {})
        if auto_extract_filters and not filters:
            effective_filters = extract_metadata_filters(query)

        # 1. Query Expansion (generates query variants)
        queries = [query]
        if use_query_expansion:
            queries = expand_query(query, n_variants=3)

        # 2. HyDE (hypothetical document embedding for dense retrieval)
        dense_query = query
        if use_hyde and use_dense:
            dense_query = generate_hyde_doc(query)

        ranked_lists: list[list[dict[str, Any]]] = []

        # Dense search
        if use_dense:
            dense_results = self.dense_retriever.search(
                query=dense_query,
                namespace=namespace,
                top_k=top_k,
                filters=effective_filters if effective_filters else None,
            )
            ranked_lists.append(dense_results)

        # BM25 search across all query variants
        if use_bm25:
            bm25_idx = self.get_bm25_index(namespace)
            for q in queries:
                bm25_results = bm25_idx.search(
                    query=q,
                    top_k=top_k,
                    filters=effective_filters if effective_filters else None,
                    docstore=self.docstore,
                )
                if bm25_results:
                    ranked_lists.append(bm25_results)

        if not ranked_lists:
            return []

        if len(ranked_lists) == 1:
            return ranked_lists[0][:top_k]

        return reciprocal_rank_fusion(ranked_lists, k=rrf_k, top_n=top_k)
