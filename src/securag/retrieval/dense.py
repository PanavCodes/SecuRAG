"""Dense vector retriever using BGE-M3 and Pinecone."""

import logging
from typing import Any

from securag.clients import get_embedder, get_pinecone_index
from securag.ingest.chunk import Docstore

logger = logging.getLogger(__name__)


def build_pinecone_filter(filters: dict[str, Any] | None) -> dict[str, Any] | None:
    """Translate dictionary filters to Pinecone filter syntax."""
    if not filters:
        return None

    pc_filter: dict[str, Any] = {}
    for k, v in filters.items():
        if v is not None:
            pc_filter[k] = {"$eq": v}
    return pc_filter if pc_filter else None


class DenseRetriever:
    """Performs semantic search across Pinecone namespaces."""

    def __init__(self, docstore: Docstore | None = None):
        self.docstore = docstore or Docstore()

    def search(
        self,
        query: str,
        namespace: str = "all",
        top_k: int = 20,
        filters: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Query Pinecone with dense query embedding and return candidates."""
        embedder = get_embedder()
        index = get_pinecone_index()

        query_vec = embedder.encode([query], normalize_embeddings=True)[0].tolist()
        pc_filter = build_pinecone_filter(filters)

        namespaces_to_query = ["attack", "cve"] if namespace == "all" else [namespace]
        candidates: list[dict[str, Any]] = []

        for ns in namespaces_to_query:
            try:
                kwargs: dict[str, Any] = {
                    "vector": query_vec,
                    "namespace": ns,
                    "top_k": top_k,
                    "include_metadata": True,
                }
                if pc_filter:
                    kwargs["filter"] = pc_filter

                res = index.query(**kwargs)
                for m in res.get("matches", []):
                    chunk_id = m.get("id", "")
                    meta = m.get("metadata", {})
                    score = float(m.get("score", 0.0))

                    chunk_rec = self.docstore.get_chunk(chunk_id)
                    text = chunk_rec["text"] if chunk_rec else meta.get("text_preview", "")

                    candidates.append({
                        "chunk_id": chunk_id,
                        "source_id": meta.get("source_id", ""),
                        "source_type": meta.get("source_type", ""),
                        "namespace": ns,
                        "score": score,
                        "via": "dense",
                        "text": text,
                        "metadata": meta,
                    })
            except Exception as e:
                logger.warning("Pinecone query on namespace '%s' failed: %s", ns, e)

        # Sort combined results by score descending
        candidates.sort(key=lambda x: x["score"], reverse=True)
        return candidates[:top_k]
