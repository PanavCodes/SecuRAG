"""BM25 sparse retriever for SecuRAG preserving security entity IDs."""

import logging
from pathlib import Path
import pickle
import re
from typing import Any
from rank_bm25 import BM25Okapi

from securag.ingest.chunk import Docstore

logger = logging.getLogger(__name__)

ID_PATTERN = re.compile(
    r"\b(?:cve-\d{4}-\d{4,}|cwe-\d+|capec-\d+|t\d{4}(?:\.\d{3})?|m\d{4}|ta\d{4})\b",
    re.IGNORECASE,
)


def bm25_tokenize(text: str) -> list[str]:
    """Tokenize text into lowercase words while preserving security IDs as single tokens."""
    text_lower = text.lower()
    tokens: list[str] = []
    last_end = 0

    for match in ID_PATTERN.finditer(text_lower):
        start, end = match.span()
        if start > last_end:
            sub = text_lower[last_end:start]
            tokens.extend([w for w in re.split(r"[^a-z0-9]+", sub) if w])
        tokens.append(match.group(0))
        last_end = end

    if last_end < len(text_lower):
        sub = text_lower[last_end:]
        tokens.extend([w for w in re.split(r"[^a-z0-9]+", sub) if w])

    return tokens


class BM25Index:
    """Manages BM25 indexing, persistence, and querying."""

    def __init__(self, namespace: str = "all", index_dir: str = "data/processed"):
        self.namespace = namespace
        self.index_file = Path(index_dir) / f"bm25_{namespace}.pkl"
        self.bm25: BM25Okapi | None = None
        self.chunk_ids: list[str] = []
        self.chunks_meta: list[dict[str, Any]] = []

    def build_from_docstore(self, docstore: Docstore | None = None) -> None:
        """Build BM25 index from all chunks in docstore."""
        ds = docstore or Docstore()
        if self.namespace == "all":
            chunks = ds.get_all_chunks()
        else:
            chunks = ds.get_all_chunks(namespace=self.namespace)

        logger.info("Building BM25 index for namespace '%s' with %d chunks...", self.namespace, len(chunks))

        self.chunk_ids = [c["chunk_id"] for c in chunks]
        self.chunks_meta = [
            {
                "chunk_id": c["chunk_id"],
                "source_id": c["source_id"],
                "source_type": c["source_type"],
                "namespace": c["namespace"],
                "metadata": c.get("metadata", {}),
            }
            for c in chunks
        ]

        tokenized_corpus = [bm25_tokenize(c["text"]) for c in chunks]
        self.bm25 = BM25Okapi(tokenized_corpus)

        self.save()
        logger.info("BM25 index for '%s' saved to %s", self.namespace, self.index_file)

    def save(self) -> None:
        self.index_file.parent.mkdir(parents=True, exist_ok=True)
        with self.index_file.open("wb") as f:
            pickle.dump({
                "bm25": self.bm25,
                "chunk_ids": self.chunk_ids,
                "chunks_meta": self.chunks_meta,
            }, f)

    def load(self) -> bool:
        if not self.index_file.exists():
            return False
        with self.index_file.open("rb") as f:
            data = pickle.load(f)
            self.bm25 = data["bm25"]
            self.chunk_ids = data["chunk_ids"]
            self.chunks_meta = data["chunks_meta"]
        return True

    def search(
        self,
        query: str,
        top_k: int = 20,
        filters: dict[str, Any] | None = None,
        docstore: Docstore | None = None,
    ) -> list[dict[str, Any]]:
        """Query BM25 index with tokenized query and apply metadata filters."""
        if self.bm25 is None and not self.load():
            self.build_from_docstore(docstore)

        if not self.bm25 or not self.chunk_ids:
            return []

        tokens = bm25_tokenize(query)
        if not tokens:
            return []

        scores = self.bm25.get_scores(tokens)
        ds = docstore or Docstore()

        candidates: list[dict[str, Any]] = []
        for idx, score in enumerate(scores):
            if score <= 0.0:
                continue

            meta = self.chunks_meta[idx]
            chunk_meta = meta.get("metadata", {})

            # Apply metadata filters
            if filters:
                if "year" in filters and chunk_meta.get("year") != filters["year"]:
                    continue
                if "in_kev" in filters and chunk_meta.get("in_kev") != filters["in_kev"]:
                    continue
                if "severity" in filters and chunk_meta.get("severity") != filters["severity"]:
                    continue
                if "source_type" in filters and meta.get("source_type") != filters["source_type"]:
                    continue

            candidates.append({
                "chunk_id": meta["chunk_id"],
                "source_id": meta["source_id"],
                "source_type": meta["source_type"],
                "namespace": meta["namespace"],
                "score": float(score),
                "via": "bm25",
                "metadata": chunk_meta,
            })

        # Sort descending by score
        candidates.sort(key=lambda x: x["score"], reverse=True)
        candidates = candidates[:top_k]

        # Attach full text from docstore
        for c in candidates:
            chunk_rec = ds.get_chunk(c["chunk_id"])
            c["text"] = chunk_rec["text"] if chunk_rec else ""

        return candidates


def build_all_bm25_indexes(docstore: Docstore | None = None) -> dict[str, BM25Index]:
    """Build all three BM25 indexes: cve, attack, all."""
    ds = docstore or Docstore()
    indexes = {}
    for ns in ["attack", "cve", "all"]:
        idx = BM25Index(namespace=ns)
        idx.build_from_docstore(ds)
        indexes[ns] = idx
    return indexes


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    build_all_bm25_indexes()
