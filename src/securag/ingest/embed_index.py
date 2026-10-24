"""High-throughput embedding and Pinecone indexing pipeline for SecuRAG."""

from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import time
from typing import Any
import numpy as np

from securag.clients import get_embedder, get_pinecone_index
from securag.config import get_settings
from securag.ingest.chunk import Docstore, batch_iterate

logger = logging.getLogger(__name__)


def build_vector_record(chunk: dict[str, Any], vector: np.ndarray) -> dict[str, Any]:
    """Format vector record for Pinecone upsert with Section 3.2 metadata schema."""
    meta = chunk.get("metadata", {})
    metadata: dict[str, Any] = {
        "source_id": str(chunk.get("source_id", "")),
        "source_type": str(chunk.get("source_type", "")),
        "title": str(meta.get("title", ""))[:200],
        "in_kev": bool(meta.get("in_kev", False)),
        "text_preview": str(chunk.get("text", ""))[:300],
    }

    if meta.get("year") is not None:
        metadata["year"] = int(meta["year"])

    if meta.get("severity"):
        metadata["severity"] = str(meta["severity"])

    if meta.get("cwe_ids"):
        metadata["cwe_ids"] = [str(c) for c in meta["cwe_ids"]]

    return {
        "id": chunk["chunk_id"],
        "values": vector.tolist(),
        "metadata": metadata,
    }


def embed_and_upsert_namespace(
    namespace: str,
    docstore: Docstore | None = None,
    batch_size: int = 16,
    upsert_batch_size: int = 200,
    max_chunks: int | None = None,
    start_offset: int = 0,
    max_workers: int = 8,
) -> int:
    """Embed all chunks in a namespace and concurrently upsert to Pinecone."""
    import torch
    ds = docstore or Docstore()
    embedder = get_embedder()
    index = get_pinecone_index()

    chunks = ds.get_all_chunks(namespace=namespace)
    if start_offset > 0:
        chunks = chunks[start_offset:]
    if max_chunks is not None:
        chunks = chunks[:max_chunks]

    total = len(chunks)
    logger.info("Starting embedding for namespace '%s': %d chunks (offset=%d, encode_batch=%d, workers=%d)...",
                namespace, total, start_offset, batch_size, max_workers)

    start_time = time.time()
    vector_buffer: list[dict[str, Any]] = []
    futures = set()
    total_upserted = 0

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        for i in range(0, total, batch_size):
            chunk_batch = chunks[i : i + batch_size]
            texts = [c["text"] for c in chunk_batch]

            # 1. Encode on GPU
            embeddings = embedder.encode(
                texts,
                batch_size=len(texts),
                normalize_embeddings=True,
                show_progress_bar=False,
            )

            # 2. Build records
            for j in range(len(chunk_batch)):
                vector_buffer.append(build_vector_record(chunk_batch[j], embeddings[j]))

            # 3. Flush buffer to concurrent upsert workers
            while len(vector_buffer) >= upsert_batch_size:
                upsert_chunk = vector_buffer[:upsert_batch_size]
                vector_buffer = vector_buffer[upsert_batch_size:]

                # Backpressure: if too many in flight, wait for one
                if len(futures) >= max_workers * 2:
                    done, futures = as_completed(futures), set()
                    for f in done:
                        f.result()

                fut = executor.submit(index.upsert, vectors=upsert_chunk, namespace=namespace)
                futures.add(fut)
                total_upserted += len(upsert_chunk)

                if total_upserted % 1000 == 0 or total_upserted >= total:
                    elapsed = time.time() - start_time
                    rate = total_upserted / elapsed if elapsed > 0 else 0
                    logger.info("Namespace '%s': %d/%d chunks submitted (%.1f chunks/s)",
                                namespace, total_upserted, total, rate)

        # Flush remaining buffer
        if vector_buffer:
            fut = executor.submit(index.upsert, vectors=vector_buffer, namespace=namespace)
            futures.add(fut)
            total_upserted += len(vector_buffer)

        # Wait for all in-flight upserts to complete
        for f in as_completed(futures):
            f.result()

    total_time = time.time() - start_time
    logger.info("Namespace '%s' complete: %d chunks upserted in %.2fs (%.1f chunks/s)",
                namespace, total, total_time, total / total_time if total_time > 0 else 0)
    return total


def query_pinecone(
    query_text: str,
    namespace: str = "attack",
    top_k: int = 5,
    filter_dict: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Query Pinecone with dense query vector and return matched records."""
    embedder = get_embedder()
    index = get_pinecone_index()

    query_vec = embedder.encode([query_text], normalize_embeddings=True)[0].tolist()

    kwargs: dict[str, Any] = {
        "vector": query_vec,
        "namespace": namespace,
        "top_k": top_k,
        "include_metadata": True,
    }
    if filter_dict:
        kwargs["filter"] = filter_dict

    res = index.query(**kwargs)
    matches = []
    for m in res.get("matches", []):
        matches.append({
            "id": m.get("id"),
            "score": m.get("score"),
            "metadata": m.get("metadata", {}),
        })
    return matches


def get_pinecone_stats() -> dict[str, Any]:
    """Return index stats including vector counts per namespace."""
    index = get_pinecone_index()
    return index.describe_index_stats()


def run_full_embedding_pipeline(namespaces: list[str] | None = None) -> dict[str, int]:
    """Execute complete embedding and Pinecone upsert for all namespaces."""
    ns_to_run = namespaces or ["attack", "cve"]
    ds = Docstore()
    results: dict[str, int] = {}

    for ns in ns_to_run:
        count = embed_and_upsert_namespace(ns, docstore=ds)
        results[ns] = count

    stats = get_pinecone_stats()
    logger.info("Pinecone Index Stats: %s", stats)
    return results


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    run_full_embedding_pipeline()
