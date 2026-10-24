"""Background runner to embed and upsert CVE chunks into Pinecone with auto-resume."""

import logging
import sys
import time

from securag.ingest.embed_index import embed_and_upsert_namespace, get_pinecone_stats

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

if __name__ == "__main__":
    stats = get_pinecone_stats()
    ns_map = stats.get("namespaces", {})
    existing_cves = ns_map.get("cve", {}).get("vector_count", 0) if isinstance(ns_map.get("cve"), dict) else getattr(ns_map.get("cve", None), "vector_count", 0)
    print(f"Resuming CVE embedding from offset {existing_cves}...")

    t0 = time.time()
    count = embed_and_upsert_namespace(
        namespace="cve",
        batch_size=16,
        upsert_batch_size=200,
        start_offset=existing_cves,
    )
    elapsed = time.time() - t0
    print(f"\nSuccessfully embedded and upserted {count} CVE chunks in {elapsed:.2f}s ({count/elapsed:.1f} chunks/s)")
    final_stats = get_pinecone_stats()
    print("Final Pinecone Stats:", final_stats)
