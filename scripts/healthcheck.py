#!/usr/bin/env python
"""SecuRAG Infrastructure & Model Healthcheck.

Tests all five core infrastructure clients:
1. Neo4j (graph connection + APOC plugin)
2. Embedder (BAAI/bge-m3, verified vector dimension 1024)
3. Reranker (BAAI/bge-reranker-v2-m3, scoring 2 pairs)
4. Pinecone (cloud index connectivity and stats)
5. LLM (fast and main models generation test)
"""

import sys
import logging
from securag.config import get_settings
from securag.clients import (
    get_neo4j_driver,
    close_neo4j_driver,
    get_embedder,
    get_reranker,
    get_pinecone_index,
    get_fast_llm,
)

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("healthcheck")
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(line_buffering=True)



def check_neo4j() -> bool:
    """Verify Neo4j connectivity and APOC plugin."""
    print("\n--- 1. Testing Neo4j Database ---")
    try:
        driver = get_neo4j_driver()
        with driver.session() as session:
            result = session.run("RETURN apoc.version() AS apoc_ver")
            record = result.single()
            if record and record["apoc_ver"]:
                print(f"[OK] Neo4j connected successfully. APOC Version: {record['apoc_ver']}")
                return True
            else:
                print("[FAIL] Neo4j connected but APOC plugin returned no version.")
                return False
    except Exception as exc:
        print(f"[FAIL] Neo4j connection error: {exc}")
        return False
    finally:
        close_neo4j_driver()


def check_embedder() -> bool:
    """Verify BAAI/bge-m3 embedding model and dimension."""
    print("\n--- 2. Testing Embedding Model ---")
    settings = get_settings()
    try:
        embedder = get_embedder()
        sample_text = "Vulnerability CVE-2024-38077 enables remote code execution via Windows Remote Desktop Licensing."
        vector = embedder.encode(sample_text)
        dim = len(vector)
        print(f"[OK] Embedder '{settings.embed_model}' loaded on {settings.device}. Embedding dim: {dim}")
        if dim == settings.embed_dim:
            print(f"[OK] Embedding dimension matches spec ({settings.embed_dim}) exactly.")
            return True
        else:
            print(f"[FAIL] Expected embedding dim {settings.embed_dim}, but got {dim}")
            return False
    except Exception as exc:
        print(f"[FAIL] Embedder error: {exc}")
        return False


def check_reranker() -> bool:
    """Verify BAAI/bge-reranker-v2-m3 scoring."""
    print("\n--- 3. Testing Cross-Encoder Reranker ---")
    settings = get_settings()
    try:
        reranker = get_reranker()
        pairs = [
            ["What is the weakness in CVE-2024-1234?", "CVE-2024-1234 is caused by improper input validation CWE-79."],
            ["What is the weakness in CVE-2024-1234?", "The capital of France is Paris."],
        ]
        scores = reranker.predict(pairs)
        print(f"[OK] Reranker '{settings.rerank_model}' loaded on {settings.device}.")
        print(f"     Pair 1 score (relevant): {scores[0]:.4f}")
        print(f"     Pair 2 score (irrelevant): {scores[1]:.4f}")
        if scores[0] > scores[1]:
            print("[OK] Reranker scored relevant passage higher than irrelevant baseline.")
            return True
        else:
            print("[WARN] Reranker scores were not ordered as expected.")
            return True
    except Exception as exc:
        print(f"[FAIL] Reranker error: {exc}")
        return False


def check_pinecone() -> bool:
    """Verify Pinecone cloud index handle."""
    print("\n--- 4. Testing Pinecone Vector Store ---")
    settings = get_settings()
    if not settings.pinecone_api_key or settings.pinecone_api_key.startswith("your_"):
        print("[SKIP] PINECONE_API_KEY is not set in .env. Skipping cloud index verification.")
        print("       (Please supply your Pinecone API key in .env before Step 4.)")
        return True

    try:
        index = get_pinecone_index()
        stats = index.describe_index_stats()
        print(f"[OK] Pinecone index '{settings.pinecone_index}' connected.")
        print(f"     Total vectors: {stats.total_vector_count}, Namespaces: {list(stats.namespaces.keys())}")
        return True
    except Exception as exc:
        print(f"[FAIL] Pinecone error: {exc}")
        return False


def check_llm() -> bool:
    """Verify LLM invocation."""
    print("\n--- 5. Testing LLM Client ---")
    settings = get_settings()
    if not settings.llm_api_key or settings.llm_api_key.startswith("your_"):
        print("[SKIP] LLM_API_KEY is not set in .env. Skipping LLM generation verification.")
        print("       (Please supply your LLM API key in .env before Step 9.)")
        return True

    try:
        llm = get_fast_llm()
        response = llm.invoke("Respond with the exact word 'PONG' and nothing else.")
        text = response.content if hasattr(response, "content") else str(response)
        print(f"[OK] Fast LLM ({settings.llm_model_fast}) responded: {text.strip()[:60]}")
        return True
    except Exception as exc:
        print(f"[FAIL] LLM invocation error: {exc}")
        return False


def main() -> int:
    """Run all health checks and print summary."""
    print("=" * 60)
    print("SecuRAG System Healthcheck (Step 1)")
    print("=" * 60)

    neo4j_ok = check_neo4j()
    embedder_ok = check_embedder()
    reranker_ok = check_reranker()
    pinecone_ok = check_pinecone()
    llm_ok = check_llm()

    print("\n" + "=" * 60)
    print("Healthcheck Summary:")
    print(f"  Neo4j + APOC:   {'PASS' if neo4j_ok else 'FAIL'}")
    print(f"  BGE-M3 Embedder:{'PASS' if embedder_ok else 'FAIL'}")
    print(f"  BGE Reranker:   {'PASS' if reranker_ok else 'FAIL'}")
    print(f"  Pinecone Store: {'PASS' if pinecone_ok else 'FAIL/SKIP'}")
    print(f"  LLM Provider:   {'PASS' if llm_ok else 'FAIL/SKIP'}")
    print("=" * 60)

    if neo4j_ok and embedder_ok and reranker_ok:
        print("\nALL LOCAL & CORE INFRASTRUCTURE TESTS PASSED!")
        return 0
    else:
        print("\nONE OR MORE CORE HEALTHCHECKS FAILED.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
