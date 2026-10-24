"""Model downloader and pre-warming script for SecuRAG.

Downloads and validates:
1. Dense Embedding Model: BAAI/bge-m3 (1024-dim, multilingual)
2. Neural Cross-Encoder Reranker: BAAI/bge-reranker-v2-m3
"""

import sys
import time
import torch
from sentence_transformers import SentenceTransformer, CrossEncoder

from securag.config import get_settings


def download_models():
    settings = get_settings()
    device = "cuda" if torch.cuda.is_available() and settings.device == "cuda" else "cpu"
    print("=" * 65)
    print(" SecuRAG ML Model Pre-Download & Verification")
    print(f" Target Device: {device.upper()} (CUDA Available: {torch.cuda.is_available()})")
    print("=" * 65)

    # 1. Download BGE-M3 Embedder
    print(f"\n[1/2] Downloading & Loading Embedder: {settings.embed_model}...")
    t0 = time.time()
    try:
        embedder = SentenceTransformer(settings.embed_model, device=device)
        test_vec = embedder.encode("Cybersecurity threat triage test sentence")
        dim = test_vec.shape[0] if hasattr(test_vec, "shape") else len(test_vec)
        elapsed = time.time() - t0
        print(f"[OK] Embedder '{settings.embed_model}' ready on {device} ({elapsed:.1f}s, dim={dim})")
    except Exception as exc:
        print(f"[ERROR] Failed to load embedder '{settings.embed_model}': {exc}", file=sys.stderr)
        sys.exit(1)

    # 2. Download BGE-Reranker-v2-M3 CrossEncoder
    print(f"\n[2/2] Downloading & Loading Cross-Encoder: {settings.rerank_model}...")
    t0 = time.time()
    try:
        reranker = CrossEncoder(settings.rerank_model, device=device)
        score = reranker.predict([("CVE query", "Relevant vulnerability advisory")])
        elapsed = time.time() - t0
        print(f"[OK] Reranker '{settings.rerank_model}' ready on {device} ({elapsed:.1f}s, test_score={score[0]:.4f})")
    except Exception as exc:
        print(f"[ERROR] Failed to load reranker '{settings.rerank_model}': {exc}", file=sys.stderr)
        sys.exit(1)

    print("\n" + "=" * 65)
    print(" [SUCCESS] All ML models downloaded and verified in local cache!")
    print("=" * 65)


if __name__ == "__main__":
    download_models()
