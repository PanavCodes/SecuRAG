# NOTES
Running log. The agent updates this every step: assumptions, deviations from docs/build_agent.md, failures, field paths actually used.

## Step log

### Step 0: Scaffold & Environment Bootstrap
- Isolated Python 3.12.13 environment created at `.venv` using `uv venv --python 3.12 .venv` to satisfy `neo4j-graphrag` Python <= 3.12 constraint (system default was 3.13.15).
- Installed PyTorch CUDA 12.4 (`torch==2.6.0+cu124`, `torchvision==0.21.0+cu124`) for NVIDIA GeForce RTX 4060 Laptop GPU. Verified with `torch.cuda.is_available() == True`.
- Dependency conflict resolved: `ragas==0.4.3` imports `langchain_community.chat_models.vertexai`. In `langchain-community==0.4.2`, provider modules were removed. Pinned `langchain-community==0.3.31` in `requirements.txt`. Full core imports (`langgraph`, `neo4j`, `pinecone`, `sentence_transformers`, `ragas`) passed.
- Project folder layout created: `src/securag/{ingest,graph,retrieval,agent,eval,api,ui}`, `data/{processed,eval}`, `results`, `tests`.

### Step 1: Config + Clients
- Implemented `src/securag/config.py` backed by `pydantic-settings` to parse `.env` parameters, model parameters, limits, and ablation flags.
- Implemented `src/securag/clients.py` providing client handles for Neo4j driver, Pinecone index, SentenceTransformer (`BAAI/bge-m3`), CrossEncoder (`BAAI/bge-reranker-v2-m3`), and LangChain chat models.
- Download acceleration: Hugging Face throttles unauthenticated single-thread large downloads to ~0.9 MB/s; implemented `scripts/fast_download.py` using 16 concurrent HTTP Range workers, downloading the 2.27 GB reranker weights in 193s (~11.2 MB/s).
- Acceptance test `python scripts/healthcheck.py` passed:
  - Neo4j + APOC: OK (Version 5.26.32).
  - Embedder: OK (BAAI/bge-m3 on cuda, dimension exactly 1024).
  - Cross-Encoder: OK (BAAI/bge-reranker-v2-m3 on cuda, relevant: 0.1752, irrelevant: 0.0000).

