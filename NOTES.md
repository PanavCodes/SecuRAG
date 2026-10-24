# NOTES
Running log. The agent updates this every step: assumptions, deviations from docs/build_agent.md, failures, field paths actually used.

## Step log

### Step 0: Scaffold & Environment Bootstrap
- Isolated Python 3.12.13 environment created at `.venv` using `uv venv --python 3.12 .venv` to satisfy `neo4j-graphrag` Python <= 3.12 constraint (system default was 3.13.15).
- Installed PyTorch CUDA 12.4 (`torch==2.6.0+cu124`, `torchvision==0.21.0+cu124`) for NVIDIA GeForce RTX 4060 Laptop GPU. Verified with `torch.cuda.is_available() == True`.
- Dependency conflict resolved: `ragas==0.4.3` imports `langchain_community.chat_models.vertexai`. In `langchain-community==0.4.2`, provider modules were removed. Pinned `langchain-community==0.3.31` in `requirements.txt`. Full core imports (`langgraph`, `neo4j`, `pinecone`, `sentence_transformers`, `ragas`) passed.
- Project folder layout created: `src/securag/{ingest,graph,retrieval,agent,eval,api,ui}`, `data/{processed,eval}`, `results`, `tests`.

