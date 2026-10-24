# SecuRAG — Setup and Spec Sheet

Do this once, by hand, before handing the project to Claude Code or Antigravity.
Windows (PowerShell) steps first, macOS/Linux equivalents in brackets where they differ.

---

## 1. Spec sheet

### Accounts and keys you need
| What | Why | Notes |
|---|---|---|
| Pinecone account + API key | Vector store | Free tier is enough for ~20k chunks. Check current free-tier limits on regions and indexes. |
| An LLM API key | Router, grader, answer, reflection, RAGAS judge | Pick one provider. Needs two model names: a cheap fast one and a stronger one. A local llama.cpp model is fine for coding but too slow for the evaluation runs. |
| (Optional) LangSmith key | Tracing | Or skip tracing until Step 12. |
| (Optional) web search API key | CRAG web fallback | Can be left empty; the agent then answers "not in knowledge base". |

### Software
| Tool | Version | Check |
|---|---|---|
| Python | 3.12 recommended (3.11 ok, not 3.13) | `py -3.12 --version` |
| Git | any recent | `git --version` |
| Docker Desktop (WSL2 backend on Windows) | any recent | `docker --version` |
| NVIDIA driver + CUDA-capable PyTorch | for GPU embeddings | `nvidia-smi` |
| Claude Code and/or Antigravity | to run the build | open once and sign in |

### Hardware (approximate)
| Item | Minimum | Comfortable |
|---|---|---|
| RAM | 16 GB | 32 GB |
| GPU | none (CPU works, slow) | 8 GB VRAM or more |
| Disk | 10 GB free | 20 GB (2 CVE years ~0.8 GB, ATT&CK/CAPEC small, model weights several GB, Neo4j data) |

### Software stack
| Layer | Choice |
|---|---|
| Orchestration | LangGraph |
| Graph DB | Neo4j 5 (Docker) with APOC |
| Vector DB | Pinecone serverless, cosine, dimension 1024, namespaces `cve`, `attack`, `advisories` |
| Sparse retrieval | `rank_bm25` in the app, fused with RRF |
| Doc store | SQLite |
| Embeddings | BAAI/bge-m3 (sentence-transformers) |
| Reranker | BAAI/bge-reranker-v2-m3 (CrossEncoder) |
| Evaluation | RAGAS + custom multi-hop accuracy |
| Tracing | LangSmith or LangFuse |
| API / UI | FastAPI / Streamlit |

### Rough cost and time (estimates, not measured)
- Data download: a few GB total, depends on years chosen.
- Embedding ~20k chunks with bge-m3: minutes on a GPU, much longer on CPU.
- Full ablation (about 7 configs x 60-100 questions, plus RAGAS judging) means on the order of 10,000+ LLM calls. Use the fast model wherever the spec allows and test with a 10-question subset first.

---

## 2. Create the project folder and virtual environment

### Windows (PowerShell)
```powershell
# unzip securag-starter somewhere, then:
cd C:\path\to\securag-starter

# allow venv activation for this session only
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

# create and activate the venv
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1

python -m pip install --upgrade pip
```

### macOS / Linux
```bash
cd securag-starter
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
```

### Install PyTorch FIRST (GPU build)
On Windows, plain `pip install torch` gives a CPU-only build. Go to https://pytorch.org, choose Pip + your OS + a CUDA version your driver supports, and copy the command it gives. It looks like:
```powershell
pip install torch --index-url https://download.pytorch.org/whl/cu128
```
(the `cu128` part changes over time; use the selector). Verify:
```powershell
python -c "import torch; print(torch.__version__, torch.cuda.is_available())"
```
`True` means the GPU works. If `False`, set `DEVICE=cpu` in `.env` or fix the driver/CUDA build.

### Install the rest
```powershell
pip install -r requirements.txt
# if resolution fails on your machine:
# pip install -r requirements-loose.txt
```
Quick import test:
```powershell
python -c "import langgraph, neo4j, pinecone, sentence_transformers, ragas; print('imports ok')"
```

---

## 3. Configure `.env`
```powershell
Copy-Item .env.example .env        # [cp .env.example .env]
notepad .env
```
Fill in: `LLM_*`, `PINECONE_API_KEY`, `NEO4J_PASSWORD` (8+ characters). Leave the rest at defaults for now. Never commit `.env`.

---

## 4. Start Neo4j
```powershell
docker compose up -d
```
Open http://localhost:7474, log in with user `neo4j` and your password. Run `RETURN apoc.version()`; a version string means APOC is loaded.

---

## 5. Clone reference repos and data

### Windows
```powershell
.\scripts\clone_third_party.ps1
.\scripts\clone_data.ps1 -Years 2024,2025
```
### macOS / Linux
```bash
./scripts/clone_third_party.sh
./scripts/clone_data.sh 2024 2025
```
What this does
- `third_party/`: 9 reference repos (Graph-R1, RouteRAG, CRAG, langgraph-ai, Corrective-Rag, self-rag, neo4j-graphrag-python, microsoft/graphrag, ragas), shallow clones. Commit hashes go to `third_party/COMMITS.txt`.
- `data/raw/`: CVE records for the years you pass (sparse checkout, about 400 MB per year), CISA KEV, ATT&CK enterprise file only, CAPEC 2.1 STIX file only, and the CWE XML.
- The CWE download URL could not be tested from my environment. If the script warns, download the XML manually from https://cwe.mitre.org/data/downloads.html into `data\raw\cwe\`.
- Add `-WithOptional` (PowerShell) or `--with-optional` (bash) to `clone_third_party` for `ms-graphrag-neo4j` and `langfuse`.

Check:
```powershell
dir third_party
dir data\raw
dir data\raw\cvelistV5\cves
```

---

## 6. Git init and first commit
```powershell
git init
git add .
git commit -m "step-0: scaffold from starter"
```

---

## 7. Hand over to the agent

If a local llama.cpp server is running on the same GPU, stop it before the embedding step so the embedding model has VRAM.

### Claude Code
```powershell
cd C:\path\to\securag-starter
claude
```
First prompt:
```
Read AGENTS.md, docs/build.md and docs/build_agent.md fully. Then execute Step 0 and Step 1 of docs/build_agent.md. Environment is already set up (venv, .env, Neo4j, clones). Run each acceptance test, show the output, update NOTES.md and commit. Stop after Step 1 and wait for me.
```
Then one prompt per step or small group of steps:
```
Continue with Step N of docs/build_agent.md. Plan first, implement, run the acceptance test, show the output, update NOTES.md, commit, then stop.
```

### Antigravity
1. Open the `securag-starter` folder as the workspace.
2. Make sure the agent loads `AGENTS.md` (and `GEMINI.md`). Rule-file behavior has changed between versions; if it does not pick them up, paste the first prompt above and tell it to read those files explicitly.
3. Use the same prompts as above.

Recommendation: let the agent do Steps 0-3 first and check the Neo4j chain query yourself before continuing. Data-mapping mistakes are cheapest to catch there.

---

## 8. Troubleshooting
| Problem | Fix |
|---|---|
| `Activate.ps1 cannot be loaded` | Run the `Set-ExecutionPolicy -Scope Process ...` line, then activate again |
| `torch.cuda.is_available()` is False | Wrong torch build or old driver. Reinstall torch from the pytorch.org command; update NVIDIA driver |
| CUDA out of memory while embedding | Lower `EMBED_BATCH_SIZE` to 8-16, stop other GPU programs, or set `DEVICE=cpu` |
| `docker compose` says NEO4J_PASSWORD not set | `.env` missing or empty value; password needs 8+ characters |
| Neo4j will not start | `docker logs securag-neo4j`; delete `data\neo4j` only if you are fine losing the graph |
| `pip install -r requirements.txt` conflict | Use `requirements-loose.txt`, then record the working versions in `NOTES.md` |
| Sparse checkout slow | First clone fetches metadata only; files download when `sparse-checkout set` runs. Be patient on `cvelistV5` |
| Old LangChain imports fail | LangChain is v1.x. Use `langchain_text_splitters`, `langchain_core`, and plain LangGraph |
