# SecuRAG — Build Guide

Agentic hybrid GraphRAG for CVE / threat-intel triage.
Course mapping: Course 2 (RAG, Vector DBs, LangGraph agents, Observability).

> Status legend used below
> - **VERIFIED** = repo URL appeared in search results while preparing this file.
> - All repo URLs were checked with `git ls-remote` on 2026-10-24 and exist. License and last-commit checks are still your job.
> - Use the scripts in `scripts/` (PowerShell and bash) for cloning. The clone block in Section 3 below is the plain version; the scripts use sparse checkout for the large data repos.
> - **NO CODE** = paper has no public implementation found. You implement from the paper.

---

## 1. What we are building

```
Query -> Router (simple / multi-hop / out-of-KB)
  simple    -> Hybrid retrieve (BM25 + dense, RRF)            [Pinecone]
  multi-hop -> Decompose -> Graph traversal + vector          [Neo4j + Pinecone]
  OOKB      -> Web / live-feed fallback (CRAG)
-> GraphER-style rerank -> cross-encoder rerank
-> CRAG evaluator (correct / ambiguous / incorrect)
     incorrect -> rewrite query -> loop (max 3, novelty guard)
-> Grounded answer with CVE / CWE / ATT&CK citations
-> Reflection node (faithfulness check) -> final
```

Papers being replicated / adapted

| Paper | Venue | Used for |
|---|---|---|
| Graph-R1 | ICML 2026 | Multi-turn agentic graph retrieval, reward design (answer + retrieval + graph-path) |
| RouteRAG | ACL Findings 2026 | Router: text vs graph vs both, retrieval cost awareness |
| GraphER (Oracle, arXiv 2603.24925) | arXiv 2026 | Query-time graph rerank, no extra graph infra |
| CRAG (Yan et al.) | arXiv 2024 | Retrieval evaluator, decompose-recompose, web fallback |

Not IEEE. If faculty requires IEEE, search IEEE Xplore for a matching paper and cite it as related work; keep the above as the implementation base.

---

## 2. Repos to clone

### 2.1 Paper implementations (read + borrow logic)

| # | Repo | Status | Role in SecuRAG | Take | Watch out |
|---|---|---|---|---|---|
| 1 | https://github.com/LHRLAB/Graph-R1 | VERIFIED | Core paper. Think -> query -> retrieve -> rethink loop. | Agent loop structure, reward definition, eval scripts for HotpotQA / 2Wiki / Musique | Uses a knowledge **hypergraph** + RL training (GRPO / PPO / REINFORCE++). You use Neo4j property graph. Copy the loop and reward, not the training stack. |
| 2 | https://github.com/YucanGuo/RouteRAG | VERIFIED | Router paper. Chooses text vs graph vs hybrid per step. | Action space (reason / text-retrieve / graph-retrieve / answer), efficiency reward idea | RL based. Replace learned policy with LLM router first. RL = stretch goal. |
| 3 | https://github.com/HuskyInSalt/CRAG | VERIFIED | Official CRAG. | Evaluator logic (correct / ambiguous / incorrect), decompose-then-recompose filtering | Needs pretrained evaluator weights + fine-tuned LLaMA-2. Last commit ~1 year old. **Borrow logic, do not run as-is.** |
| 4 | GraphER, arXiv 2603.24925 | NO CODE | Reranker. Offline enrichment + online graph smoothing. | Implement Graph Cohesive Smoothing from the paper | No maintained implementation found. Log assumptions in an experiment log before coding. |

### 2.2 LangGraph / agent scaffolding

| # | Repo | Status | Role | Take |
|---|---|---|---|---|
| 5 | https://github.com/piyushagni5/langgraph-ai | VERIFIED | Base skeleton. Folder `agentic-rag/agentic-rag-systems/building-adaptive-rag/` has router, retrieval grader, web fallback, `state.py`, `graph.py`, tests. | Graph layout, node/chain separation, pytest pattern |
| 6 | https://github.com/Bisma474/Corrective-Rag | VERIFIED | CRAG as FastAPI + React app. | API + UI structure, evaluator-to-web-fallback wiring |
| 7 | https://github.com/langchain-ai/langgraph | VERIFIED (ls-remote) | Framework. | Checkpointers, conditional edges, recursion limit |
| 8 | https://github.com/AkariAsai/self-rag | VERIFIED (ls-remote) | Self-RAG reflection tokens. | Reflection / critique prompts for the final faithfulness node |

### 2.3 GraphRAG / graph layer

| # | Repo | Status | Role | Take |
|---|---|---|---|---|
| 9 | https://github.com/neo4j/neo4j-graphrag-python | VERIFIED | Primary graph library. Retrievers, KG builder pipeline. | `VectorRetriever`, Cypher retrievers, `SimpleKGPipeline` for advisory text. Needs Neo4j + APOC core. |
| 10 | https://github.com/neo4j-contrib/ms-graphrag-neo4j | VERIFIED | Microsoft GraphRAG algorithm (communities + summaries) on Neo4j. | Optional: community summaries for "global" questions |
| 11 | https://github.com/microsoft/graphrag | VERIFIED | Original GraphRAG research code (Edge et al., 2024). | Reference for community detection + hierarchical summaries. Baseline to compare against in ablation. |

### 2.4 Data sources (cybersecurity corpus)

| # | Repo / source | Status | What it gives | Note |
|---|---|---|---|---|
| 12 | https://github.com/CVEProject/cvelistV5 | VERIFIED | All CVE records, CVE JSON 5.x, organized by year | **Huge.** One year (2024) is ~39k files / ~400 MB. Use sparse checkout of only the years you need (see scripts in `scripts/`). |
| 13 | https://github.com/cisagov/vulnrichment | VERIFIED | CISA enrichment: SSVC, CVSS, CWE, KEV flag | Already merged into live CVE data via ADP; clone only if you need it separately |
| 14 | https://github.com/cisagov/kev-data | VERIFIED | Known Exploited Vulnerabilities, CSV + JSON + schema | Small. Good "exploited in the wild" label. |
| 15 | https://github.com/mitre-attack/attack-stix-data | VERIFIED | MITRE ATT&CK in STIX 2.1 (enterprise / mobile / ICS) | Use only `enterprise-attack/enterprise-attack.json`. The full repo is >1 GB of old versions, so use a sparse checkout. Check ATT&CK Terms of Use. |
| 16 | https://github.com/mitre/cti | VERIFIED | **CAPEC** in STIX (use `capec/2.1/stix-capec.json`; includes CWE and ATT&CK ids per CAPEC) | Use only for CAPEC. For ATT&CK use #15. |
| 17 | https://github.com/opencve/opencve-kb | VERIFIED | Pre-merged CVE records (MITRE + Vulnrichment + NVD + Red Hat) | Optional shortcut instead of merging sources yourself |
| 18 | CWE list (cwe.mitre.org, download XML/CSV) | NOT GITHUB | CWE entries and hierarchy | Direct download, no git clone |
| 19 | EPSS scores (FIRST.org) | NOT GITHUB | Exploit likelihood score | Optional feature for ranking |

### 2.5 Evaluation, rerank, observability

| # | Repo | Status | Role |
|---|---|---|---|
| 20 | https://github.com/explodinggradients/ragas | VERIFIED | RAGAS: faithfulness, answer relevancy, context precision / recall |
| 21 | https://github.com/FlagOpen/FlagEmbedding | VERIFIED (ls-remote) | BGE-M3 embeddings + `bge-reranker-v2-m3` cross-encoder |
| 22 | https://github.com/langfuse/langfuse | VERIFIED (ls-remote) | Open-source tracing (alternative to LangSmith, course 4.3) |
| 23 | https://github.com/langchain-ai/langchain | VERIFIED (ls-remote) | Loaders, splitters, retrievers, LCEL |

Skip if short on time: #10, #17, #22.

---

## 3. Clone script

```bash
mkdir -p securag/third_party && cd securag/third_party

# --- paper code (reference) ---
git clone --depth 1 https://github.com/LHRLAB/Graph-R1.git
git clone --depth 1 https://github.com/YucanGuo/RouteRAG.git
git clone --depth 1 https://github.com/HuskyInSalt/CRAG.git

# --- scaffolding ---
git clone --depth 1 https://github.com/piyushagni5/langgraph-ai.git
git clone --depth 1 https://github.com/Bisma474/Corrective-Rag.git
git clone --depth 1 https://github.com/AkariAsai/self-rag.git            # from memory, verify

# --- graph layer ---
git clone --depth 1 https://github.com/neo4j/neo4j-graphrag-python.git
git clone --depth 1 https://github.com/microsoft/graphrag.git
git clone --depth 1 https://github.com/neo4j-contrib/ms-graphrag-neo4j.git   # optional

# --- evaluation ---
git clone --depth 1 https://github.com/explodinggradients/ragas.git

cd ..
mkdir -p data/raw && cd data/raw

# --- data (large, shallow) ---
# cvelistV5 and attack-stix-data are large: prefer scripts/clone_data.* (sparse checkout)
git clone --depth 1 https://github.com/CVEProject/cvelistV5.git
git clone --depth 1 https://github.com/cisagov/kev-data.git
git clone --depth 1 https://github.com/mitre-attack/attack-stix-data.git
git clone --depth 1 https://github.com/mitre/cti.git                          # CAPEC
# CWE: download from https://cwe.mitre.org/data/downloads.html into data/raw/cwe/
```

Rules
- `third_party/` is **reference**. Do not import from it directly. Copy the logic you need into `src/securag/` and note the source in a header comment (license compliance).
- Add `third_party/` and `data/raw/` to `.gitignore`. Keep a `THIRD_PARTY.md` listing repo, commit hash, license.
- Record the commit hash of each clone: `git -C third_party/<repo> rev-parse HEAD`.

---

## 4. How the repos combine

| SecuRAG component | Built from |
|---|---|
| LangGraph state, nodes, graph wiring | #5 skeleton + #7 |
| Router (simple / multi-hop / OOKB) | #5 router chain + #2 action space |
| Hybrid retrieval (BM25 + dense + RRF) | Course 2.5, `rank_bm25` + Pinecone + #23 `EnsembleRetriever` |
| Graph retrieval (Cypher, entity expansion) | #9 + #1 loop |
| Graph rerank (query-time) | #4 paper, implemented by you |
| Cross-encoder rerank | #21 |
| CRAG evaluator + rewrite loop | #3 logic + #6 wiring |
| Faithfulness / reflection node | #8 prompts |
| Multi-step agent with reward-style scoring | #1 reward design (score only; no RL training in v1) |
| Graph schema + ingestion | #12 #14 #15 #16 #18 -> Neo4j |
| Advisory text -> KG (LLM extraction) | #9 `SimpleKGPipeline` |
| Evaluation | #20 + Graph-R1 eval datasets |
| API + UI | #6 structure, FastAPI + Streamlit/React |

### Graph schema (start here, extend later)
```
(CVE)-[:HAS_WEAKNESS]->(CWE)
(CWE)-[:RELATED_TO]->(CAPEC)
(CAPEC)-[:MAPS_TO]->(Technique)           // ATT&CK
(Technique)-[:PART_OF]->(Tactic)
(Technique)-[:MITIGATED_BY]->(Mitigation)
(CVE)-[:LISTED_IN]->(KEV)
(CVE)-[:AFFECTS]->(Product)
(Advisory)-[:MENTIONS]->(CVE)
```
Build the structured edges from data first. Use LLM extraction only for advisory text.

---

## 5. Project layout

```
securag/
  third_party/                 # reference clones (gitignored)
  data/
    raw/                       # clones + downloads (gitignored)
    processed/                 # cleaned JSONL, chunks
    eval/                      # question sets, gold answers
  src/securag/
    ingest/                    # load -> clean -> chunk -> enrich -> embed -> index
    graph/                     # neo4j schema, loaders, cypher retrievers
    retrieval/                 # bm25, dense, rrf, rerank (graph + cross-encoder)
    agent/
      state.py                 # typed state
      nodes.py                 # router, retriever, evaluator, rewriter, generator, reflector
      graph.py                 # LangGraph wiring + recursion limit
    eval/                      # ragas runner, ablation runner, latency/cost logger
    api/                       # FastAPI
    ui/                        # Streamlit or React
  tests/
  notebooks/
  THIRD_PARTY.md
  build.md
  docker-compose.yml
  pyproject.toml
  .env.example
```

---

## 6. Build plan (6 weeks)

**Week 1 — Data + graph**
- Clone data (section 3). Filter CVEs to 2023-2026, web-app and network classes only.
- Parse CVE JSON, KEV, ATT&CK STIX, CAPEC, CWE.
- Create Neo4j (Docker, APOC enabled). Load structured edges.
- Done when: Cypher query returns CVE -> CWE -> CAPEC -> Technique chain.

**Week 2 — Vector + hybrid retrieval**
- Chunk descriptions and advisories (domain-aware: one CVE = one chunk + metadata).
- Pinecone index with namespaces `cve`, `attack`, `advisories`. Metadata: cwe, severity, kev, year.
- BM25 + dense + RRF. Add HyDE and query expansion.
- Done when: hybrid beats dense-only on a 20-question dev set.

**Week 3 — LangGraph agent v1**
- Fork #5 skeleton. Nodes: router, retrieve, grade, rewrite, generate.
- Add graph retrieval node (Neo4j) for multi-hop route.
- Add recursion limit + max rewrite rounds + novelty guard.
- Done when: simple and multi-hop questions both route and answer.

**Week 4 — Paper components**
- CRAG evaluator (LLM-scored, 3 classes) + decompose-recompose.
- GraphER-style rerank: offline metadata enrichment, query-time graph, smoothing.
- Cross-encoder rerank (#21).
- Reflection node for faithfulness.
- Done when: each component can be toggled by config flag (needed for ablation).

**Week 5 — Evaluation**
- Build question set: 60-100 questions, 3 tiers (single-hop, 2-hop, 3-hop). Gold answers checked against source data.
- Run RAGAS + multi-hop accuracy + latency + token cost.
- Optional: run a HotpotQA / 2Wiki subset to compare with Graph-R1 numbers.
- LangSmith or LangFuse tracing on.

**Week 6 — Polish**
- UI, demo script, failure analysis, README, report, slides.
- Stretch (only if time): reward-based router tuning, RL fine-tuning from #1 / #2.

---

## 7. Ablation table (the main result)

| Config | Components |
|---|---|
| A | Naive RAG (dense only) |
| B | + BM25 hybrid (RRF) |
| C | + cross-encoder rerank |
| D | + graph retrieval |
| E | + GraphER-style rerank |
| F | + CRAG evaluator and rewrite loop |
| G | Full (+ router + reflection) |

Report per config: Faithfulness, Answer Relevancy, Context Precision, Context Recall, multi-hop accuracy (by tier), P50 / P95 latency, tokens per query, cost per query.
Baseline for comparison: Microsoft GraphRAG (#11).

---

## 8. Stack

- Python 3.10-3.12 (neo4j-graphrag requires 3.9-3.12)
- LangGraph, LangChain, Pinecone client, `rank_bm25`
- Neo4j 5 + APOC (Docker)
- Embeddings: BGE-M3 (local) or OpenAI; Reranker: `bge-reranker-v2-m3`
- RAGAS, LangSmith or LangFuse
- FastAPI + Streamlit (or React)

```bash
docker run -d --name neo4j -p 7474:7474 -p 7687:7687 \
  -e NEO4J_AUTH=neo4j/change_me \
  -e NEO4J_PLUGINS='["apoc"]' neo4j:5
```

`.env.example`
```
OPENAI_API_KEY=
PINECONE_API_KEY=
PINECONE_INDEX=securag
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=
LANGSMITH_API_KEY=
MAX_REWRITE_ROUNDS=3
RECURSION_LIMIT=50
```

---

## 9. Risks and honest caveats

- **No GraphER code.** Implement from paper. Budget extra time, keep it as a toggle.
- **RL is not v1.** Graph-R1 and RouteRAG train with RL (GPU heavy). v1 uses an LLM router and a scored evaluator. Say this clearly in the report; do not claim RL training unless you do it.
- **Graph-R1 uses a hypergraph.** SecuRAG uses a Neo4j property graph. Adapted, not identical. Document differences.
- **CRAG repo is heavy.** Needs LLaMA-2 weights. Reimplement the evaluator with an LLM or a small cross-encoder.
- **Data freshness.** CVE data changes daily. Pin a snapshot date and commit hash for reproducibility.
- **Answer correctness.** Wrong CVE/patch info looks bad in a demo. Validate gold answers against source records; show citations in every answer.
- **Licenses.** Check each repo's LICENSE. ATT&CK has its own Terms of Use. CVE and KEV data are public but cite sources.
- **Cost.** LLM graph extraction is expensive. Use structured edges first, extract from advisories only, use a small model.
- **Licenses.** URLs exist, but read each LICENSE before copying any code.

---

## 10. Pre-start checklist

- [ ] For every cloned repo, note license + last commit in THIRD_PARTY.md
- [ ] Record commit hashes in THIRD_PARTY.md
- [ ] Pick data slice (years, vuln classes)
- [ ] Neo4j running with APOC
- [ ] Pinecone index created
- [ ] 20-question dev set written
- [ ] Config flags for every component (ablation depends on this)

---

## 11. References

- Graph-R1: Luo et al., ICML 2026 (arXiv 2507.21892)
- RouteRAG: Guo et al., ACL Findings 2026 (arXiv 2512.09487)
- GraphER: Miao et al., Oracle AI (arXiv 2603.24925)
- CRAG: Yan et al. (arXiv 2401.15884)
- GraphRAG: Edge et al. (arXiv 2404.16130)
- Self-RAG: Asai et al., ICLR 2024
