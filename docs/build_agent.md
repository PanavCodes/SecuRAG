# SecuRAG — Agent Build Spec

Audience: an AI coding agent. Build the project exactly as specified.
Companion file: `docs/build.md` (repo list, paper context). Read it first, then this file. Setup of venv, Docker and clones is described in `SETUP.md` and is normally done by the human before the agent starts.
Where this file and `build.md` disagree, this file wins.

---

## 0. Operating rules for the agent

1. Work step by step in the order of Section 5. Do not start step N+1 until step N's **Acceptance test** passes.
2. After each step: run the acceptance test, print the result, commit with message `step-N: <title>`.
3. Never invent field names. Open a real sample file from `data/raw/` and confirm the field path before writing a parser. Section 4 lists *expected* paths; they are from memory of the formats and may be slightly off.
4. Never invent library APIs. Library versions move. Check the installed version's docs or `help()` before using an API. If an API differs from this file, follow the installed library and note it in `NOTES.md`.
5. Do not import code from `third_party/`. Read it, then re-implement in `src/securag/`. Add a header comment naming the source repo, commit hash and license.
6. No hardcoded secrets. Read everything from `.env`. Never commit `.env`.
7. Every pipeline component must be switchable by a config flag (Section 7). The ablation study depends on it.
8. Keep a running `NOTES.md`: assumptions, deviations from this spec, things that failed. Update it every step.
9. If a step cannot pass its acceptance test after 3 honest attempts, stop and write the blocker in `NOTES.md` instead of faking the result.
10. Do not claim features that are not built. In particular: **no RL training in v1**. The router is LLM-based. Reward-style scoring is used for evaluation only.

---

## 1. Locked decisions (do not change without writing why in NOTES.md)

| Topic | Decision |
|---|---|
| Language | Python 3.12 (dependency resolution was tested on 3.12; 3.11 should also work) |
| Package manager | `uv` (fallback `pip` + venv) |
| Agent framework | LangGraph (+ LangChain for loaders/splitters/LLM wrappers) |
| Graph DB | Neo4j 5.x Community in Docker, APOC plugin enabled |
| Vector DB | Pinecone serverless, one index, three namespaces |
| Sparse retrieval | `rank_bm25` kept **in the application**, not in Pinecone |
| Fusion | Reciprocal Rank Fusion in application code, `k=60` |
| Doc store (full text) | SQLite file `data/processed/docstore.sqlite` |
| Embeddings | `BAAI/bge-m3` via `sentence-transformers` (dense vectors only), **dimension 1024** |
| Reranker | `BAAI/bge-reranker-v2-m3` via `sentence-transformers` `CrossEncoder`. FlagEmbedding is NOT used (less dependency risk). |
| LLM | Provider-agnostic. Model names come from `.env` (`LLM_MODEL_MAIN`, `LLM_MODEL_FAST`). Fast model for routing/grading, main model for answer/reflection. |
| Evaluation | RAGAS + custom multi-hop accuracy |
| Tracing | LangSmith (env flag) or LangFuse. Pick one, default LangSmith. |
| API | FastAPI |
| UI | Streamlit (simple, one file) |
| Data slice | CVEs from `DATA_YEARS` (default 2024,2025), capped at `CVE_MAX` (default 20000; keep all KEV-listed CVEs first, then CVEs that have a CWE, then the rest), plus all ATT&CK enterprise, all CAPEC, all CWE. Reason: one CVE year alone is ~39k files / ~400 MB on disk. |

Why BM25 outside Pinecone: Pinecone single-index sparse-dense hybrid has metric constraints; keeping BM25 in-app avoids that and keeps ablation toggles simple.
Why text in SQLite: Pinecone metadata has a size limit per vector. Store only short fields in metadata, full text in SQLite keyed by `chunk_id`.

---

## 2. Environment setup (Step 0 details)

### Required services
- Docker (for Neo4j)
- Pinecone account + API key
- LLM provider API key
- Optional GPU. `bge-m3` and the reranker run on CPU but slowly; use GPU if available.

### Neo4j container
```bash
docker run -d --name securag-neo4j \
  -p 7474:7474 -p 7687:7687 \
  -v $(pwd)/data/neo4j:/data \
  -e NEO4J_AUTH=neo4j/${NEO4J_PASSWORD} \
  -e NEO4J_PLUGINS='["apoc"]' \
  neo4j:5
```
Check: browser at `http://localhost:7474` loads; `RETURN apoc.version()` returns a version.

### Python dependencies (pin exact versions after first successful install into `requirements.lock`)
```
langgraph
langgraph-checkpoint-sqlite
langchain
langchain-community
langchain-text-splitters
neo4j
neo4j-graphrag
pinecone
sentence-transformers
rank-bm25
ragas
datasets
fastapi
uvicorn
streamlit
pydantic
pydantic-settings
python-dotenv
pandas
pyarrow
lxml
stix2
tqdm
pytest
```
`neo4j-graphrag` requires Python 3.9-3.12, so use 3.11 or 3.12 (not 3.13). Note: LangChain is now v1.x. Old tutorial imports (e.g. `langchain.text_splitter`, `langchain.retrievers.EnsembleRetriever`) have moved; use `langchain_text_splitters` and `langchain_core`, and prefer plain LangGraph + your own code over legacy LangChain chains. Full pinned list is in `requirements.txt`; PyTorch must be installed separately first (see `SETUP.md`).

### `.env.example`
```
# LLM
LLM_PROVIDER=
LLM_API_KEY=
LLM_MODEL_MAIN=
LLM_MODEL_FAST=

# Pinecone
PINECONE_API_KEY=
PINECONE_INDEX=securag
PINECONE_CLOUD=aws
PINECONE_REGION=us-east-1

# Neo4j
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=

# Models
EMBED_MODEL=BAAI/bge-m3
EMBED_DIM=1024
RERANK_MODEL=BAAI/bge-reranker-v2-m3
DATA_YEARS=2024,2025
CVE_MAX=20000

# Agent limits
MAX_REWRITE_ROUNDS=3
RECURSION_LIMIT=50
RETRIEVAL_TOP_K=20
RERANK_TOP_N=6
NOVELTY_COSINE_THRESHOLD=0.90

# Tracing
LANGSMITH_TRACING=false
LANGSMITH_API_KEY=
LANGSMITH_PROJECT=securag

# Web fallback (optional)
WEB_SEARCH_PROVIDER=
WEB_SEARCH_API_KEY=
```

---

## 3. Database specifications

### 3.1 Neo4j property graph

**Node labels and properties**

| Label | Key property (unique) | Other properties |
|---|---|---|
| `CVE` | `id` (e.g. `CVE-2024-1234`) | `description`, `published` (date), `cvss_score` (float, nullable), `cvss_severity`, `in_kev` (bool), `kev_date_added` (date, nullable), `ssvc_exploitation` (nullable) |
| `CWE` | `id` (e.g. `CWE-79`) | `name`, `description`, `abstraction` |
| `CAPEC` | `id` (e.g. `CAPEC-63`) | `name`, `description`, `severity`, `likelihood` |
| `Technique` | `id` (e.g. `T1021`, sub-technique `T1021.001`) | `name`, `description`, `is_subtechnique` (bool), `platforms` (list) |
| `Tactic` | `id` (e.g. `TA0008`) | `name`, `shortname`, `description` |
| `Mitigation` | `id` (e.g. `M1032`) | `name`, `description` |
| `Product` | `key` (`vendor::product`, lowercase) | `vendor`, `product` |
| `Advisory` | `id` | `title`, `source`, `url`, `published`, `text_ref` (doc id in docstore) |
| `Chunk` | `chunk_id` | `namespace`, `source_id`, `position` (links graph to vector store) |

**Relationship types**

```
(CVE)-[:HAS_WEAKNESS]->(CWE)
(CWE)-[:RELATED_ATTACK_PATTERN]->(CAPEC)
(CAPEC)-[:RELATED_TECHNIQUE]->(Technique)
(Technique)-[:IN_TACTIC]->(Tactic)
(Technique)-[:SUBTECHNIQUE_OF]->(Technique)
(Mitigation)-[:MITIGATES]->(Technique)
(CVE)-[:AFFECTS]->(Product)
(Advisory)-[:MENTIONS]->(CVE)
(Chunk)-[:DESCRIBES]->(CVE|CWE|CAPEC|Technique|Mitigation|Advisory)
(CWE)-[:CHILD_OF]->(CWE)
```

**Constraints and indexes** (run once in `graph/schema.py`, idempotent)
```cypher
CREATE CONSTRAINT cve_id IF NOT EXISTS FOR (n:CVE) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT cwe_id IF NOT EXISTS FOR (n:CWE) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT capec_id IF NOT EXISTS FOR (n:CAPEC) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT tech_id IF NOT EXISTS FOR (n:Technique) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT tactic_id IF NOT EXISTS FOR (n:Tactic) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT mit_id IF NOT EXISTS FOR (n:Mitigation) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT product_key IF NOT EXISTS FOR (n:Product) REQUIRE n.key IS UNIQUE;
CREATE CONSTRAINT advisory_id IF NOT EXISTS FOR (n:Advisory) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT chunk_id IF NOT EXISTS FOR (n:Chunk) REQUIRE n.chunk_id IS UNIQUE;
CREATE INDEX cve_published IF NOT EXISTS FOR (n:CVE) ON (n.published);
CREATE INDEX cve_kev IF NOT EXISTS FOR (n:CVE) ON (n.in_kev);
```
Use `MERGE` on the key property for every load so re-runs do not duplicate. Load in batches with `UNWIND $rows AS row`.

**Neo4j vector index:** not required. Dense vectors live in Pinecone. Do not duplicate them in Neo4j.

### 3.2 Pinecone

- One index, name from `PINECONE_INDEX`.
- `dimension = 1024` (must equal `EMBED_DIM`; if the embedding model changes, create a new index).
- `metric = cosine`.
- Serverless spec from `PINECONE_CLOUD` / `PINECONE_REGION`.
- Create only if absent. Never delete an existing index without being told.

**Namespaces**

| Namespace | Contents |
|---|---|
| `cve` | One chunk per CVE description (plus affected product string) |
| `attack` | CWE, CAPEC, Technique, Mitigation descriptions |
| `advisories` | Chunked advisory / write-up text (if any is ingested) |

**Vector ID scheme:** `{namespace}:{source_id}:{position}` e.g. `cve:CVE-2024-1234:0`.

**Metadata per vector** (keep small; no full text)

| Field | Type | Applies to |
|---|---|---|
| `source_id` | string | all |
| `source_type` | string (`cve`,`cwe`,`capec`,`technique`,`mitigation`,`advisory`) | all |
| `title` | string (truncate 200 chars) | all |
| `year` | int | cve, advisory |
| `cwe_ids` | list of strings | cve |
| `severity` | string | cve |
| `in_kev` | bool | cve |
| `text_preview` | string (first 300 chars) | all |

Full chunk text: SQLite `chunks(chunk_id TEXT PRIMARY KEY, namespace TEXT, source_id TEXT, source_type TEXT, position INT, text TEXT, meta_json TEXT)`.

### 3.3 BM25 index
- Built from all chunk texts in the docstore, one BM25 index per namespace plus one combined.
- Tokenizer: lowercase, split on non-alphanumerics, **keep IDs intact** (`cve-2024-1234`, `t1021`, `cwe-79`) as single tokens. Exact IDs matter for BM25.
- Persist with `pickle` to `data/processed/bm25_{namespace}.pkl`; rebuild whenever the docstore changes.

---

## 4. Source-to-graph mapping (verify every path against a real file first)

### 4.1 CVE (`data/raw/cvelistV5/cves/<year>/<bucket>/CVE-*.json`, CVE JSON 5.x)
Paths below were **checked against a real 2024 file** (Oct 2026). Still re-check on your sample.
- id: `cveMetadata.cveId`
- state: `cveMetadata.state` → skip if not `PUBLISHED`
- published: `cveMetadata.datePublished`
- description: `containers.cna.descriptions[]` where `lang` starts with `en` → `value`
- CWE: `containers.cna.problemTypes[].descriptions[]` where `type == "CWE"` → `cweId`; also check `containers.adp[]` (CISA container) for the same
- products: `containers.cna.affected[]` → `vendor`, `product`
- CVSS: `containers.cna.metrics[]` → `cvssV3_1.baseScore` / `baseSeverity` (also check `cvssV4_0`, and ADP containers)
- KEV (CISA ADP container): `containers.adp[].metrics[].other` where `type == "kev"` → `content.dateAdded` (about 0.5% of CVEs)
- SSVC (same container): `other.type == "ssvc"` → `other.content` has keys `id, role, options, version, timestamp`; `options` is a list of single-key dicts (e.g. Exploitation, Automatable, Technical Impact)
- CNA CWE present in roughly 57% of records; CISA ADP adds CWE for some more. Take the union.
- CNA CVSS 3.1 present in roughly 66%; some CVEs have only v3.0 / v4.0 or none, so `cvss_score` can be null.
- Files live at `cves/<year>/<NNxxx>/CVE-*.json`.
Filter: year in `DATA_YEARS`, then apply `CVE_MAX` rule from Section 1.

### 4.2 KEV (`data/raw/kev-data/`)
Use the JSON file. Expected: `vulnerabilities[]` with `cveID`, `dateAdded`, `vendorProject`, `product`, `shortDescription`. Set `CVE.in_kev = true` and `kev_date_added`. Create the CVE node even if it is pre-2023 only if it is a KEV entry (KEV is small and useful for demos).

### 4.3 ATT&CK (`data/raw/attack-stix-data/enterprise-attack/enterprise-attack.json`, STIX 2.1)
Parse `objects[]`:
- `type == "attack-pattern"` → Technique. ID from `external_references[]` where `source_name == "mitre-attack"` → `external_id`. Skip if `revoked` or `x_mitre_deprecated` is true.
- `type == "x-mitre-tactic"` → Tactic (`external_id` TAxxxx, `x_mitre_shortname`).
- `type == "course-of-action"` → Mitigation.
- `type == "relationship"`: `relationship_type == "mitigates"` → `MITIGATES`; `subtechnique-of` → `SUBTECHNIQUE_OF`.
- Technique → Tactic: from `kill_chain_phases[].phase_name` matching tactic `x_mitre_shortname`.
- Technique → CAPEC: **do not rely on ATT&CK for this** (only ~36 techniques carry CAPEC refs). Take the link from the CAPEC side (Section 4.4).
- Note: the current ATT&CK file also has types `x-mitre-analytic`, `x-mitre-detection-strategy`, `campaign`, `malware`, `tool`, `intrusion-set`. Ignore them in v1.
- Use only `enterprise-attack/enterprise-attack.json` (the folder holds every historical version and is >1 GB).

### 4.4 CAPEC (`data/raw/cti/capec/2.1/stix-capec.json`; path checked, 2.0 also exists)
- `attack-pattern` objects (615) with `external_references[].source_name == "capec"` → CAPEC node (`external_id` like `CAPEC-63`).
- Same object lists CWE with `source_name == "cwe"` (`external_id` like `CWE-79`) → `CWE-RELATED_ATTACK_PATTERN->CAPEC`.
- Same object lists ATT&CK with `source_name == "ATTACK"` (`external_id` like `T1574.010`, about 177 CAPECs) → `CAPEC-RELATED_TECHNIQUE->Technique`.
- `course-of-action` objects + `mitigates` relationships are CAPEC mitigations; ignore in v1.
- Expect the full CVE→CWE→CAPEC→Technique chain to exist for only a subset of CVEs. That is normal; build demo questions around CWEs that do link through.

### 4.5 CWE (`data/raw/cwe/*.xml`, downloaded from cwe.mitre.org)
- `Weakness` elements: `ID`, `Name`, `Description`, `Abstraction`.
- Hierarchy: `Related_Weaknesses/Related_Weakness` with `Nature="ChildOf"` → `CHILD_OF`.
- Related CAPEC: `Related_Attack_Patterns/Related_Attack_Pattern` `CAPEC_ID` → link if not already created.
- IDs are numeric in XML; store as `CWE-<n>`.

### 4.6 Advisories (optional, last)
If time permits, ingest a small set (≤200) of public security advisory texts into the `advisories` namespace. Extract `CVE-\d{4}-\d{4,}` mentions with regex → `MENTIONS`. Use LLM entity extraction (`neo4j-graphrag` `SimpleKGPipeline`) only on this text, with the fast model.

---

## 5. Step-by-step build

### Step 0 — Scaffold
**Actions:** create the folder layout from `build.md` Section 5; `pyproject.toml`; `.gitignore` (include `.env`, `data/raw/`, `data/neo4j/`, `third_party/`, `*.pkl`); `.env.example`; `NOTES.md`; `THIRD_PARTY.md`; `docker-compose.yml` (Neo4j service from Section 2); if `third_party/` and `data/raw/` are missing, run `scripts/clone_third_party.*` and `scripts/clone_data.*` (the human normally has done this already; see `SETUP.md`). Create the folder layout without overwriting existing files.
**Acceptance:** `docker compose up -d` brings Neo4j up; `uv run python -c "import langgraph, neo4j, pinecone"` succeeds; `THIRD_PARTY.md` lists each cloned repo with commit hash.

### Step 1 — Config + clients
**Actions:** `src/securag/config.py` (pydantic settings from `.env`); `clients.py` returning Neo4j driver, Pinecone index handle, embedder, reranker, LLM (main + fast). Add `scripts/healthcheck.py` that tests all of them.
**Acceptance:** `python scripts/healthcheck.py` prints OK for Neo4j, Pinecone, embedder (returns vector of length 1024), reranker (scores 2 sample pairs), LLM (returns text).

### Step 2 — Parse sources to normalized JSONL
**Actions:** one parser per source in `src/securag/ingest/parsers/` (cve, kev, attack, capec, cwe). Output to `data/processed/*.jsonl` using the fields in Section 3.1. Open a real sample of each source first and log the field paths used in `NOTES.md`.
**Acceptance:** `pytest tests/test_parsers.py` passes with checks: CVE count > 0; every CVE has `id` and `description`; ≥1 Technique with id `T1021`; ≥1 CWE with id `CWE-79`; KEV count > 0. Print counts per file.

### Step 3 — Build Neo4j graph
**Actions:** `graph/schema.py` (constraints/indexes, Section 3.1); `graph/load.py` loads nodes then relationships with `MERGE` and batching. Idempotent.
**Acceptance:** run the loader twice; node counts unchanged on the second run. This Cypher returns ≥1 row:
```cypher
MATCH (c:CVE)-[:HAS_WEAKNESS]->(w:CWE)-[:RELATED_ATTACK_PATTERN]->(p:CAPEC)-[:RELATED_TECHNIQUE]->(t:Technique)-[:IN_TACTIC]->(ta:Tactic)
RETURN c.id, w.id, p.id, t.id, ta.name LIMIT 5
```
If it returns 0 rows, inspect the link chain edge by edge, log which link is empty, fix the mapping (Section 4), do not fake data.

### Step 4 — Chunk, embed, store
**Actions:** `ingest/chunk.py` — CVE: one chunk per CVE (`"{id}. {description} Affected: {products}"`). CWE/CAPEC/Technique/Mitigation: one chunk each, split with `RecursiveCharacterTextSplitter` (chunk_size 800, overlap 100) only if longer. Write to SQLite docstore. `ingest/embed_index.py` embeds in batches, upserts to Pinecone with metadata from Section 3.2. Create `Chunk` nodes and `DESCRIBES` edges in Neo4j.
**Acceptance:** Pinecone namespace counts equal docstore counts per namespace (check `describe_index_stats`). A test query `"cross-site scripting"` against `attack` namespace returns CWE-79 in the top 5. Re-running does not duplicate vectors (same IDs).

### Step 5 — BM25 + hybrid retrieval
**Actions:** `retrieval/bm25.py` (Section 3.3), `retrieval/dense.py`, `retrieval/hybrid.py` with RRF. Metadata filter support (`year`, `in_kev`, `severity`, `source_type`).
**Acceptance:** `tests/test_retrieval.py`: query by exact ID `CVE-2021-44228` → BM25 returns it rank 1 (if in slice; otherwise use a known in-slice CVE); a semantic query returns relevant results via dense; hybrid recall@10 ≥ best of dense-only and BM25-only on the 20-question dev set (`data/eval/dev.jsonl`, create it now — format in Section 8).

### Step 6 — Query optimization
**Actions:** `retrieval/query_opt.py` — query expansion (LLM → 3 variants), HyDE (LLM writes a hypothetical answer → embed), metadata filter extraction from the query ("exploited in the wild" → `in_kev=true`). Each behind a flag.
**Acceptance:** with each flag on, retrieval on the dev set runs without error; print recall@10 with and without each. Keep a flag on by default only if it does not lower recall.

### Step 7 — Graph retrieval
**Actions:** `graph/retrieve.py` — (a) entity linking: regex for `CVE-…`, `CWE-…`, `CAPEC-…`, `T\d{4}(\.\d{3})?`, plus fuzzy name match against Technique/CWE names; (b) fixed Cypher templates for common hops (CVE→CWE→CAPEC→Technique→Tactic, Technique→Mitigation, KEV filter); (c) generic bounded k-hop expansion (`max 3 hops`, `LIMIT` always set). Return structured paths plus the chunk texts of nodes on the paths.
**Acceptance:** for a known multi-hop question (written in dev set) the returned paths include the gold chain. Every Cypher query has a `LIMIT`; add a test that scans the code for unbounded `MATCH` patterns.

### Step 8 — Rerankers
**Actions:** `retrieval/rerank.py`: (a) cross-encoder rerank (`bge-reranker-v2-m3`) on top `RETRIEVAL_TOP_K`, keep `RERANK_TOP_N`. (b) `retrieval/graph_rerank.py` — GraphER-style reranker implemented from arXiv 2603.24925 (**no public code exists**; read the paper first):
  1. Offline enrichment: at index time, attach relation keys to each chunk (e.g. CWE ids, technique ids, product key).
  2. Online: take candidates with initial scores; build a graph where two candidates are connected if they share a key; run smoothing (score_i ← α·score_i + (1-α)·mean(neighbor scores)); α default 0.7, configurable.
  3. Re-sort.
  Document in `NOTES.md` every place where your implementation is a simplification of the paper.
**Acceptance:** unit test with a synthetic candidate set shows that a low-scored candidate sharing keys with two high-scored ones moves up. Rerank flags each toggle independently.

### Step 9 — Agent state and nodes
**Actions:** `agent/state.py`, `agent/nodes.py`, `agent/graph.py` per Section 6. Build with LangGraph `StateGraph`, conditional edges, and a checkpointer (in-memory first, SQLite later). Run with `recursion_limit = RECURSION_LIMIT`.
**Acceptance:** `pytest tests/test_agent_routes.py`: a single-fact question routes `simple`; a question containing two relations routes `multi_hop`; an unrelated question ("weather in Paris") routes `out_of_kb`. A run never exceeds `MAX_REWRITE_ROUNDS` rewrites; test with a deliberately unanswerable question and assert termination.

### Step 10 — CRAG evaluator and rewrite loop
**Actions:** `grade_documents` node: for each retrieved chunk, fast LLM scores relevance 0-1 with a strict JSON output. Aggregate: any chunk ≥ 0.7 → `correct`; all < 0.3 → `incorrect`; else `ambiguous`. `correct` → refine (decompose passages into key sentences, drop irrelevant); `ambiguous` → refine + extra retrieval from another source; `incorrect` → rewrite query (LLM) and loop. **Novelty guard:** if the rewritten query's embedding cosine similarity to any previous query ≥ `NOVELTY_COSINE_THRESHOLD`, stop looping and go to fallback.
**Acceptance:** log shows loop terminating by (a) success, (b) max rounds, or (c) novelty guard, each covered by a test.

### Step 11 — Generation with citations + reflection
**Actions:** `generate` node: answer only from provided context, every claim followed by a citation tag `[CVE-…]`, `[CWE-…]`, `[T…]`, or `[chunk_id]`; if context is insufficient, say so. `reflect` node: main LLM checks each claim against context, returns `{faithful: bool, unsupported_claims: []}`; if not faithful and rounds remain → regenerate with the unsupported claims removed or re-retrieve.
**Acceptance:** 10 sample questions: every answer contains ≥1 citation; every cited ID exists in Neo4j (write a validator that checks this automatically and fails the test otherwise).

### Step 12 — Observability
**Actions:** enable LangSmith (or LangFuse) tracing via env. Add `eval/metrics_logger.py` capturing per-query: latency per node, total latency, tokens in/out, estimated cost (price table in config), route taken, rewrite rounds.
**Acceptance:** after a 20-query run, a CSV `results/runtime_metrics.csv` exists with P50 / P95 latency computed by a script `scripts/summarize_metrics.py`.

### Step 13 — Evaluation + ablation
**Actions:** finish the question set (Section 8) to ≥60 questions. `eval/run_ablation.py` runs configs A-G (Section 7) over the set and writes `results/ablation.csv` and `results/ablation.md`. Run RAGAS (faithfulness, answer relevancy, context precision, context recall) plus multi-hop exact/F1 accuracy by tier.
**Acceptance:** `results/ablation.md` table exists with all 7 configs × all metrics. No empty cells. Include a "Failure analysis" file `results/failures.md` listing ≥10 wrong answers with cause (retrieval miss / wrong graph path / evaluator error / generation error).

### Step 14 — API + UI
**Actions:** FastAPI `POST /ask {question, config_overrides?}` → `{answer, citations, route, rounds, latency_ms, trace_url?}`; Streamlit page: question box, answer, citations with expandable source text, graph path shown as text list, config toggles.
**Acceptance:** `curl` to `/ask` returns valid JSON; Streamlit launches; one end-to-end demo question works for each route.

### Step 15 — Docs
**Actions:** `README.md` (setup, run, architecture diagram, results table from Step 13, limitations). Update `THIRD_PARTY.md`. Final `NOTES.md` cleanup.
**Acceptance:** a fresh clone + README instructions reaches a working `/ask` (the agent verifies by following its own README in a clean venv where possible).

---

## 6. Agent state and node contracts

```python
class AgentState(TypedDict):
    question: str
    route: Literal["simple", "multi_hop", "out_of_kb"] | None
    sub_questions: list[str]
    queries_tried: list[str]
    rewrite_round: int
    candidates: list[dict]       # {chunk_id, text, source_id, source_type, score, via}
    graph_paths: list[dict]      # {nodes: [...], rels: [...]}
    graded: list[dict]           # candidate + relevance score
    verdict: Literal["correct", "ambiguous", "incorrect"] | None
    context: list[dict]          # refined passages passed to generation
    answer: str | None
    citations: list[str]
    reflection: dict | None      # {faithful: bool, unsupported_claims: [...]}
    config: dict                 # active feature flags
    metrics: dict                # per-node latency, tokens
```

| Node | Input → Output | Notes |
|---|---|---|
| `route_query` | question → `route` | Fast LLM, structured output, also returns sub_questions for multi_hop |
| `retrieve_hybrid` | question/queries → `candidates` | BM25 + dense + RRF (+ expansion / HyDE if flagged) |
| `retrieve_graph` | question → `graph_paths`, extra `candidates` | Only on `multi_hop` or when flagged |
| `rerank` | `candidates` → `candidates` (top N) | Graph rerank then cross-encoder, each flagged |
| `grade_documents` | `candidates` → `graded`, `verdict` | Fast LLM, JSON |
| `refine_context` | `graded` → `context` | Decompose-recompose, drop low-scoring |
| `rewrite_query` | question + `queries_tried` → new query, `rewrite_round += 1` | Novelty guard here |
| `web_fallback` | question → `candidates` | Only if configured; else return "not found in knowledge base" path |
| `generate` | `context` → `answer`, `citations` | Citation tags mandatory |
| `reflect` | `answer`, `context` → `reflection` | Main LLM |

Edges:
- `route_query` → (`simple`: `retrieve_hybrid`) | (`multi_hop`: `retrieve_hybrid` + `retrieve_graph`) | (`out_of_kb`: `web_fallback`)
- `rerank` → `grade_documents`
- `grade_documents` → `correct`/`ambiguous`: `refine_context` | `incorrect`: `rewrite_query` if rounds < max and novel, else `web_fallback`/`generate` with "insufficient evidence"
- `generate` → `reflect` → `END` (or one regenerate pass if unfaithful)

All LLM nodes return strict JSON validated with pydantic; on parse failure retry once, then fail the node with a logged error.

---

## 7. Config flags and ablation configs

```yaml
flags:
  use_bm25: true
  use_query_expansion: false
  use_hyde: false
  use_cross_encoder: true
  use_graph_retrieval: true
  use_graph_rerank: true
  use_crag_loop: true
  use_router: true
  use_reflection: true
```

| Config | Flags on (everything else off) |
|---|---|
| A Naive | dense only, no rerank, no router, no loop |
| B | A + `use_bm25` |
| C | B + `use_cross_encoder` |
| D | C + `use_graph_retrieval` |
| E | D + `use_graph_rerank` |
| F | E + `use_crag_loop` |
| G Full | F + `use_router` + `use_reflection` (+ expansion/HyDE if they helped in Step 6) |

Baseline for comparison (if time): Microsoft GraphRAG run over the same corpus.

---

## 8. Evaluation data format

`data/eval/questions.jsonl`, one JSON object per line:
```json
{
  "id": "q001",
  "tier": 1,
  "question": "...",
  "gold_answer": "...",
  "gold_entities": ["CVE-2024-1234", "CWE-79"],
  "gold_path": ["CVE-2024-1234", "CWE-79", "CAPEC-63", "T1059"],
  "source_check": "how this answer was verified from raw data"
}
```
- Tier 1: single-hop (≈20). Tier 2: two hops (≈25). Tier 3: three or more hops, or aggregation (≈15-20).
- **Gold answers are generated from Neo4j / raw data by script where possible** (Cypher → answer), not written from the LLM's memory. Hand-check a random 20%.
- Include 5-10 out-of-KB questions with `"gold_answer": "NOT_IN_KB"` to test the router and fallback.
- RAGAS input columns: `question`, `answer`, `contexts`, `ground_truth` (check the installed version's expected column names).

---

## 9. Definition of done

- [ ] Steps 0-15 acceptance tests pass
- [ ] `results/ablation.md` complete (7 configs × metrics)
- [ ] `results/failures.md` has ≥10 analysed failures
- [ ] Every answer in the demo has validated citations
- [ ] README reproduces the setup from scratch
- [ ] `NOTES.md` lists every deviation and simplification (especially GraphER and any skipped optional parts)
- [ ] No secrets in git history

---

## 10. Things the agent must verify itself (spec may be wrong here)

1. CWE XML field paths (Section 4.5). CVE, ATT&CK and CAPEC paths were checked against real files, but re-check on your sample.
2. Chain coverage: how many CVEs actually reach a Technique. Log the number in `NOTES.md`.
3. Current API of: LangGraph (`StateGraph`, checkpointers, recursion limit config), `pinecone` client (index creation, upsert, query by namespace), `neo4j-graphrag`, RAGAS (metric names, dataset columns).
4. Pinecone free-tier limits on regions, number of indexes and namespaces.
5. Whether the chosen LLM provider supports structured/JSON output; if not, use prompt-enforced JSON plus validation.
6. Licenses and terms: each cloned repo, ATT&CK Terms of Use.
