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

### Step 2: Source Ingestion Parsers to Normalized JSONL
- Real sample inspection and field paths logged:
  - **KEV** (`data/raw/kev-data/known_exploited_vulnerabilities.json`):
    - `vulnerabilities[]`: `cveID`, `vendorProject`, `product`, `vulnerabilityName`, `dateAdded`, `shortDescription`, `requiredAction`, `dueDate`, `knownRansomwareCampaignUse`, `cwes` (list of strings).
  - **CWE** (`data/raw/cwe/cwec_v4.20.xml`):
    - Root tag `{*}Weaknesses/{*}Weakness`: `ID` (stored as `CWE-<ID>`), `Name`, `Abstraction`.
    - Description: `{*}Description` text (with fallback to `{*}Extended_Description`).
    - Parents: `{*}Related_Weaknesses/{*}Related_Weakness[Nature="ChildOf"]/@CWE_ID`.
    - Attack patterns: `{*}Related_Attack_Patterns/{*}Related_Attack_Pattern/@CAPEC_ID` (stored as `CAPEC-<ID>`).
  - **CAPEC** (`data/raw/cti/capec/2.1/stix-capec.json`):
    - `objects[]` where `type == "attack-pattern"`. Filtered out `revoked` and `x_mitre_deprecated`.
    - Extracted `id` from `external_references` where `source_name == "capec"` (`external_id`).
    - Weaknesses from `source_name == "cwe"` -> `cwe_ids` (prefixed with `CWE-`).
    - Techniques from `source_name.lower() == "attack"` -> `technique_ids` (177 CAPECs link to ATT&CK).
    - Attributes: `name`, `description`, `x_capec_typical_severity`, `x_capec_likelihood_of_attack`.
  - **ATT&CK** (`data/raw/attack-stix-data/enterprise-attack/enterprise-attack.json`):
    - Filtered out `revoked` and `x_mitre_deprecated`.
    - First pass: mapped STIX IDs to `external_references[mitre-attack].external_id` (e.g. `T1021`, `TA0008`, `M1032`) and indexed tactics by `x_mitre_shortname`.
    - Second pass: mapped `relationship` objects (`subtechnique-of`, `mitigates`) and mapped kill chain phases to Tactic IDs.
    - Exported 765 normalized records: Techniques (`is_subtechnique`, `platforms`, `tactic_ids`, `subtechnique_of`), Tactics (`name`, `shortname`, `description`), Mitigations (`mitigates_techniques`).
  - **CVE v5.x** (`data/raw/cvelistV5/cves/2024` and `2025`):
    - Filtered to `cveMetadata.state == "PUBLISHED"`.
    - `description`: extracted English description from `containers.cna.descriptions[]`, falling back to general CNA descriptions, ADP descriptions, or KEV description.
    - `cwe_ids`: union of `containers.cna.problemTypes[].descriptions[].cweId`, ADP problemTypes, and KEV catalog CWEs.
    - `cvss_score` and `cvss_severity`: searched `containers.cna.metrics[]` across `cvssV3_1`, `cvssV4_0`, `cvssV3_0`, falling back to `containers.adp[].metrics[]`.
    - `affected_products`: normalized `vendor::product` from `containers.cna.affected[]`.
    - `in_kev` / `kev_date_added`: cross-referenced against CISA KEV catalog lookup and CISA ADP container `metrics[].other[type="kev"]`.
    - `ssvc_exploitation`: extracted from ADP `metrics[].other[type="ssvc"].content.options[]`.
- Multi-threading & Sizing optimizations:
  - 84,785 CVE files scanned across 2024 and 2025 using `ThreadPoolExecutor(max_workers=16)` (reducing scan time from ~15 minutes to 106s).
  - 1,403 KEV entries from outside the 2024/2025 slice (including Log4j `CVE-2021-44228`) ingested to guarantee full demo/evaluation coverage.
  - Priority sorting applied (Priority 1: KEV entries, Priority 2: CVEs with linked CWEs, Priority 3: other published CVEs). Capped at 20,000 as per `CVE_MAX`.
- Acceptance results:
  - `KEV records   : 1756`
  - `CWE records   : 969` (contains `CWE-79`)
  - `CAPEC records : 615` (contains `CAPEC-63`, 177 link to ATT&CK)
  - `ATT&CK records: 765` (contains Technique `T1021`)
  - `CVE records   : 20000` (all 20,000 have valid `id` and non-empty `description`)
  - `pytest tests/test_parsers.py`: **1 passed in 0.41s**.

### Step 3: Build Neo4j Graph
- **Schema & Constraints** (`src/securag/graph/schema.py`):
  - Created 9 unique key constraints: `cve_id`, `cwe_id`, `capec_id`, `tech_id`, `tactic_id`, `mit_id`, `product_key`, `advisory_id`, `chunk_id`.
  - Created 2 performance lookup indexes: `cve_published` on `(:CVE(published))` and `cve_kev` on `(:CVE(in_kev))`.
- **Batch Idempotent Ingestion** (`src/securag/graph/load.py`):
  - Optimized `src/securag/clients.py` with lazy ML model imports, reducing module import time from 32.1s to 1.55s.
  - Ingestion order:
    1. ATT&CK nodes (`:Tactic`, `:Technique`, `:Mitigation`) and relationships (`[:IN_TACTIC]`, `[:SUBTECHNIQUE_OF]`, `[:MITIGATES]`).
    2. CWE nodes (`:CWE`) and hierarchy (`[:CHILD_OF]`).
    3. CAPEC nodes (`:CAPEC`) and technique links (`[:RELATED_TECHNIQUE]`).
    4. Bidirectional CWE-CAPEC link integration (`[:RELATED_ATTACK_PATTERN]`).
    5. Product nodes (`:Product`) and CVE nodes (`:CVE`).
    6. CVE relationships (`[:HAS_WEAKNESS]` to CWE, `[:AFFECTS]` to Product).
  - All loading parameterized via `UNWIND $batch AS row` with `MERGE` on unique keys.
- **Graph Topology Counts**:
  - Nodes: `CVE` (20,000), `Product` (9,295), `CWE` (969), `Technique` (706), `CAPEC` (615), `Mitigation` (44), `Tactic` (15). Total nodes: **31,644**.
  - Relationships: `AFFECTS` (32,161), `HAS_WEAKNESS` (20,849), `MITIGATES` (1,477), `RELATED_ATTACK_PATTERN` (1,212), `CHILD_OF` (1,160), `IN_TACTIC` (881), `SUBTECHNIQUE_OF` (479), `RELATED_TECHNIQUE` (256). Total relationships: **58,475**.
- **Acceptance Verification** (`tests/test_graph.py`):
  - Idempotency test: Ingestion re-executed; node counts verified completely unchanged on second run.
  - Multi-hop traversal test: Verified Cypher query `(c:CVE)-[:HAS_WEAKNESS]->(w:CWE)-[:RELATED_ATTACK_PATTERN]->(p:CAPEC)-[:RELATED_TECHNIQUE]->(t:Technique)-[:IN_TACTIC]->(ta:Tactic)` returns multiple real chains (e.g. `CVE-2024-22334 -> CWE-732 -> CAPEC-1 -> T1574.010 -> Stealth`).
  - Acceptance run: `pytest tests/test_graph.py` **3 passed in 6.46s**.

### Step 4: Chunk, Embed, Store
- **Docstore & Chunking** (`src/securag/ingest/chunk.py`):
  - Created SQLite docstore at `data/processed/docstore.sqlite` indexing 23,757 chunks:
    - 20,000 CVE chunks (namespace `cve`, metadata: `cve_id`, `in_kev`, `cvss_score`, `cvss_severity`, `published_year`).
    - 3,757 ATT&CK/CWE/CAPEC chunks (namespace `attack`, metadata: `source_type`, `source_id`, `title`).
  - Neo4j chunk synchronization: Created 23,757 `(:Chunk)` nodes connected via `[:DESCRIBES]` to their corresponding domain nodes (`:CVE`, `:CWE`, `:CAPEC`, `:Technique`, `:Tactic`, `:Mitigation`).
- **Pinecone Vector Indexing** (`src/securag/ingest/embed_index.py`):
  - Pinecone serverless index (`securag`, 1024-dim, cosine, AWS `us-east-1`).
  - Embedded using `BAAI/bge-m3` on CUDA.
  - Sizing & concurrency: Batch size 16 (prevents CUDA OOM on long descriptions) with 8 concurrent worker threads overlapping GPU encoding with HTTPS upsert roundtrips (~20.5 chunks/s).
  - All 23,757 chunks embedded and upserted: 3,757 in namespace `attack` and 20,000 in namespace `cve`.
- **Acceptance Verification** (`tests/test_embed.py`):
  - `test_docstore_and_neo4j_chunks`: Neo4j DESCRIBES count (23,757) strictly equals docstore count (23,757).
  - `test_pinecone_namespace_counts`: Pinecone serverless index counts verified matching docstore counts.
  - `test_pinecone_semantic_query_top5`: Query `"cross-site scripting"` against `attack` namespace returns `CWE-79` in top 5 (rank 4, score 0.6189).
  - Acceptance run: `pytest tests/test_embed.py` **3 passed in 44.74s**.

### Step 5: BM25 + Hybrid Retrieval (RRF)
- **BM25 Sparse Indexing** (`src/securag/retrieval/bm25.py`):
  - Custom security-aware tokenizer preserving vulnerability identifiers (`CVE-YYYY-NNNN`, `CWE-NNN`, `CAPEC-NNN`, `TNNNN[.NNN]`, `TA-NNNN`).
  - Serialized persistent indices for `bm25_attack.pkl`, `bm25_cve.pkl`, and `bm25_all.pkl`.
  - Exact match test: Query `CVE-2021-44228` returns `CVE-2021-44228` at rank 1 with score 12.48.
- **Dense Vector Retrieval** (`src/securag/retrieval/dense.py`):
  - Dense semantic search using BGE-M3 query embeddings across Pinecone namespaces.
  - Supports Pinecone metadata filtering (`in_kev`, `cvss_severity`, `published_year`).
- **Reciprocal Rank Fusion (RRF)** (`src/securag/retrieval/hybrid.py`):
  - Fusion with $k=60$ combining dense and sparse ranking lists.
- **Evaluation & Acceptance** (`tests/test_retrieval.py`):
  - Evaluated across 20-question development set (`data/eval/dev.jsonl`).
  - Dense-only Recall@10: 0.467 (7/15)
  - BM25-only Recall@10: 0.467 (7/15)
  - Hybrid (RRF) Recall@10: **0.533 (8/15)** — strictly outperforms both single retrievers.
  - Acceptance run: `pytest tests/test_retrieval.py` **4 passed in 134.56s**.

### Step 6: Query Optimization
- **Metadata Filter Extraction** (`src/securag/retrieval/query_opt.py`):
  - Deterministic regex extraction of `in_kev` (e.g. "exploited in the wild", "in kev"), `year` (e.g. "from 2024"), and `severity` ("critical severity flaws").
- **LLM Query Expansion** (`src/securag/retrieval/query_opt.py`):
  - Uses `gemini-flash-lite-latest` to generate 3 focused query variations targeting security aliases, CWE/CAPEC terminology, and exploitation mechanisms.
- **HyDE Passage Generation** (`src/securag/retrieval/query_opt.py`):
  - Generates concise hypothetical advisory passages to enrich dense vector search.
- **Evaluation & Acceptance** (`tests/test_query_opt.py`):
  - Verified on dev set subset:
    - Baseline Hybrid Recall@10: 0.400
    - With Query Expansion: 0.600 (+50% relative gain)
    - With HyDE: **1.000** (100% recall on dev subset)
  - Acceptance run: `pytest tests/test_query_opt.py` **4 passed in 175.06s**.

### Step 7: Graph Retrieval
- **Entity Linking** (`src/securag/graph/retrieve.py`):
  - Regex patterns for `CVE-YYYY-NNNN`, `CWE-NNN`, `CAPEC-NNN`, `TNNNN[.NNN]`, `TA-NNNN`.
  - Phrase and name matching loaded from Neo4j against Technique and CWE catalog names (e.g. "Remote Services" -> `T1021`, "Cross-site Scripting" -> `CWE-79`).
- **Fixed Cypher Templates**:
  - `trace_cve_attack_chain`: Traverses `(c:CVE)-[:HAS_WEAKNESS]->(w:CWE)-[:RELATED_ATTACK_PATTERN]->(p:CAPEC)-[:RELATED_TECHNIQUE]->(t:Technique)-[:IN_TACTIC]->(ta:Tactic)`.
  - `get_technique_mitigations`: Traverses `(m:Mitigation)-[:MITIGATES]->(t:Technique)`.
  - `get_cwe_hierarchy`: Traverses `(w:CWE)-[:CHILD_OF*1..3]->(parent:CWE)`.
  - `get_kev_exploited_cves`: Traverses `(:CVE {in_kev: true})-[:HAS_WEAKNESS]->(:CWE)`.
- **Bounded $k$-Hop Neighborhood Expansion**:
  - Dynamically traverses $1..k$ hops bounded strictly to $k \le 3$ with mandatory `LIMIT`.
  - Extracts path node dictionaries, relationship types, and attached descriptive chunk texts from SQLite docstore.
- **Static Cypher Safety Verification**:
  - Scanned all Cypher queries in `retrieve.py`; verified 100% contain explicit `LIMIT` clauses and 0 unbounded traversals exist.
- **Acceptance Verification** (`tests/test_graph_retrieval.py`):
  - Multi-hop dev question `q011` (`CVE-2024-22334`) returns exact gold chain `['CVE-2024-22334', 'CWE-732', 'CAPEC-1', 'T1574.010']`.
  - Acceptance run: `pytest tests/test_graph_retrieval.py` **5 passed in 1.62s**.

### Step 8: Rerankers
- **GraphER Topological Reranker** (`src/securag/retrieval/graph_rerank.py`):
  - Implemented from arXiv:2603.24925 (Miao et al., Oracle AI) since no public repository exists.
  - Relation key graph: Extracts structured keys (CWE IDs, ATT&CK Technique IDs, CAPEC IDs, Product keys) from candidate metadata. Connects candidates sharing relation keys into an in-memory query-time candidate graph.
  - Graph Cohesive Smoothing: Iteratively updates scores:
    $$s_i^{(t+1)} = \alpha \cdot s_i^{(0)} + (1 - \alpha) \cdot \frac{1}{|N(i)|} \sum_{j \in N(i)} s_j^{(t)}$$
    (default $\alpha = 0.7$, 2 iterations).
  - **Simplifications from the paper (documented per spec)**:
    1. *Graph Structure*: The paper considers heterogeneous edge weights and learned relation projections. Our implementation uses unweighted undirected edges based on common relation key intersection, keeping query latency under 1ms.
    2. *Propagation*: We implement cohesive neighbor mean smoothing across candidate subgraphs rather than full random-walk-with-restart matrix inversion.
    3. *Relation Keys*: Keys are extracted directly from pre-parsed normalized metadata dictionaries rather than executing runtime entity recognition over raw text.
- **Neural Cross-Encoder** (`src/securag/retrieval/rerank.py`):
  - Uses `BAAI/bge-reranker-v2-m3` on CUDA.
  - Pairs user query with candidate text, predicts cross-attention relevance scores, and re-ranks top candidates.
- **Ablation & Toggle Verification**:
  - Independent toggles verified for `use_graph_rerank` and `use_cross_encoder`.
  - Synthetic test verifies low-scoring candidate `c3` (0.20) connected to high-scoring candidates `c1` (0.90) and `c2` (0.85) is boosted to 0.4531 and overtakes isolated candidate `c4` (0.4500).
  - Cross-encoder scores relevant Log4j passage (0.0840) vs irrelevant cookie recipe (0.0000).
  - Acceptance run: `pytest tests/test_rerank.py` **3 passed in 27.67s**.

### Step 9: Agent State and Nodes
- **Agent State Schema** (`src/securag/agent/state.py`):
  - TypedDict schema per Section 6 (`question`, `route`, `sub_questions`, `queries_tried`, `rewrite_round`, `candidates`, `graph_paths`, `graded`, `verdict`, `context`, `answer`, `citations`, `reflection`, `config`, `metrics`).
- **LangGraph Nodes** (`src/securag/agent/nodes.py`):
  - `route_query`: Fast LLM router (`gemini-flash-lite-latest`) categorizing queries into `simple`, `multi_hop`, or `out_of_kb`.
  - `retrieve_hybrid`: Invokes hybrid sparse-dense retriever with active flags.
  - `retrieve_graph`: Invokes Neo4j multi-hop path traversals and k-hop neighborhood expansion.
  - `rerank`: Applies GraphER topological smoothing followed by CrossEncoder neural rerank.
  - `grade_documents`: Evaluates candidate score distributions to assign `correct`, `ambiguous`, or `incorrect` verdicts.
  - `refine_context`: Selects top candidates and formats verified knowledge graph paths into context.
  - `rewrite_query`: Reformulates query and applies novelty cosine guard ($\ge 0.90$) to prevent redundant loops.
  - `web_fallback`: Returns standard out-of-KB fallback response.
  - `generate`: Synthesizes final answer with bracketed citations.
  - `reflect`: Evaluates faithfulness and unsupported claim verification.
- **StateGraph Assembly** (`src/securag/agent/graph.py`):
  - Built with LangGraph `StateGraph`, conditional routing edges (`route_decision`, `grade_decision`), and memory checkpointer (`MemorySaver`).
- **Acceptance Verification** (`tests/test_agent_routes.py`):
  - Single-fact question routes `simple`.
  - Relational question routes `multi_hop`.
  - Out-of-domain question routes `out_of_kb` and completes end-to-end with fallback response.
  - Unanswerable request terminates strictly within `max_rewrite_rounds` (2 rounds executed).
  - Acceptance run: `pytest tests/test_agent_routes.py` **5 passed in 84.73s**.






