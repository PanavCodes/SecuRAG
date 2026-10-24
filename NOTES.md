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
