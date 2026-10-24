# Third-Party Dependencies and Reference Repositories

This document tracks all external reference repositories, packages, and data sources used in SecuRAG in compliance with Section 0 and Section 5 of `docs/build_agent.md`.

> **Rule:** Code from `third_party/` is never imported directly. Implementations in `src/securag/` adapt logic with header attribution comments.

---

## 1. Reference Repositories (`third_party/`)

| Repository | Source URL | Commit Hash | Role in SecuRAG | License |
|---|---|---|---|---|
| `Graph-R1` | https://github.com/LHRLAB/Graph-R1 | `e44dbff72721006f83d32ab9c1adc422d9bff2c0` | Multi-turn retrieval loop structure & reward scoring | MIT |
| `RouteRAG` | https://github.com/YucanGuo/RouteRAG | `244d30d83c2ed289c0fb2ee072ba938ec3f65e3f` | Action space design for text vs graph routing | MIT |
| `CRAG` | https://github.com/HuskyInSalt/CRAG | `de7c2961ae624a1483a138c5798e1f6d0c4fb0e0` | Evaluator logic & decompose-recompose context refinement | Apache-2.0 |
| `langgraph-ai` | https://github.com/piyushagni5/langgraph-ai | `7ed556f75776eb905c1b1dcb0c45c0cb56b53690` | Agentic RAG state skeleton & node patterns | MIT |
| `Corrective-Rag` | https://github.com/Bisma474/Corrective-Rag | `df8b3669160a098346461ca6f0e87dcb8871854b` | CRAG API & evaluator wiring | MIT |
| `self-rag` | https://github.com/AkariAsai/self-rag | `1fcdc420e48f50a7d7ab1ece5494221b93252e99` | Reflection prompt strategies | MIT |
| `neo4j-graphrag-python` | https://github.com/neo4j/neo4j-graphrag-python | `6265f046e1578854d1f2ecaec6e781ffed3f8ede` | Neo4j property graph retrieval & schema utilities | Apache-2.0 |
| `microsoft/graphrag` | https://github.com/microsoft/graphrag | `c600ff80b77b9b62c47d539a3ac9569e95d8949b` | Baseline GraphRAG comparison reference | MIT |
| `ragas` | https://github.com/explodinggradients/ragas | `298b68274234c060deacab3cf5fb52aa3a20e885` | Evaluation harness for faithfulness & precision/recall | Apache-2.0 |
| `GraphER` | arXiv:2603.24925 | *Paper only (no public repo)* | Query-time topological graph smoothing reranker (`src/securag/retrieval/graph_rerank.py`) | Academic Paper |

---

## 2. Public Data Sources (`data/raw/`)

| Source | Provider / URL | License / Terms of Use | Notes |
|---|---|---|---|
| **cvelistV5** | https://github.com/CVEProject/cvelistV5 | CC0-1.0 | Official CVE JSON 5.x records (sparse checkout 2024, 2025) |
| **CISA KEV** | https://github.com/cisagov/kev-data | CC0-1.0 | Known Exploited Vulnerabilities catalog |
| **MITRE ATT&CK** | https://github.com/mitre-attack/attack-stix-data | [MITRE ATT&CK Terms of Use](https://attack.mitre.org/resources/terms-of-use/) | Enterprise attack STIX 2.1 |
| **MITRE CAPEC** | https://github.com/mitre/cti | [CAPEC Terms of Use](https://capec.mitre.org/about/termsofuse.html) | Common Attack Pattern Enumeration and Classification STIX |
| **MITRE CWE** | https://cwe.mitre.org | [CWE Terms of Use](https://cwe.mitre.org/about/termsofuse.html) | Common Weakness Enumeration XML catalog |

---

## 3. Core Python Libraries

- `langgraph`: BSD-3-Clause
- `neo4j`: Apache-2.0
- `neo4j-graphrag`: Apache-2.0
- `pinecone`: Apache-2.0
- `sentence-transformers`: Apache-2.0
- `rank-bm25`: Apache-2.0
- `ragas`: Apache-2.0
- `fastapi`: MIT
- `streamlit`: Apache-2.0
- `torch`: Modified BSD
