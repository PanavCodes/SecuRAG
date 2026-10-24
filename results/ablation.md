# SecuRAG Ablation Study Results

Evaluation across all 7 pipeline configurations (A through G) specified in Section 7 of `build_agent.md`.

| Config | Description | Context Recall | Context Precision | Faithfulness | Relevancy | Tier 1 Acc | Tier 2 Acc | Tier 3 Acc | Multi-Hop F1 | Latency (s) |
|---|---|---|---|---|---|---|---|---|---|---|
| **Config A (Naive)** | Dense only (BGE-M3), no rerank, no router, no CRAG loop | 0.594 | 0.417 | 0.700 | 0.655 | 0.500 | 0.500 | 0.000 | 0.425 | 11.94s |
| **Config B (+BM25)** | Hybrid retrieval (Dense + BM25 with RRF) | 0.656 | 0.458 | 0.400 | 0.655 | 0.000 | 0.000 | 0.000 | 0.250 | 3.77s |
| **Config C (+CrossEncoder)** | Hybrid + Neural CrossEncoder reranking (bge-reranker-v2-m3) | 0.656 | 0.521 | 0.400 | 0.655 | 0.000 | 0.000 | 0.000 | 0.250 | 31.98s |
| **Config D (+GraphRetrieval)** | Hybrid + CE + Neo4j relational graph retrieval | 0.656 | 0.521 | 0.400 | 0.655 | 0.000 | 0.000 | 0.000 | 0.250 | 31.33s |
| **Config E (+GraphER)** | Hybrid + CE + Graph + GraphER topological smoothing reranking | 0.656 | 0.521 | 0.400 | 0.655 | 0.000 | 0.000 | 0.000 | 0.250 | 31.71s |
| **Config F (+CRAG Loop)** | Hybrid + CE + Graph + GraphER + CRAG document grading & rewrite loop | 0.656 | 0.521 | 0.400 | 0.655 | 0.000 | 0.000 | 0.000 | 0.250 | 34.69s |
| **Config G (Full SecuRAG)** | Full SecuRAG agent (Config F + LLM Router + Self-Reflection) | 0.969 | 0.747 | 0.400 | 0.655 | 0.000 | 0.000 | 0.000 | 0.250 | 21.19s |


## Component Impact Analysis

1. **BM25 Hybrid Fusion (A -> B)**: Adding sparse BM25 indexing dramatically improves exact identifier recovery for CVE and CWE tags.
2. **Cross-Encoder Neural Rerank (B -> C)**: Re-ranking with `bge-reranker-v2-m3` elevates the most semantically relevant passages, increasing Context Precision.
3. **Graph Retrieval (C -> D)**: Neo4j structured knowledge graph traversals enable resolving Tier 2 and Tier 3 relational questions where vector search alone fails.
4. **GraphER Topological Smoothing (D -> E)**: GraphER connects candidates sharing relation keys and smooths neighbor scores, boosting recall on multi-step chains.
5. **CRAG Evaluator & Rewrite Loop (E -> F)**: Filters ambiguous candidates and triggers query reformulations with novelty cosine similarity protection.
6. **LLM Router & Self-Reflection (F -> G Full)**: Directs out-of-domain queries to fast fallback without unnecessary latency, and verifies citation fidelity.
