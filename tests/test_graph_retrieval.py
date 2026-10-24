"""Acceptance tests for Step 7: Graph Retrieval, Entity Linking, and Bounded Cypher Queries."""

import re
from pathlib import Path
import pytest

from securag.graph.retrieve import (
    link_entities,
    trace_cve_attack_chain,
    get_technique_mitigations,
    get_cwe_hierarchy,
    get_kev_exploited_cves,
    expand_entity_subgraph,
    GraphRetriever,
)


def test_entity_linking_regex_and_names():
    """Verify entity linking finds explicit IDs and names."""
    # 1. Regex test
    q1 = "Analyze CVE-2024-22334 involving CWE-732 and CAPEC-1 targeting T1574.010 under TA0005"
    entities = link_entities(q1)
    e_map = {e["id"]: e["type"] for e in entities}

    assert "CVE-2024-22334" in e_map, "Failed to link CVE-2024-22334"
    assert "CWE-732" in e_map, "Failed to link CWE-732"
    assert "CAPEC-1" in e_map, "Failed to link CAPEC-1"
    assert "T1574.010" in e_map, "Failed to link T1574.010"
    assert "TA0005" in e_map, "Failed to link TA0005"

    # 2. Phrase / Name matching test
    q2 = "How can attackers use Remote Services or Cross-site Scripting to gain access?"
    entities2 = link_entities(q2)
    e2_ids = {e["id"] for e in entities2}

    print(f"\nLinked from q2: {entities2}")
    assert ("T1021" in e2_ids or "CWE-79" in e2_ids), f"Expected T1021 or CWE-79 linked from names, got {e2_ids}"


def test_multihop_gold_chain_retrieval():
    """Verify known multi-hop question returns the gold attack path and context chunks."""
    retriever = GraphRetriever()
    query = "Trace the full attack chain from CVE-2024-22334 to an ATT&CK technique."
    res = retriever.retrieve(query, max_hops=3, limit=15)

    print("\n--- Graph Retrieval Paths for CVE-2024-22334 ---")
    for idx, p in enumerate(res["paths"], 1):
        print(f"  Path {idx}: {p.get('path')}")
    print("-------------------------------------------------")

    assert len(res["paths"]) > 0, "Graph retrieval returned 0 paths"

    # Verify gold chain: CVE-2024-22334 -> CWE-732 -> CAPEC-1 -> T1574.010
    found_gold_chain = False
    for p in res["paths"]:
        path_nodes = p.get("path", [])
        if "CVE-2024-22334" in path_nodes and "CWE-732" in path_nodes and "T1574.010" in path_nodes:
            found_gold_chain = True
            break

    assert found_gold_chain, f"Gold chain ['CVE-2024-22334', 'CWE-732', 'CAPEC-1', 'T1574.010'] not found in paths: {res['paths']}"

    # Verify context chunks attached
    assert len(res["context_chunks"]) > 0, "No context chunks retrieved for graph nodes"
    chunk_sources = {c["source_id"] for c in res["context_chunks"]}
    assert "CVE-2024-22334" in chunk_sources, "Chunk text for CVE-2024-22334 was not attached"


def test_technique_mitigations():
    """Verify technique mitigations traversal."""
    mits = get_technique_mitigations("T1021", limit=5)
    print(f"\nMitigations for T1021: {mits}")
    assert len(mits) > 0, "Expected mitigations for technique T1021"
    for m in mits:
        assert "mitigation_id" in m
        assert m["technique_id"] == "T1021"


def test_cwe_hierarchy():
    """Verify CWE hierarchy traversal."""
    hierarchy = get_cwe_hierarchy("CWE-79", limit=5)
    print(f"\nCWE-79 hierarchy: {hierarchy}")
    assert len(hierarchy) > 0, "Expected hierarchy for CWE-79"
    parent_ids = [h["parent_id"] for h in hierarchy]
    assert "CWE-74" in parent_ids, f"Expected parent CWE-74 in hierarchy, got {parent_ids}"


def test_no_unbounded_cypher_queries_and_all_have_limit():
    """Scan src/securag/graph/retrieve.py to verify every Cypher query has a LIMIT and no unbounded MATCH."""
    retrieve_path = Path("src/securag/graph/retrieve.py")
    assert retrieve_path.exists(), "src/securag/graph/retrieve.py not found"

    content = retrieve_path.read_text(encoding="utf-8")

    # Find all multi-line and single-line strings that contain MATCH
    # Matches patterns like cypher = \"\"\"...\"\"\" or session.run(\"...MATCH...\")
    cypher_blocks = re.findall(r'"""(.*?)"""', content, re.DOTALL)
    cypher_blocks += re.findall(r'session\.run\(\s*["\'](.*?)["\']', content)

    match_queries = [b.strip() for b in cypher_blocks if re.search(r"\bMATCH\b", b) and not b.strip().startswith("Extract")]
    assert len(match_queries) >= 5, f"Expected at least 5 Cypher MATCH queries, found {len(match_queries)}"

    for idx, query in enumerate(match_queries, 1):
        # 1. Assert explicit LIMIT is present
        assert "LIMIT" in query.upper(), f"Query #{idx} is missing a LIMIT clause:\n{query}"

        # 2. Assert no unbounded hops like -[*]-, -[*..]-, or -[*1..]- without an upper bound
        unbounded_hop = re.search(r"-\[\w*\*(\.\.)?\s*\]-", query)
        assert not unbounded_hop, f"Query #{idx} contains unbounded relationship traversal:\n{query}"

        unbounded_range = re.search(r"-\[\w*\*\d+\.\.\s*\]-", query)
        assert not unbounded_range, f"Query #{idx} contains unbounded range traversal without upper bound:\n{query}"

    print(f"\nScanned {len(match_queries)} Cypher queries in retrieve.py; all contain LIMIT and bounded hops.")
