"""Acceptance tests for Step 4: Chunking, Docstore, Neo4j DESCRIBES edges, and Pinecone vector index."""

import pytest
from securag.clients import get_neo4j_driver, close_neo4j_driver
from securag.ingest.chunk import Docstore
from securag.ingest.embed_index import get_pinecone_stats, query_pinecone


def test_docstore_and_neo4j_chunks():
    """Verify SQLite docstore and Neo4j :Chunk nodes match in count and have DESCRIBES edges."""
    ds = Docstore()
    counts = ds.get_namespace_counts()

    assert "cve" in counts, "Docstore missing 'cve' namespace"
    assert "attack" in counts, "Docstore missing 'attack' namespace"
    assert counts["cve"] == 20000, f"Expected 20000 CVE chunks, got {counts['cve']}"
    assert counts["attack"] > 0, f"Expected attack chunks > 0, got {counts['attack']}"

    total_docstore_chunks = sum(counts.values())

    # Verify Neo4j Chunk nodes and DESCRIBES edges
    driver = get_neo4j_driver()
    with driver.session() as session:
        r = session.run("MATCH (ch:Chunk)-[:DESCRIBES]->(t) RETURN count(ch) AS cnt").single()
        neo4j_chunk_count = r["cnt"] if r else 0

    assert neo4j_chunk_count == total_docstore_chunks, (
        f"Neo4j DESCRIBES count ({neo4j_chunk_count}) does not match docstore count ({total_docstore_chunks})"
    )


def test_pinecone_namespace_counts():
    """Verify Pinecone namespace vector counts equal docstore counts."""
    ds = Docstore()
    docstore_counts = ds.get_namespace_counts()

    stats = get_pinecone_stats()
    namespaces = stats.get("namespaces", {})

    for ns, doc_cnt in docstore_counts.items():
        assert ns in namespaces, f"Namespace '{ns}' not found in Pinecone stats: {namespaces}"
        pinecone_cnt = namespaces[ns].get("vector_count", 0)
        assert pinecone_cnt == doc_cnt, (
            f"Pinecone vector count for namespace '{ns}' ({pinecone_cnt}) does not match docstore ({doc_cnt})"
        )


def test_pinecone_semantic_query_top5():
    """Verify a test query for 'cross-site scripting' against attack namespace returns CWE-79 in top 5."""
    matches = query_pinecone("cross-site scripting", namespace="attack", top_k=5)
    assert len(matches) > 0, "Query returned 0 matches from Pinecone"

    source_ids = [m["metadata"].get("source_id") for m in matches]
    titles = [m["metadata"].get("title", "") for m in matches]

    print("\n--- Semantic Search Top 5 for 'cross-site scripting' ---")
    for idx, m in enumerate(matches, 1):
        print(f"  {idx}. [{m['metadata'].get('source_id')}] (score: {m['score']:.4f}) - {m['metadata'].get('title')}")
    print("---------------------------------------------------------")

    assert "CWE-79" in source_ids, f"CWE-79 was not found in top 5 matches: {source_ids}"
