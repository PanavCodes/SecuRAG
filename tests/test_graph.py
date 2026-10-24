"""Acceptance tests for Step 3: Neo4j Graph schema, idempotent batch loading, and 5-hop traversal."""

import pytest
from securag.clients import get_neo4j_driver, close_neo4j_driver
from securag.graph.schema import verify_schema
from securag.graph.load import load_all, get_graph_counts


@pytest.fixture(scope="module")
def neo4j_driver():
    driver = get_neo4j_driver()
    yield driver
    close_neo4j_driver()


def test_schema_constraints_and_indexes(neo4j_driver):
    """Verify all constraints and indexes required by Section 3.1 are active."""
    meta = verify_schema(neo4j_driver)
    expected_constraints = {
        "cve_id",
        "cwe_id",
        "capec_id",
        "tech_id",
        "tactic_id",
        "mit_id",
        "product_key",
        "advisory_id",
        "chunk_id",
    }
    actual_constraints = set(meta["constraints"])
    for ec in expected_constraints:
        assert ec in actual_constraints, f"Constraint '{ec}' is not active in Neo4j"

    expected_indexes = {"cve_published", "cve_kev"}
    actual_indexes = set(meta["indexes"])
    for ei in expected_indexes:
        assert ei in actual_indexes, f"Index '{ei}' is not active in Neo4j"


def test_five_hop_path_traversal(neo4j_driver):
    """Verify that the full 5-hop attack path returns >= 1 row.

    Cypher: (CVE)-[:HAS_WEAKNESS]->(CWE)-[:RELATED_ATTACK_PATTERN]->(CAPEC)-[:RELATED_TECHNIQUE]->(Technique)-[:IN_TACTIC]->(Tactic)
    """
    query = """
    MATCH (c:CVE)-[:HAS_WEAKNESS]->(w:CWE)-[:RELATED_ATTACK_PATTERN]->(p:CAPEC)-[:RELATED_TECHNIQUE]->(t:Technique)-[:IN_TACTIC]->(ta:Tactic)
    RETURN c.id AS cve, w.id AS cwe, p.id AS capec, t.id AS technique, ta.name AS tactic
    LIMIT 5
    """
    with neo4j_driver.session() as session:
        results = session.run(query).data()

    assert len(results) >= 1, "5-hop traversal must return at least 1 row"
    print("\n--- 5-Hop Attack Path Acceptance Samples ---")
    for r in results:
        print(f"  {r['cve']} -> {r['cwe']} -> {r['capec']} -> {r['technique']} -> {r['tactic']}")
    print("--------------------------------------------")


def test_loader_idempotency(neo4j_driver):
    """Verify that running the batch loader twice leaves node counts unchanged."""
    counts_before = get_graph_counts(neo4j_driver)
    assert counts_before["CVE"] == 20000, f"Expected 20,000 CVEs, found {counts_before['CVE']}"
    assert counts_before["CWE"] > 0, "CWE count must be > 0"
    assert counts_before["CAPEC"] > 0, "CAPEC count must be > 0"
    assert counts_before["Technique"] > 0, "Technique count must be > 0"

    # Re-run loader to test idempotency
    counts_after = load_all(neo4j_driver, batch_size=2000)

    # Assert node counts are identical
    for label in ["CVE", "CWE", "CAPEC", "Technique", "Tactic", "Mitigation", "Product"]:
        assert counts_after[label] == counts_before[label], (
            f"Node count for label {label} changed on second run: "
            f"before={counts_before[label]}, after={counts_after[label]}"
        )

    print("\n--- Idempotency Verified: Node Counts Unchanged ---")
    for label in ["CVE", "CWE", "CAPEC", "Technique", "Tactic", "Mitigation", "Product"]:
        print(f"  {label:12s}: {counts_after[label]:6d}")
    print("---------------------------------------------------")
