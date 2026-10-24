"""Neo4j graph schema: constraints and indexes for SecuRAG."""

import logging
from typing import Any
from neo4j import Driver

from securag.clients import get_neo4j_driver

logger = logging.getLogger(__name__)

CONSTRAINTS = [
    ("cve_id", "CREATE CONSTRAINT cve_id IF NOT EXISTS FOR (n:CVE) REQUIRE n.id IS UNIQUE"),
    ("cwe_id", "CREATE CONSTRAINT cwe_id IF NOT EXISTS FOR (n:CWE) REQUIRE n.id IS UNIQUE"),
    ("capec_id", "CREATE CONSTRAINT capec_id IF NOT EXISTS FOR (n:CAPEC) REQUIRE n.id IS UNIQUE"),
    ("tech_id", "CREATE CONSTRAINT tech_id IF NOT EXISTS FOR (n:Technique) REQUIRE n.id IS UNIQUE"),
    ("tactic_id", "CREATE CONSTRAINT tactic_id IF NOT EXISTS FOR (n:Tactic) REQUIRE n.id IS UNIQUE"),
    ("mit_id", "CREATE CONSTRAINT mit_id IF NOT EXISTS FOR (n:Mitigation) REQUIRE n.id IS UNIQUE"),
    ("product_key", "CREATE CONSTRAINT product_key IF NOT EXISTS FOR (n:Product) REQUIRE n.key IS UNIQUE"),
    ("advisory_id", "CREATE CONSTRAINT advisory_id IF NOT EXISTS FOR (n:Advisory) REQUIRE n.id IS UNIQUE"),
    ("chunk_id", "CREATE CONSTRAINT chunk_id IF NOT EXISTS FOR (n:Chunk) REQUIRE n.chunk_id IS UNIQUE"),
]

INDEXES = [
    ("cve_published", "CREATE INDEX cve_published IF NOT EXISTS FOR (n:CVE) ON (n.published)"),
    ("cve_kev", "CREATE INDEX cve_kev IF NOT EXISTS FOR (n:CVE) ON (n.in_kev)"),
]


def create_schema(driver: Driver | None = None) -> dict[str, Any]:
    """Execute all idempotent schema constraints and indexes on Neo4j."""
    d = driver or get_neo4j_driver()
    created_constraints: list[str] = []
    created_indexes: list[str] = []

    with d.session() as session:
        for name, query in CONSTRAINTS:
            logger.info("Applying constraint: %s", name)
            session.run(query)
            created_constraints.append(name)

        for name, query in INDEXES:
            logger.info("Applying index: %s", name)
            session.run(query)
            created_indexes.append(name)

    logger.info("Created %d constraints and %d indexes.", len(created_constraints), len(created_indexes))
    return {
        "constraints": created_constraints,
        "indexes": created_indexes,
    }


def verify_schema(driver: Driver | None = None) -> dict[str, list[str]]:
    """Query Neo4j system metadata to verify active constraints and indexes."""
    d = driver or get_neo4j_driver()
    with d.session() as session:
        c_res = session.run("SHOW CONSTRAINTS YIELD name").data()
        constraints = [r["name"] for r in c_res]

        i_res = session.run("SHOW INDEXES YIELD name").data()
        indexes = [r["name"] for r in i_res]

    return {
        "constraints": constraints,
        "indexes": indexes,
    }


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    create_schema()
    meta = verify_schema()
    print("Active Constraints:", meta["constraints"])
    print("Active Indexes:", meta["indexes"])
