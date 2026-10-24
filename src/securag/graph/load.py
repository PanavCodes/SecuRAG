"""Batch graph loader: populates Neo4j from data/processed/*.jsonl using idempotent MERGE."""

import json
import logging
import time
from pathlib import Path
from typing import Any, Generator, Iterable
from neo4j import Driver

from securag.clients import get_neo4j_driver
from securag.graph.schema import create_schema

logger = logging.getLogger(__name__)


def batch_iterate(items: Iterable[Any], size: int = 1000) -> Generator[list[Any], None, None]:
    """Yield items in chunks of `size`."""
    batch: list[Any] = []
    for item in items:
        batch.append(item)
        if len(batch) >= size:
            yield batch
            batch = []
    if batch:
        yield batch


def load_attack_data(session: Any, attack_path: str = "data/processed/attack.jsonl", batch_size: int = 1000) -> dict[str, int]:
    """Load Tactics, Techniques, Mitigations and their relationships."""
    p = Path(attack_path)
    if not p.exists():
        raise FileNotFoundError(f"{attack_path} not found")

    tactics: list[dict[str, Any]] = []
    techniques: list[dict[str, Any]] = []
    mitigations: list[dict[str, Any]] = []
    in_tactic_rels: list[dict[str, str]] = []
    subtech_rels: list[dict[str, str]] = []
    mitigates_rels: list[dict[str, str]] = []

    with p.open("r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            r = json.loads(line)
            rtype = r.get("type")
            if rtype == "tactic":
                tactics.append(r)
            elif rtype == "technique":
                techniques.append(r)
                tech_id = r["id"]
                for tid in r.get("tactic_ids", []):
                    in_tactic_rels.append({"tech_id": tech_id, "tactic_id": tid})
                if r.get("subtechnique_of"):
                    subtech_rels.append({"child_id": tech_id, "parent_id": r["subtechnique_of"]})
            elif rtype == "mitigation":
                mitigations.append(r)
                mit_id = r["id"]
                for tid in r.get("mitigates_techniques", []):
                    mitigates_rels.append({"mit_id": mit_id, "tech_id": tid})

    # Load Tactic nodes
    tactic_query = """
    UNWIND $batch AS row
    MERGE (t:Tactic {id: row.id})
    SET t.name = row.name,
        t.shortname = row.shortname,
        t.description = row.description
    """
    for batch in batch_iterate(tactics, batch_size):
        session.run(tactic_query, {"batch": batch})

    # Load Technique nodes
    tech_query = """
    UNWIND $batch AS row
    MERGE (t:Technique {id: row.id})
    SET t.name = row.name,
        t.description = row.description,
        t.is_subtechnique = row.is_subtechnique,
        t.platforms = row.platforms
    """
    for batch in batch_iterate(techniques, batch_size):
        session.run(tech_query, {"batch": batch})

    # Load Mitigation nodes
    mit_query = """
    UNWIND $batch AS row
    MERGE (m:Mitigation {id: row.id})
    SET m.name = row.name,
        m.description = row.description
    """
    for batch in batch_iterate(mitigations, batch_size):
        session.run(mit_query, {"batch": batch})

    # Relationships: IN_TACTIC
    in_tactic_query = """
    UNWIND $batch AS row
    MATCH (t:Technique {id: row.tech_id})
    MATCH (ta:Tactic {id: row.tactic_id})
    MERGE (t)-[:IN_TACTIC]->(ta)
    """
    for batch in batch_iterate(in_tactic_rels, batch_size):
        session.run(in_tactic_query, {"batch": batch})

    # Relationships: SUBTECHNIQUE_OF
    subtech_query = """
    UNWIND $batch AS row
    MATCH (c:Technique {id: row.child_id})
    MATCH (p:Technique {id: row.parent_id})
    MERGE (c)-[:SUBTECHNIQUE_OF]->(p)
    """
    for batch in batch_iterate(subtech_rels, batch_size):
        session.run(subtech_query, {"batch": batch})

    # Relationships: MITIGATES
    mitigates_query = """
    UNWIND $batch AS row
    MATCH (m:Mitigation {id: row.mit_id})
    MATCH (t:Technique {id: row.tech_id})
    MERGE (m)-[:MITIGATES]->(t)
    """
    for batch in batch_iterate(mitigates_rels, batch_size):
        session.run(mitigates_query, {"batch": batch})

    logger.info("Loaded ATT&CK: %d tactics, %d techniques, %d mitigations", len(tactics), len(techniques), len(mitigations))
    return {
        "tactics": len(tactics),
        "techniques": len(techniques),
        "mitigations": len(mitigations),
    }


def load_cwe_data(session: Any, cwe_path: str = "data/processed/cwe.jsonl", batch_size: int = 1000) -> dict[str, int]:
    """Load CWE nodes, CHILD_OF hierarchy, and RELATED_ATTACK_PATTERN links."""
    p = Path(cwe_path)
    if not p.exists():
        raise FileNotFoundError(f"{cwe_path} not found")

    cwes: list[dict[str, Any]] = []
    child_of_rels: list[dict[str, str]] = []
    cwe_capec_rels: list[dict[str, str]] = []

    with p.open("r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            r = json.loads(line)
            cwes.append({
                "id": r["id"],
                "name": r.get("name", ""),
                "description": r.get("description", ""),
                "abstraction": r.get("abstraction", ""),
            })
            for parent_id in r.get("child_of", []):
                child_of_rels.append({"child_id": r["id"], "parent_id": parent_id})
            for cap_id in r.get("capec_ids", []):
                cwe_capec_rels.append({"cwe_id": r["id"], "capec_id": cap_id})

    # Load CWE nodes
    cwe_query = """
    UNWIND $batch AS row
    MERGE (w:CWE {id: row.id})
    SET w.name = row.name,
        w.description = row.description,
        w.abstraction = row.abstraction
    """
    for batch in batch_iterate(cwes, batch_size):
        session.run(cwe_query, {"batch": batch})

    # Relationships: CHILD_OF
    child_of_query = """
    UNWIND $batch AS row
    MATCH (c:CWE {id: row.child_id})
    MATCH (p:CWE {id: row.parent_id})
    MERGE (c)-[:CHILD_OF]->(p)
    """
    for batch in batch_iterate(child_of_rels, batch_size):
        session.run(child_of_query, {"batch": batch})

    logger.info("Loaded CWE: %d nodes, %d CHILD_OF rels", len(cwes), len(child_of_rels))
    return {
        "cwes": len(cwes),
        "child_of": len(child_of_rels),
        "cwe_capec_pairs": cwe_capec_rels,
    }


def load_capec_data(session: Any, capec_path: str = "data/processed/capec.jsonl", batch_size: int = 1000) -> dict[str, int]:
    """Load CAPEC nodes, RELATED_TECHNIQUE links, and RELATED_ATTACK_PATTERN links."""
    p = Path(capec_path)
    if not p.exists():
        raise FileNotFoundError(f"{capec_path} not found")

    capecs: list[dict[str, Any]] = []
    tech_rels: list[dict[str, str]] = []
    cwe_rels: list[dict[str, str]] = []

    with p.open("r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            r = json.loads(line)
            capec_id = r["id"]
            capecs.append({
                "id": capec_id,
                "name": r.get("name", ""),
                "description": r.get("description", ""),
                "severity": r.get("severity"),
                "likelihood": r.get("likelihood"),
            })
            for tid in r.get("technique_ids", []):
                tech_rels.append({"capec_id": capec_id, "tech_id": tid})
            for cwe_id in r.get("cwe_ids", []):
                cwe_rels.append({"cwe_id": cwe_id, "capec_id": capec_id})

    # Load CAPEC nodes
    capec_query = """
    UNWIND $batch AS row
    MERGE (p:CAPEC {id: row.id})
    SET p.name = row.name,
        p.description = row.description,
        p.severity = row.severity,
        p.likelihood = row.likelihood
    """
    for batch in batch_iterate(capecs, batch_size):
        session.run(capec_query, {"batch": batch})

    # Relationships: RELATED_TECHNIQUE (CAPEC -> Technique)
    tech_query = """
    UNWIND $batch AS row
    MATCH (p:CAPEC {id: row.capec_id})
    MATCH (t:Technique {id: row.tech_id})
    MERGE (p)-[:RELATED_TECHNIQUE]->(t)
    """
    for batch in batch_iterate(tech_rels, batch_size):
        session.run(tech_query, {"batch": batch})

    logger.info("Loaded CAPEC: %d nodes, %d RELATED_TECHNIQUE rels", len(capecs), len(tech_rels))
    return {
        "capecs": len(capecs),
        "capec_tech": len(tech_rels),
        "capec_cwe_pairs": cwe_rels,
    }


def link_cwe_capec(session: Any, pairs: list[dict[str, str]], batch_size: int = 1000) -> int:
    """Link (CWE)-[:RELATED_ATTACK_PATTERN]->(CAPEC) idempotently."""
    # Deduplicate pairs
    unique_pairs = list({(p["cwe_id"], p["capec_id"]): p for p in pairs}.values())
    query = """
    UNWIND $batch AS row
    MATCH (w:CWE {id: row.cwe_id})
    MATCH (p:CAPEC {id: row.capec_id})
    MERGE (w)-[:RELATED_ATTACK_PATTERN]->(p)
    """
    for batch in batch_iterate(unique_pairs, batch_size):
        session.run(query, {"batch": batch})
    logger.info("Linked %d unique CWE-CAPEC pairs.", len(unique_pairs))
    return len(unique_pairs)


def load_cve_and_products(
    session: Any,
    cve_path: str = "data/processed/cve.jsonl",
    batch_size: int = 1000,
) -> dict[str, int]:
    """Load Products, CVE nodes, and (CVE)-[:HAS_WEAKNESS]->(CWE), (CVE)-[:AFFECTS]->(Product)."""
    p = Path(cve_path)
    if not p.exists():
        raise FileNotFoundError(f"{cve_path} not found")

    cves: list[dict[str, Any]] = []
    products_map: dict[str, dict[str, str]] = {}
    cve_cwe_rels: list[dict[str, str]] = []
    cve_prod_rels: list[dict[str, str]] = []

    with p.open("r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            r = json.loads(line)
            cve_id = r["id"]

            cves.append({
                "id": cve_id,
                "description": r.get("description", ""),
                "published": r.get("published", ""),
                "cvss_score": r.get("cvss_score"),
                "cvss_severity": r.get("cvss_severity"),
                "in_kev": bool(r.get("in_kev", False)),
                "kev_date_added": r.get("kev_date_added"),
                "ssvc_exploitation": r.get("ssvc_exploitation"),
            })

            # CWE relationships
            for cwe_id in r.get("cwe_ids", []):
                cve_cwe_rels.append({"cve_id": cve_id, "cwe_id": cwe_id})

            # Product nodes & relationships
            for prod_key in r.get("affected_products", []):
                if prod_key not in products_map:
                    parts = prod_key.split("::", 1)
                    vendor = parts[0]
                    prod = parts[1] if len(parts) > 1 else ""
                    products_map[prod_key] = {"key": prod_key, "vendor": vendor, "product": prod}
                cve_prod_rels.append({"cve_id": cve_id, "product_key": prod_key})

    # 1. Load Product nodes
    prod_query = """
    UNWIND $batch AS row
    MERGE (p:Product {key: row.key})
    SET p.vendor = row.vendor,
        p.product = row.product
    """
    for batch in batch_iterate(list(products_map.values()), batch_size):
        session.run(prod_query, {"batch": batch})

    # 2. Load CVE nodes
    cve_query = """
    UNWIND $batch AS row
    MERGE (c:CVE {id: row.id})
    SET c.description = row.description,
        c.published = row.published,
        c.cvss_score = row.cvss_score,
        c.cvss_severity = row.cvss_severity,
        c.in_kev = row.in_kev,
        c.kev_date_added = row.kev_date_added,
        c.ssvc_exploitation = row.ssvc_exploitation
    """
    for batch in batch_iterate(cves, batch_size):
        session.run(cve_query, {"batch": batch})

    # 3. Relationships: (CVE)-[:HAS_WEAKNESS]->(CWE)
    cve_cwe_query = """
    UNWIND $batch AS row
    MATCH (c:CVE {id: row.cve_id})
    MATCH (w:CWE {id: row.cwe_id})
    MERGE (c)-[:HAS_WEAKNESS]->(w)
    """
    for batch in batch_iterate(cve_cwe_rels, batch_size):
        session.run(cve_cwe_query, {"batch": batch})

    # 4. Relationships: (CVE)-[:AFFECTS]->(Product)
    cve_prod_query = """
    UNWIND $batch AS row
    MATCH (c:CVE {id: row.cve_id})
    MATCH (p:Product {key: row.product_key})
    MERGE (c)-[:AFFECTS]->(p)
    """
    for batch in batch_iterate(cve_prod_rels, batch_size):
        session.run(cve_prod_query, {"batch": batch})

    logger.info("Loaded CVE: %d nodes, %d products, %d HAS_WEAKNESS rels, %d AFFECTS rels",
                len(cves), len(products_map), len(cve_cwe_rels), len(cve_prod_rels))
    return {
        "cves": len(cves),
        "products": len(products_map),
        "cve_cwe": len(cve_cwe_rels),
        "cve_prod": len(cve_prod_rels),
    }


def get_graph_counts(driver: Driver | None = None) -> dict[str, int]:
    """Return dictionary of current node and relationship counts in Neo4j."""
    d = driver or get_neo4j_driver()
    counts: dict[str, int] = {}
    with d.session() as session:
        for label in ["CVE", "CWE", "CAPEC", "Technique", "Tactic", "Mitigation", "Product"]:
            res = session.run(f"MATCH (n:{label}) RETURN count(n) AS cnt").single()
            counts[label] = res["cnt"] if res else 0

        for rel in ["HAS_WEAKNESS", "RELATED_ATTACK_PATTERN", "RELATED_TECHNIQUE", "IN_TACTIC", "SUBTECHNIQUE_OF", "MITIGATES", "AFFECTS", "CHILD_OF"]:
            res = session.run(f"MATCH ()-[r:{rel}]->() RETURN count(r) AS cnt").single()
            counts[rel] = res["cnt"] if res else 0

    return counts


def load_all(driver: Driver | None = None, batch_size: int = 1000) -> dict[str, int]:
    """Execute complete schema creation and idempotent batch loading across all sources."""
    d = driver or get_neo4j_driver()
    start_time = time.time()

    # Step 3.1: Ensure constraints and indexes exist
    create_schema(d)

    with d.session() as session:
        # 1. ATT&CK
        logger.info("Ingesting ATT&CK data...")
        load_attack_data(session, batch_size=batch_size)

        # 2. CWE
        logger.info("Ingesting CWE data...")
        cwe_info = load_cwe_data(session, batch_size=batch_size)

        # 3. CAPEC
        logger.info("Ingesting CAPEC data...")
        capec_info = load_capec_data(session, batch_size=batch_size)

        # 4. Link CWE <-> CAPEC from both sources
        logger.info("Linking CWE to CAPEC...")
        all_cwe_capec_pairs = cwe_info["cwe_capec_pairs"] + capec_info["capec_cwe_pairs"]
        link_cwe_capec(session, all_cwe_capec_pairs, batch_size=batch_size)

        # 5. CVE & Products
        logger.info("Ingesting CVE and Product data...")
        load_cve_and_products(session, batch_size=batch_size)

    elapsed = time.time() - start_time
    logger.info("Graph ingestion completed in %.2fs", elapsed)

    counts = get_graph_counts(d)
    return counts


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    counts = load_all(batch_size=1000)
    print("\n--- Neo4j Graph Summary ---")
    for k, v in counts.items():
        print(f"  {k:25s}: {v:8d}")
    print("---------------------------\n")
