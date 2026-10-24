"""Graph retrieval: entity linking, fixed Cypher templates, and bounded k-hop traversal."""

import logging
import re
from typing import Any
from neo4j import Driver

from securag.clients import get_neo4j_driver
from securag.ingest.chunk import Docstore

logger = logging.getLogger(__name__)

# Regex patterns for cybersecurity entity linking
ENTITY_REGEXES = {
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE),
    "cwe": re.compile(r"\bCWE-\d+\b", re.IGNORECASE),
    "capec": re.compile(r"\bCAPEC-\d+\b", re.IGNORECASE),
    "technique": re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE),
    "tactic": re.compile(r"\bTA\d{4}\b", re.IGNORECASE),
}

# Cache for known technique and CWE names for fuzzy/exact phrase entity linking
_NAME_CACHE: dict[str, dict[str, str]] = {}


def _load_name_cache(driver: Driver) -> dict[str, dict[str, str]]:
    """Load common technique and CWE names from Neo4j for entity linking."""
    global _NAME_CACHE
    if _NAME_CACHE:
        return _NAME_CACHE

    technique_names: dict[str, str] = {}
    cwe_names: dict[str, str] = {}

    try:
        with driver.session() as session:
            # Query Techniques with LIMIT
            t_res = session.run("MATCH (t:Technique) RETURN t.id AS id, t.name AS name LIMIT 1000").data()
            for row in t_res:
                if row.get("name") and row.get("id"):
                    technique_names[row["name"].strip().lower()] = row["id"]

            # Query CWEs with LIMIT
            w_res = session.run("MATCH (w:CWE) RETURN w.id AS id, w.name AS name LIMIT 1000").data()
            for row in w_res:
                if row.get("name") and row.get("id"):
                    cwe_names[row["name"].strip().lower()] = row["id"]

        _NAME_CACHE = {
            "technique": technique_names,
            "cwe": cwe_names,
        }
    except Exception as e:
        logger.warning("Could not load graph name cache: %s", e)
        _NAME_CACHE = {"technique": {}, "cwe": {}}

    return _NAME_CACHE


def link_entities(query: str, driver: Driver | None = None) -> list[dict[str, str]]:
    """Extract and link security entity IDs from query text via regex and name matching."""
    linked: list[dict[str, str]] = []
    seen_ids: set[str] = set()

    # 1. Regex ID extraction (CVE, CWE, CAPEC, Technique, Tactic)
    for etype, pattern in ENTITY_REGEXES.items():
        matches = pattern.findall(query)
        for m in matches:
            norm_id = m.upper().strip()
            if norm_id not in seen_ids:
                seen_ids.add(norm_id)
                linked.append({
                    "id": norm_id,
                    "type": etype,
                    "match_method": "regex",
                })

    # 2. Phrase matching against known Technique and CWE names
    d = driver or get_neo4j_driver()
    name_cache = _load_name_cache(d)
    query_lower = query.lower()

    # Match Techniques (e.g. "Remote Services", "Pass the Hash")
    for name, tid in name_cache.get("technique", {}).items():
        if len(name) >= 5 and name in query_lower and tid not in seen_ids:
            seen_ids.add(tid)
            linked.append({
                "id": tid,
                "type": "technique",
                "match_method": "name_match",
                "matched_name": name,
            })

    # Match CWEs (e.g. "Cross-site Scripting", "SQL Injection")
    for name, wid in name_cache.get("cwe", {}).items():
        if len(name) >= 6 and name in query_lower and wid not in seen_ids:
            seen_ids.add(wid)
            linked.append({
                "id": wid,
                "type": "cwe",
                "match_method": "name_match",
                "matched_name": name,
            })

    return linked


# ---------------------------------------------------------
# Fixed Cypher Templates for Common Multi-Hop Inquiries
# All queries MUST contain an explicit LIMIT
# ---------------------------------------------------------

def trace_cve_attack_chain(cve_id: str, driver: Driver | None = None, limit: int = 10) -> list[dict[str, Any]]:
    """Traverse CVE -> CWE -> CAPEC -> Technique -> Tactic chain."""
    d = driver or get_neo4j_driver()
    cypher = """
    MATCH path = (c:CVE {id: $cve_id})-[:HAS_WEAKNESS]->(w:CWE)-[:RELATED_ATTACK_PATTERN]->(p:CAPEC)-[:RELATED_TECHNIQUE]->(t:Technique)
    OPTIONAL MATCH (t)-[:IN_TACTIC]->(ta:Tactic)
    RETURN c.id AS cve_id,
           w.id AS cwe_id, w.name AS cwe_name,
           p.id AS capec_id, p.name AS capec_name,
           t.id AS technique_id, t.name AS technique_name,
           ta.id AS tactic_id, ta.name AS tactic_name,
           [n IN nodes(path) | n.id] + CASE WHEN ta IS NOT NULL THEN [ta.name] ELSE [] END AS path_ids
    LIMIT $limit
    """
    with d.session() as session:
        return session.run(cypher, cve_id=cve_id, limit=limit).data()


def get_technique_mitigations(technique_id: str, driver: Driver | None = None, limit: int = 10) -> list[dict[str, Any]]:
    """Traverse Technique <- MITIGATES - Mitigation."""
    d = driver or get_neo4j_driver()
    cypher = """
    MATCH (m:Mitigation)-[:MITIGATES]->(t:Technique {id: $tech_id})
    RETURN m.id AS mitigation_id, m.name AS mitigation_name, m.description AS description, t.id AS technique_id
    LIMIT $limit
    """
    with d.session() as session:
        return session.run(cypher, tech_id=technique_id, limit=limit).data()


def get_cwe_hierarchy(cwe_id: str, driver: Driver | None = None, limit: int = 10) -> list[dict[str, Any]]:
    """Traverse CWE hierarchy up to 3 hops."""
    d = driver or get_neo4j_driver()
    cypher = """
    MATCH path = (w:CWE {id: $cwe_id})-[:CHILD_OF*1..3]->(parent:CWE)
    RETURN w.id AS cwe_id, parent.id AS parent_id, parent.name AS parent_name,
           [n IN nodes(path) | n.id] AS hierarchy_path
    LIMIT $limit
    """
    with d.session() as session:
        return session.run(cypher, cwe_id=cwe_id, limit=limit).data()


def get_cwe_attack_patterns(cwe_id: str, driver: Driver | None = None, limit: int = 15) -> list[dict[str, Any]]:
    """Find CAPEC attack patterns related to a CWE weakness."""
    d = driver or get_neo4j_driver()
    cypher = """
    MATCH (w:CWE {id: $cwe_id})-[:RELATED_ATTACK_PATTERN]->(p:CAPEC)
    RETURN p.id AS capec_id, p.name AS capec_name, w.id AS cwe_id
    LIMIT $limit
    """
    with d.session() as session:
        return session.run(cypher, cwe_id=cwe_id, limit=limit).data()


def get_technique_tactics(technique_id: str, driver: Driver | None = None, limit: int = 10) -> list[dict[str, Any]]:
    """Find ATT&CK tactics a technique belongs to."""
    d = driver or get_neo4j_driver()
    cypher = """
    MATCH (t:Technique {id: $technique_id})-[:IN_TACTIC]->(ta:Tactic)
    RETURN ta.id AS tactic_id, ta.name AS tactic_name, t.id AS technique_id
    LIMIT $limit
    """
    with d.session() as session:
        return session.run(cypher, technique_id=technique_id, limit=limit).data()


def get_capec_techniques(capec_id: str, driver: Driver | None = None, limit: int = 10) -> list[dict[str, Any]]:
    """Find ATT&CK techniques related to a CAPEC attack pattern."""
    d = driver or get_neo4j_driver()
    cypher = """
    MATCH (p:CAPEC {id: $capec_id})-[:RELATED_TECHNIQUE]->(t:Technique)
    RETURN t.id AS technique_id, t.name AS technique_name, p.id AS capec_id
    LIMIT $limit
    """
    with d.session() as session:
        return session.run(cypher, capec_id=capec_id, limit=limit).data()


def get_kev_exploited_cves(cwe_id: str | None = None, driver: Driver | None = None, limit: int = 10) -> list[dict[str, Any]]:
    """Find KEV-exploited CVEs optionally filtered by CWE."""
    d = driver or get_neo4j_driver()
    cypher = """
    MATCH (c:CVE {in_kev: true})-[:HAS_WEAKNESS]->(w:CWE)
    WHERE ($cwe_id IS NULL OR w.id = $cwe_id)
    RETURN c.id AS cve_id, c.cvss_score AS cvss_score, c.description AS description, w.id AS cwe_id
    ORDER BY c.cvss_score DESC
    LIMIT $limit
    """
    with d.session() as session:
        return session.run(cypher, cwe_id=cwe_id, limit=limit).data()


# ---------------------------------------------------------
# Bounded k-hop Subgraph Expansion
# ---------------------------------------------------------

def expand_entity_subgraph(
    entity_id: str,
    max_hops: int = 2,
    driver: Driver | None = None,
    limit: int = 25,
) -> list[dict[str, Any]]:
    """Expand k-hop neighborhood from an entity node, strictly bounded to max_hops <= 3."""
    d = driver or get_neo4j_driver()
    bounded_hops = min(max(1, max_hops), 3)

    # Dynamic Cypher string for strictly bounded traversal with LIMIT
    cypher = f"""
    MATCH path = (start)-[r*1..{bounded_hops}]-(target)
    WHERE coalesce(start.id, start.key) = $entity_id
      AND NOT target:Chunk
    RETURN [n IN nodes(path) | {{
        id: coalesce(n.id, n.key),
        label: labels(n)[0],
        name: coalesce(n.name, n.id, n.key)
    }}] AS nodes,
    [rel IN relationships(path) | type(rel)] AS rels,
    [n IN nodes(path) | coalesce(n.id, n.key)] AS path_ids
    LIMIT $limit
    """
    with d.session() as session:
        return session.run(cypher, entity_id=entity_id, limit=limit).data()


class GraphRetriever:
    """Orchestrates entity linking, template execution, and k-hop neighborhood expansion."""

    def __init__(self, driver: Driver | None = None, docstore: Docstore | None = None):
        self.driver = driver or get_neo4j_driver()
        self.docstore = docstore or Docstore()

    def retrieve(
        self,
        query: str,
        max_hops: int = 2,
        limit: int = 15,
    ) -> dict[str, Any]:
        """Perform graph retrieval: link entities, traverse paths, and attach chunk text."""
        entities = link_entities(query, driver=self.driver)
        paths: list[dict[str, Any]] = []
        node_ids_found: set[str] = set()

        for ent in entities:
            eid = ent["id"]
            etype = ent["type"]
            node_ids_found.add(eid)

            # 1. Specialized template traversal
            if etype == "cve":
                cve_chains = trace_cve_attack_chain(eid, driver=self.driver, limit=limit)
                for chain in cve_chains:
                    path_ids = chain.get("path_ids", [])
                    for pid in path_ids:
                        node_ids_found.add(pid)
                    paths.append({
                        "type": "cve_attack_chain",
                        "start_id": eid,
                        "path": path_ids,
                        "details": chain,
                    })

            elif etype == "technique":
                mits = get_technique_mitigations(eid, driver=self.driver, limit=limit)
                for m in mits:
                    mid = m.get("mitigation_id")
                    if mid:
                        node_ids_found.add(mid)
                    paths.append({
                        "type": "technique_mitigation",
                        "start_id": eid,
                        "path": [mid, eid],
                        "details": m,
                    })
                tactics = get_technique_tactics(eid, driver=self.driver, limit=limit)
                for t in tactics:
                    tid = t.get("tactic_id")
                    if tid:
                        node_ids_found.add(tid)
                    paths.append({
                        "type": "technique_tactic",
                        "start_id": eid,
                        "path": [eid, tid],
                        "details": t,
                    })

            elif etype == "cwe":
                parents = get_cwe_hierarchy(eid, driver=self.driver, limit=limit)
                for p in parents:
                    h_path = p.get("hierarchy_path", [])
                    for hid in h_path:
                        node_ids_found.add(hid)
                    paths.append({
                        "type": "cwe_hierarchy",
                        "start_id": eid,
                        "path": h_path,
                        "details": p,
                    })
                capecs = get_cwe_attack_patterns(eid, driver=self.driver, limit=limit)
                for c in capecs:
                    cid = c.get("capec_id")
                    if cid:
                        node_ids_found.add(cid)
                    paths.append({
                        "type": "cwe_attack_patterns",
                        "start_id": eid,
                        "path": [eid, cid],
                        "details": c,
                    })

            elif etype == "capec":
                techs = get_capec_techniques(eid, driver=self.driver, limit=limit)
                for t in techs:
                    tid = t.get("technique_id")
                    if tid:
                        node_ids_found.add(tid)
                    paths.append({
                        "type": "capec_technique",
                        "start_id": eid,
                        "path": [eid, tid],
                        "details": t,
                    })

            # 2. General bounded k-hop traversal
            expanded = expand_entity_subgraph(eid, max_hops=max_hops, driver=self.driver, limit=limit)
            for exp in expanded:
                path_ids = exp.get("path_ids", [])
                for pid in path_ids:
                    node_ids_found.add(pid)
                paths.append({
                    "type": "k_hop_expansion",
                    "start_id": eid,
                    "nodes": exp.get("nodes", []),
                    "rels": exp.get("rels", []),
                    "path": path_ids,
                })

        # 3. Retrieve descriptive chunk texts for graph nodes
        context_chunks: list[dict[str, Any]] = []
        for nid in node_ids_found:
            # Query docstore for chunks matching source_id
            chunks = self.docstore.get_chunks_by_source_id(nid)
            for ch in chunks:
                context_chunks.append({
                    "chunk_id": ch["chunk_id"],
                    "source_id": nid,
                    "source_type": ch["source_type"],
                    "text": ch["text"],
                    "via": "graph",
                })

        return {
            "query": query,
            "linked_entities": entities,
            "paths": paths[:limit],
            "context_chunks": context_chunks,
        }
