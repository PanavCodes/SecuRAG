"""Validator to verify that all citation IDs in answers exist in Neo4j."""

import logging
import re
from typing import Any
from neo4j import Driver

from securag.clients import get_neo4j_driver

logger = logging.getLogger(__name__)

ID_PATTERNS = {
    "cve": re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE),
    "cwe": re.compile(r"^CWE-\d+$", re.IGNORECASE),
    "capec": re.compile(r"^CAPEC-\d+$", re.IGNORECASE),
    "technique": re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE),
    "tactic": re.compile(r"^TA\d{4}$", re.IGNORECASE),
}


def validate_citation_id(cid: str, driver: Driver) -> bool:
    """Check if a specific security citation ID exists in Neo4j."""
    norm_id = cid.strip()

    # Determine node label
    label = None
    for l, pat in ID_PATTERNS.items():
        if pat.match(norm_id):
            label = l
            break

    with driver.session() as session:
        if label == "cve":
            r = session.run("MATCH (n:CVE {id: $id}) RETURN count(n) AS cnt LIMIT 1", id=norm_id.upper()).single()
            return bool(r and r["cnt"] > 0)
        elif label == "cwe":
            r = session.run("MATCH (n:CWE {id: $id}) RETURN count(n) AS cnt LIMIT 1", id=norm_id.upper()).single()
            return bool(r and r["cnt"] > 0)
        elif label == "capec":
            r = session.run("MATCH (n:CAPEC {id: $id}) RETURN count(n) AS cnt LIMIT 1", id=norm_id.upper()).single()
            return bool(r and r["cnt"] > 0)
        elif label == "technique":
            r = session.run("MATCH (n:Technique {id: $id}) RETURN count(n) AS cnt LIMIT 1", id=norm_id.upper()).single()
            return bool(r and r["cnt"] > 0)
        elif label == "tactic":
            r = session.run("MATCH (n:Tactic {id: $id}) RETURN count(n) AS cnt LIMIT 1", id=norm_id.upper()).single()
            return bool(r and r["cnt"] > 0)
        else:
            # Check Chunk ID
            r = session.run("MATCH (n:Chunk {chunk_id: $id}) RETURN count(n) AS cnt LIMIT 1", id=norm_id).single()
            if r and r["cnt"] > 0:
                return True
            # Check general node by id
            r2 = session.run("MATCH (n) WHERE coalesce(n.id, n.key) = $id RETURN count(n) AS cnt LIMIT 1", id=norm_id).single()
            return bool(r2 and r2["cnt"] > 0)


def validate_citations_against_neo4j(citations: list[str], driver: Driver | None = None) -> dict[str, Any]:
    """Verify that every cited entity ID in the answer exists in Neo4j.

    Mandated by hard rule in AGENTS.md:
    'Every cited ID in an answer must exist in Neo4j (validator required).'
    """
    d = driver or get_neo4j_driver()
    valid: list[str] = []
    invalid: list[str] = []

    for cit in citations:
        # Strip path: prefix if formatted as graph path citation
        clean_cit = cit.strip()
        if clean_cit.startswith("path:"):
            # Validate every node in path
            parts = clean_cit[5:].split("->")
            all_parts_valid = True
            for p in parts:
                if not validate_citation_id(p, d):
                    all_parts_valid = False
                    invalid.append(p)
            if all_parts_valid:
                valid.append(clean_cit)
            continue

        if validate_citation_id(clean_cit, d):
            valid.append(clean_cit)
        else:
            invalid.append(clean_cit)

    return {
        "all_valid": len(invalid) == 0,
        "valid_citations": valid,
        "invalid_citations": invalid,
    }
