"""Parser for CISA Known Exploited Vulnerabilities (KEV) data."""

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def parse_kev(
    raw_path: str = "data/raw/kev-data/known_exploited_vulnerabilities.json",
    out_path: str = "data/processed/kev.jsonl",
) -> list[dict[str, Any]]:
    """Parse CISA KEV JSON file and export to normalized JSONL.

    Fields extracted per record:
    - id: CVE ID (e.g. CVE-2024-1234)
    - vendor_project: Affected vendor or project name
    - product: Vulnerable product
    - vulnerability_name: Formal vulnerability title
    - date_added: Date added to KEV catalog (YYYY-MM-DD)
    - short_description: Summary description
    - required_action: Required remediation action
    - due_date: Remediation due date
    - known_ransomware_campaign_use: Known ransomware usage status
    - cwes: List of associated CWE IDs
    """
    p = Path(raw_path)
    if not p.exists():
        raise FileNotFoundError(f"KEV data file not found at: {raw_path}")

    with p.open("r", encoding="utf-8") as f:
        data = json.load(f)

    vulnerabilities = data.get("vulnerabilities", [])
    records: list[dict[str, Any]] = []

    for item in vulnerabilities:
        cve_id = item.get("cveID", "").strip()
        if not cve_id:
            continue

        record = {
            "id": cve_id,
            "vendor_project": item.get("vendorProject", ""),
            "product": item.get("product", ""),
            "vulnerability_name": item.get("vulnerabilityName", ""),
            "date_added": item.get("dateAdded", ""),
            "short_description": item.get("shortDescription", ""),
            "required_action": item.get("requiredAction", ""),
            "due_date": item.get("dueDate", ""),
            "known_ransomware_campaign_use": item.get("knownRansomwareCampaignUse", "Unknown"),
            "cwes": item.get("cwes", []),
        }
        records.append(record)

    out_file = Path(out_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with out_file.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")

    logger.info("Parsed %d KEV records written to %s", len(records), out_path)
    return records


def get_kev_lookup(
    raw_path: str = "data/raw/kev-data/known_exploited_vulnerabilities.json",
) -> dict[str, dict[str, Any]]:
    """Return dictionary lookup mapping cveID -> KEV entry metadata."""
    p = Path(raw_path)
    if not p.exists():
        return {}

    with p.open("r", encoding="utf-8") as f:
        data = json.load(f)

    lookup: dict[str, dict[str, Any]] = {}
    for item in data.get("vulnerabilities", []):
        cid = item.get("cveID", "").strip()
        if cid:
            lookup[cid] = item
    return lookup
