"""Parser for MITRE CAPEC STIX 2.1 data."""

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def parse_capec(
    raw_path: str = "data/raw/cti/capec/2.1/stix-capec.json",
    out_path: str = "data/processed/capec.jsonl",
) -> list[dict[str, Any]]:
    """Parse MITRE CAPEC STIX file into normalized JSONL records.

    Fields extracted:
    - id: CAPEC ID (e.g. CAPEC-63)
    - name: Attack pattern name
    - description: Attack pattern description
    - severity: Typical severity (High, Medium, Low, etc.)
    - likelihood: Likelihood of attack (High, Medium, Low, etc.)
    - cwe_ids: Linked CWE weakness IDs
    - technique_ids: Linked ATT&CK technique IDs
    """
    p = Path(raw_path)
    if not p.exists():
        raise FileNotFoundError(f"CAPEC STIX file not found at: {raw_path}")

    with p.open("r", encoding="utf-8") as f:
        data = json.load(f)

    objects = data.get("objects", [])
    records: list[dict[str, Any]] = []

    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        ext_refs = obj.get("external_references", [])
        capec_id: str | None = None
        cwe_ids: list[str] = []
        technique_ids: list[str] = []

        for ref in ext_refs:
            src = ref.get("source_name", "").strip().lower()
            ext_id = ref.get("external_id", "").strip()
            if not ext_id:
                continue

            if src == "capec":
                capec_id = ext_id
            elif src == "cwe":
                # Ensure CWE- prefix
                if not ext_id.upper().startswith("CWE-"):
                    ext_id = f"CWE-{ext_id}"
                cwe_ids.append(ext_id)
            elif "attack" in src:
                # ATT&CK technique ID e.g. T1059 or T1574.010
                technique_ids.append(ext_id.upper())

        if not capec_id:
            continue

        record = {
            "id": capec_id,
            "name": obj.get("name", "").strip(),
            "description": obj.get("description", "").strip(),
            "severity": obj.get("x_capec_typical_severity"),
            "likelihood": obj.get("x_capec_likelihood_of_attack"),
            "cwe_ids": list(dict.fromkeys(cwe_ids)),
            "technique_ids": list(dict.fromkeys(technique_ids)),
        }
        records.append(record)

    out_file = Path(out_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with out_file.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")

    logger.info("Parsed %d CAPEC records written to %s", len(records), out_path)
    return records
