"""Parser for MITRE Common Weakness Enumeration (CWE) XML data."""

import json
import logging
from pathlib import Path
from typing import Any
from lxml import etree

logger = logging.getLogger(__name__)


def parse_cwe(
    raw_dir: str = "data/raw/cwe",
    out_path: str = "data/processed/cwe.jsonl",
) -> list[dict[str, Any]]:
    """Parse MITRE CWE XML catalog into normalized JSONL records.

    Fields extracted:
    - id: CWE ID formatted as CWE-<n> (e.g. CWE-79)
    - name: Weakness name
    - description: Full text description
    - abstraction: Abstraction level (Class, Base, Variant, Compound)
    - child_of: List of parent CWE IDs from Related_Weakness (Nature="ChildOf")
    - capec_ids: List of related attack patterns from Related_Attack_Patterns (CAPEC-<id>)
    """
    raw_path = Path(raw_dir)
    xml_files = list(raw_path.glob("*.xml"))
    if not xml_files:
        raise FileNotFoundError(f"No CWE XML files found in {raw_dir}")

    # Use the largest or latest xml file
    xml_file = max(xml_files, key=lambda f: f.stat().st_size)
    logger.info("Parsing CWE XML: %s", xml_file)

    tree = etree.parse(str(xml_file))
    root = tree.getroot()

    records: list[dict[str, Any]] = []

    for elem in root.iter("{*}Weakness"):
        raw_id = elem.get("ID", "").strip()
        if not raw_id:
            continue
        cwe_id = f"CWE-{raw_id}"
        name = elem.get("Name", "").strip()
        abstraction = elem.get("Abstraction", "").strip()

        desc_elem = elem.find("{*}Description")
        description = desc_elem.text.strip() if desc_elem is not None and desc_elem.text else ""
        if not description:
            ext_desc = elem.find("{*}Extended_Description")
            if ext_desc is not None and ext_desc.text:
                description = ext_desc.text.strip()

        # Extract parent relationships (Nature="ChildOf")
        parents: list[str] = []
        for rel in elem.iter("{*}Related_Weakness"):
            if rel.get("Nature") == "ChildOf":
                parent_id = rel.get("CWE_ID", "").strip()
                if parent_id:
                    parents.append(f"CWE-{parent_id}")

        # Deduplicate parents while preserving order
        parents = list(dict.fromkeys(parents))

        # Extract related CAPEC attack patterns
        capec_ids: list[str] = []
        for ap in elem.iter("{*}Related_Attack_Pattern"):
            cap_id = ap.get("CAPEC_ID", "").strip()
            if cap_id:
                capec_ids.append(f"CAPEC-{cap_id}")

        capec_ids = list(dict.fromkeys(capec_ids))

        record = {
            "id": cwe_id,
            "name": name,
            "description": description,
            "abstraction": abstraction,
            "child_of": parents,
            "capec_ids": capec_ids,
        }
        records.append(record)

    out_file = Path(out_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with out_file.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")

    logger.info("Parsed %d CWE records written to %s", len(records), out_path)
    return records
