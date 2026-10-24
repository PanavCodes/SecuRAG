"""Parser for MITRE ATT&CK Enterprise STIX 2.1 data."""

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def parse_attack(
    raw_path: str = "data/raw/attack-stix-data/enterprise-attack/enterprise-attack.json",
    out_path: str = "data/processed/attack.jsonl",
) -> list[dict[str, Any]]:
    """Parse MITRE ATT&CK Enterprise STIX file into normalized JSONL records.

    Outputs records for:
    1. Techniques (:Technique {id, name, description, is_subtechnique, platforms, tactic_ids, subtechnique_of})
    2. Tactics (:Tactic {id, name, shortname, description})
    3. Mitigations (:Mitigation {id, name, description, mitigates_techniques})
    """
    p = Path(raw_path)
    if not p.exists():
        raise FileNotFoundError(f"ATT&CK STIX file not found at: {raw_path}")

    with p.open("r", encoding="utf-8") as f:
        data = json.load(f)

    objects = data.get("objects", [])

    # Index by STIX id (e.g. "attack-pattern--...")
    stix_to_ext: dict[str, str] = {}
    tactics_by_shortname: dict[str, str] = {}  # shortname -> TAxxxx

    # First pass: map tactics and external IDs
    for obj in objects:
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        stix_id = obj.get("id")
        obj_type = obj.get("type")

        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                ext_id = ref.get("external_id")
                if stix_id and ext_id:
                    stix_to_ext[stix_id] = ext_id

        if obj_type == "x-mitre-tactic":
            shortname = obj.get("x_mitre_shortname")
            tactic_id = stix_to_ext.get(stix_id, "")
            if shortname and tactic_id:
                tactics_by_shortname[shortname] = tactic_id

    # Index relationships
    subtechnique_map: dict[str, str] = {}  # child_technique_id -> parent_technique_id
    mitigates_map: dict[str, list[str]] = {}  # mitigation_id -> [technique_ids]

    for obj in objects:
        if obj.get("type") == "relationship":
            rel_type = obj.get("relationship_type")
            src_stix = obj.get("source_ref")
            tgt_stix = obj.get("target_ref")

            src_ext = stix_to_ext.get(src_stix)
            tgt_ext = stix_to_ext.get(tgt_stix)

            if rel_type == "subtechnique-of" and src_ext and tgt_ext:
                subtechnique_map[src_ext] = tgt_ext
            elif rel_type == "mitigates" and src_ext and tgt_ext:
                mitigates_map.setdefault(src_ext, []).append(tgt_ext)

    records: list[dict[str, Any]] = []

    # Second pass: extract normalized records
    for obj in objects:
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        stix_id = obj.get("id")
        obj_type = obj.get("type")
        ext_id = stix_to_ext.get(stix_id)

        if not ext_id:
            continue

        if obj_type == "attack-pattern":
            # Map kill chain phases to Tactic IDs
            tactic_ids: list[str] = []
            for phase in obj.get("kill_chain_phases", []):
                p_name = phase.get("phase_name")
                if p_name in tactics_by_shortname:
                    tactic_ids.append(tactics_by_shortname[p_name])

            record = {
                "type": "technique",
                "id": ext_id,
                "name": obj.get("name", "").strip(),
                "description": obj.get("description", "").strip(),
                "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique", False)),
                "platforms": obj.get("x_mitre_platforms", []),
                "tactic_ids": list(dict.fromkeys(tactic_ids)),
                "subtechnique_of": subtechnique_map.get(ext_id),
            }
            records.append(record)

        elif obj_type == "x-mitre-tactic":
            record = {
                "type": "tactic",
                "id": ext_id,
                "name": obj.get("name", "").strip(),
                "shortname": obj.get("x_mitre_shortname", ""),
                "description": obj.get("description", "").strip(),
            }
            records.append(record)

        elif obj_type == "course-of-action":
            record = {
                "type": "mitigation",
                "id": ext_id,
                "name": obj.get("name", "").strip(),
                "description": obj.get("description", "").strip(),
                "mitigates_techniques": list(dict.fromkeys(mitigates_map.get(ext_id, []))),
            }
            records.append(record)

    out_file = Path(out_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with out_file.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")

    logger.info("Parsed %d ATT&CK records written to %s", len(records), out_path)
    return records
