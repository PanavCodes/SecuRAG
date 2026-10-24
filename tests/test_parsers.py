"""Acceptance tests for Step 2: Source ingestion parsers."""

import json
from pathlib import Path
import pytest


def test_processed_files_exist_and_valid():
    """Verify all 5 processed JSONL files exist, have records, and meet criteria."""
    processed_dir = Path("data/processed")
    assert processed_dir.exists(), "data/processed directory does not exist"

    # 1. KEV checks
    kev_file = processed_dir / "kev.jsonl"
    assert kev_file.exists(), "kev.jsonl missing"
    kev_records = [json.loads(line) for line in kev_file.open(encoding="utf-8") if line.strip()]
    assert len(kev_records) > 0, "KEV count must be > 0"
    for r in kev_records:
        assert "id" in r and r["id"].startswith("CVE-")

    # 2. CWE checks
    cwe_file = processed_dir / "cwe.jsonl"
    assert cwe_file.exists(), "cwe.jsonl missing"
    cwe_records = [json.loads(line) for line in cwe_file.open(encoding="utf-8") if line.strip()]
    assert len(cwe_records) > 0, "CWE count must be > 0"
    cwe_ids = {r["id"] for r in cwe_records}
    assert "CWE-79" in cwe_ids, "Must contain >=1 CWE with id CWE-79"
    cwe_79 = next(r for r in cwe_records if r["id"] == "CWE-79")
    assert cwe_79["name"], "CWE-79 must have a name"
    assert cwe_79["description"], "CWE-79 must have a description"

    # 3. CAPEC checks
    capec_file = processed_dir / "capec.jsonl"
    assert capec_file.exists(), "capec.jsonl missing"
    capec_records = [json.loads(line) for line in capec_file.open(encoding="utf-8") if line.strip()]
    assert len(capec_records) > 0, "CAPEC count must be > 0"
    capec_ids = {r["id"] for r in capec_records}
    assert "CAPEC-63" in capec_ids, "Must contain CAPEC-63"

    # 4. ATT&CK checks
    attack_file = processed_dir / "attack.jsonl"
    assert attack_file.exists(), "attack.jsonl missing"
    attack_records = [json.loads(line) for line in attack_file.open(encoding="utf-8") if line.strip()]
    assert len(attack_records) > 0, "ATT&CK count must be > 0"
    tech_ids = {r["id"] for r in attack_records if r.get("type") == "technique"}
    assert "T1021" in tech_ids, "Must contain >=1 Technique with id T1021"

    # 5. CVE checks
    cve_file = processed_dir / "cve.jsonl"
    assert cve_file.exists(), "cve.jsonl missing"
    cve_records = [json.loads(line) for line in cve_file.open(encoding="utf-8") if line.strip()]
    assert len(cve_records) > 0, "CVE count must be > 0"

    # Check: every CVE has id and description
    for idx, r in enumerate(cve_records):
        assert "id" in r and r["id"], f"Record {idx} missing id"
        assert "description" in r and r["description"].strip(), f"Record {r['id']} has empty description"

    # Print summary counts for acceptance reporting
    print("\n--- Parsed Files Acceptance Counts ---")
    print(f"KEV records   : {len(kev_records)}")
    print(f"CWE records   : {len(cwe_records)}")
    print(f"CAPEC records : {len(capec_records)}")
    print(f"ATT&CK records: {len(attack_records)}")
    print(f"CVE records   : {len(cve_records)}")
    print("--------------------------------------")
