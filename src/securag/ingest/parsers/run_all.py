"""Orchestration script to run all source parsers and output normalized JSONL files."""

import logging
import sys
import time
from pathlib import Path

from securag.ingest.parsers.attack import parse_attack
from securag.ingest.parsers.capec import parse_capec
from securag.ingest.parsers.cve import parse_cve
from securag.ingest.parsers.cwe import parse_cwe
from securag.ingest.parsers.kev import parse_kev

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("securag.ingest.run_all")


def run_all_parsers() -> dict[str, int]:
    """Execute all data parsers and return record counts per source."""
    out_dir = Path("data/processed")
    out_dir.mkdir(parents=True, exist_ok=True)

    counts: dict[str, int] = {}
    total_start = time.time()

    # 1. KEV
    t0 = time.time()
    kev_recs = parse_kev()
    counts["kev"] = len(kev_recs)
    logger.info("KEV: %d records parsed in %.2fs", len(kev_recs), time.time() - t0)

    # 2. CWE
    t0 = time.time()
    cwe_recs = parse_cwe()
    counts["cwe"] = len(cwe_recs)
    logger.info("CWE: %d records parsed in %.2fs", len(cwe_recs), time.time() - t0)

    # 3. CAPEC
    t0 = time.time()
    capec_recs = parse_capec()
    counts["capec"] = len(capec_recs)
    logger.info("CAPEC: %d records parsed in %.2fs", len(capec_recs), time.time() - t0)

    # 4. ATT&CK
    t0 = time.time()
    attack_recs = parse_attack()
    counts["attack"] = len(attack_recs)
    logger.info("ATT&CK: %d records parsed in %.2fs", len(attack_recs), time.time() - t0)

    # 5. CVE
    t0 = time.time()
    cve_recs = parse_cve()
    counts["cve"] = len(cve_recs)
    logger.info("CVE: %d records parsed in %.2fs", len(cve_recs), time.time() - t0)

    logger.info("All parsers finished in %.2fs total.", time.time() - total_start)
    print("\n--- Parsing Summary ---")
    for src, count in counts.items():
        print(f"  {src:10s}: {count:6d} records -> data/processed/{src}.jsonl")
    print("-----------------------\n")
    return counts


if __name__ == "__main__":
    run_all_parsers()
