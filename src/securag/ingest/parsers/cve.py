"""Parser for CVE JSON 5.x records from CVEProject/cvelistV5."""

import json
import logging
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from securag.config import get_settings
from securag.ingest.parsers.kev import get_kev_lookup

logger = logging.getLogger(__name__)


def _parse_single_cve_file(
    file_path: str,
    kev_lookup: dict[str, dict[str, Any]],
) -> dict[str, Any] | None:
    """Parse a single CVE JSON 5.x file."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            doc = json.load(f)
    except Exception:
        return None

    cve_meta = doc.get("cveMetadata", {})
    if cve_meta.get("state") != "PUBLISHED":
        return None

    cve_id = cve_meta.get("cveId", "").strip()
    if not cve_id:
        return None

    date_published = cve_meta.get("datePublished", "")

    containers = doc.get("containers", {})
    cna = containers.get("cna", {})
    adp_list = containers.get("adp", [])

    # Description (English first, then any non-empty)
    description = ""
    for desc in cna.get("descriptions", []):
        if desc.get("lang", "").lower().startswith("en"):
            val = desc.get("value", "").strip()
            if val:
                description = val
                break
    if not description:
        for desc in cna.get("descriptions", []):
            val = desc.get("value", "").strip()
            if val:
                description = val
                break
    if not description:
        for adp in adp_list:
            for desc in adp.get("descriptions", []):
                val = desc.get("value", "").strip()
                if val:
                    description = val
                    break
            if description:
                break
    if not description and cve_id in kev_lookup:
        description = (
            kev_lookup[cve_id].get("shortDescription", "").strip()
            or kev_lookup[cve_id].get("vulnerabilityName", "").strip()
        )
    if not description:
        title = cna.get("title", "").strip()
        if title:
            description = title
        else:
            return None

    # CWE Extraction (Union of CNA and ADP)
    cwe_set: set[str] = set()
    for pt in cna.get("problemTypes", []):
        for desc in pt.get("descriptions", []):
            cwe_id_raw = desc.get("cweId")
            if cwe_id_raw and str(cwe_id_raw).strip():
                cid = str(cwe_id_raw).strip().upper()
                if not cid.startswith("CWE-"):
                    cid = f"CWE-{cid}"
                cwe_set.add(cid)

    for adp in adp_list:
        for pt in adp.get("problemTypes", []):
            for desc in pt.get("descriptions", []):
                cwe_id_raw = desc.get("cweId")
                if cwe_id_raw and str(cwe_id_raw).strip():
                    cid = str(cwe_id_raw).strip().upper()
                    if not cid.startswith("CWE-"):
                        cid = f"CWE-{cid}"
                    cwe_set.add(cid)

    # CVSS Extraction
    cvss_score: float | None = None
    cvss_severity: str | None = None

    for metric in cna.get("metrics", []):
        for cvss_key in ("cvssV3_1", "cvssV4_0", "cvssV3_0"):
            if cvss_key in metric:
                m = metric[cvss_key]
                try:
                    cvss_score = float(m.get("baseScore", 0))
                    cvss_severity = m.get("baseSeverity", "").upper() or None
                except (TypeError, ValueError):
                    pass
                break
        if cvss_score is not None:
            break

    if cvss_score is None:
        for adp in adp_list:
            for metric in adp.get("metrics", []):
                for cvss_key in ("cvssV3_1", "cvssV4_0", "cvssV3_0"):
                    if cvss_key in metric:
                        m = metric[cvss_key]
                        try:
                            cvss_score = float(m.get("baseScore", 0))
                            cvss_severity = m.get("baseSeverity", "").upper() or None
                        except (TypeError, ValueError):
                            pass
                        break
                if cvss_score is not None:
                    break

    # Affected Products (vendor::product)
    products: set[str] = set()
    for aff in cna.get("affected", []):
        vendor = str(aff.get("vendor", "")).strip().lower()
        prod = str(aff.get("product", "")).strip().lower()
        if vendor and prod and vendor not in ("n/a", "none") and prod not in ("n/a", "none"):
            key = f"{vendor}::{prod}".replace(" ", "_")
            products.add(key)

    # KEV and SSVC Information
    in_kev = False
    kev_date_added: str | None = None
    ssvc_exploitation: str | None = None

    if cve_id in kev_lookup:
        in_kev = True
        kev_date_added = kev_lookup[cve_id].get("dateAdded")
        for c in kev_lookup[cve_id].get("cwes", []):
            c_str = str(c).strip().upper()
            if c_str:
                if not c_str.startswith("CWE-"):
                    c_str = f"CWE-{c_str}"
                cwe_set.add(c_str)

    for adp in adp_list:
        for metric in adp.get("metrics", []):
            other = metric.get("other", {})
            if other.get("type") == "kev":
                in_kev = True
                content = other.get("content", {})
                if isinstance(content, dict) and "dateAdded" in content:
                    kev_date_added = content["dateAdded"]

            elif other.get("type") == "ssvc":
                content = other.get("content", {})
                if isinstance(content, dict):
                    for opt in content.get("options", []):
                        if isinstance(opt, dict) and "Exploitation" in opt:
                            ssvc_exploitation = opt["Exploitation"]

    return {
        "id": cve_id,
        "description": description,
        "published": date_published,
        "cvss_score": cvss_score,
        "cvss_severity": cvss_severity,
        "in_kev": in_kev,
        "kev_date_added": kev_date_added,
        "ssvc_exploitation": ssvc_exploitation,
        "cwe_ids": sorted(list(cwe_set)),
        "affected_products": sorted(list(products)),
    }


def parse_cve(
    raw_dir: str = "data/raw/cvelistV5/cves",
    out_path: str = "data/processed/cve.jsonl",
    years: list[str] | None = None,
    max_cves: int | None = None,
    workers: int = 16,
) -> list[dict[str, Any]]:
    """Parse CVE v5.x records and export normalized JSONL.

    Applies the sizing rule:
    Priority 1: All KEV-listed CVEs (including pre-slice KEV records for demos/eval)
    Priority 2: CVEs with at least one linked CWE
    Priority 3: Other published CVEs
    Capped at max_cves (default from settings: 20000).
    """
    settings = get_settings()
    years_to_scan = years or settings.parsed_years
    limit = max_cves if max_cves is not None else settings.cve_max

    base_path = Path(raw_dir)
    if not base_path.exists():
        raise FileNotFoundError(f"CVE directory not found at: {raw_dir}")

    kev_lookup = get_kev_lookup()
    logger.info("Loaded %d KEV entries for cross-referencing.", len(kev_lookup))

    file_paths: list[str] = []
    for year in years_to_scan:
        year_dir = base_path / str(year)
        if not year_dir.exists():
            logger.warning("Year directory does not exist: %s", year_dir)
            continue
        for root, _, files in os.walk(str(year_dir)):
            for f in files:
                if f.endswith(".json"):
                    file_paths.append(os.path.join(root, f))

    logger.info("Scanning %d CVE files across years %s with %d workers...", len(file_paths), years_to_scan, workers)

    collected: list[dict[str, Any]] = []
    seen_ids: set[str] = set()

    with ThreadPoolExecutor(max_workers=workers) as executor:
        for res in executor.map(lambda fp: _parse_single_cve_file(fp, kev_lookup), file_paths):
            if res and res["id"] not in seen_ids:
                seen_ids.add(res["id"])
                collected.append(res)

    # Ingest any remaining KEV catalog items (e.g. pre-slice KEV entries like Log4j CVE-2021-44228)
    pre_slice_kev_count = 0
    for cid, item in kev_lookup.items():
        if cid not in seen_ids:
            seen_ids.add(cid)
            desc = (
                item.get("shortDescription", "").strip()
                or item.get("vulnerabilityName", "").strip()
                or f"Vulnerability {cid}"
            )
            cwes: list[str] = []
            for c in item.get("cwes", []):
                c_str = str(c).strip().upper()
                if c_str:
                    if not c_str.startswith("CWE-"):
                        c_str = f"CWE-{c_str}"
                    cwes.append(c_str)

            products: list[str] = []
            vendor = item.get("vendorProject", "").strip().lower()
            prod = item.get("product", "").strip().lower()
            if vendor and prod:
                products.append(f"{vendor}::{prod}".replace(" ", "_"))

            rec = {
                "id": cid,
                "description": desc,
                "published": item.get("dateAdded", ""),
                "cvss_score": None,
                "cvss_severity": None,
                "in_kev": True,
                "kev_date_added": item.get("dateAdded"),
                "ssvc_exploitation": None,
                "cwe_ids": sorted(list(set(cwes))),
                "affected_products": products,
            }
            collected.append(rec)
            pre_slice_kev_count += 1

    logger.info("Added %d KEV entries from outside configured slice.", pre_slice_kev_count)

    # Priority sorting:
    # 1. KEV-listed first
    # 2. Has linked CWE second
    # 3. Others
    def sort_key(rec: dict[str, Any]) -> tuple[int, int]:
        kev_rank = 0 if rec["in_kev"] else 1
        cwe_rank = 0 if rec["cwe_ids"] else 1
        return (kev_rank, cwe_rank)

    collected.sort(key=sort_key)
    if len(collected) > limit:
        logger.info("Capping collected CVEs from %d to %d as per CVE_MAX", len(collected), limit)
        collected = collected[:limit]

    out_file = Path(out_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with out_file.open("w", encoding="utf-8") as f:
        for r in collected:
            f.write(json.dumps(r) + "\n")

    logger.info("Parsed %d CVE records written to %s", len(collected), out_path)
    return collected
