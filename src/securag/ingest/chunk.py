"""Chunking pipeline and SQLite docstore for SecuRAG."""

import json
import logging
import sqlite3
import time
from pathlib import Path
from typing import Any, Generator, Iterable
from langchain_text_splitters import RecursiveCharacterTextSplitter
from neo4j import Driver

from securag.clients import get_neo4j_driver

logger = logging.getLogger(__name__)

DOCSTORE_PATH = "data/processed/docstore.sqlite"


class Docstore:
    """SQLite-backed docstore storing full chunk texts and metadata."""

    def __init__(self, db_path: str = DOCSTORE_PATH):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.init_db()

    def get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self) -> None:
        with self.get_connection() as conn:
            conn.execute("""
            CREATE TABLE IF NOT EXISTS chunks (
                chunk_id TEXT PRIMARY KEY,
                namespace TEXT NOT NULL,
                source_id TEXT NOT NULL,
                source_type TEXT NOT NULL,
                position INTEGER NOT NULL,
                text TEXT NOT NULL,
                meta_json TEXT NOT NULL
            );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_chunks_ns ON chunks(namespace);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_chunks_source ON chunks(source_id);")
            conn.commit()

    def upsert_chunks(self, chunks: list[dict[str, Any]]) -> int:
        if not chunks:
            return 0
        with self.get_connection() as conn:
            conn.executemany("""
            INSERT INTO chunks (chunk_id, namespace, source_id, source_type, position, text, meta_json)
            VALUES (:chunk_id, :namespace, :source_id, :source_type, :position, :text, :meta_json)
            ON CONFLICT(chunk_id) DO UPDATE SET
                text=excluded.text,
                meta_json=excluded.meta_json;
            """, [
                {
                    "chunk_id": c["chunk_id"],
                    "namespace": c["namespace"],
                    "source_id": c["source_id"],
                    "source_type": c["source_type"],
                    "position": c["position"],
                    "text": c["text"],
                    "meta_json": json.dumps(c.get("metadata", {})),
                }
                for c in chunks
            ])
            conn.commit()
        return len(chunks)

    def get_chunk(self, chunk_id: str) -> dict[str, Any] | None:
        with self.get_connection() as conn:
            row = conn.execute("SELECT * FROM chunks WHERE chunk_id = ?", (chunk_id,)).fetchone()
            if row:
                return {
                    "chunk_id": row["chunk_id"],
                    "namespace": row["namespace"],
                    "source_id": row["source_id"],
                    "source_type": row["source_type"],
                    "position": row["position"],
                    "text": row["text"],
                    "metadata": json.loads(row["meta_json"]),
                }
        return None

    def get_chunks_by_source_id(self, source_id: str) -> list[dict[str, Any]]:
        """Return all chunks matching a given source_id."""
        with self.get_connection() as conn:
            rows = conn.execute("SELECT * FROM chunks WHERE source_id = ? ORDER BY position", (source_id,)).fetchall()
            return [
                {
                    "chunk_id": r["chunk_id"],
                    "namespace": r["namespace"],
                    "source_id": r["source_id"],
                    "source_type": r["source_type"],
                    "position": r["position"],
                    "text": r["text"],
                    "metadata": json.loads(r["meta_json"]),
                }
                for r in rows
            ]

    def get_namespace_counts(self) -> dict[str, int]:
        with self.get_connection() as conn:
            rows = conn.execute("SELECT namespace, count(*) AS cnt FROM chunks GROUP BY namespace").fetchall()
            return {r["namespace"]: r["cnt"] for r in rows}

    def get_all_chunks(self, namespace: str | None = None) -> list[dict[str, Any]]:
        with self.get_connection() as conn:
            if namespace:
                rows = conn.execute("SELECT * FROM chunks WHERE namespace = ? ORDER BY chunk_id", (namespace,)).fetchall()
            else:
                rows = conn.execute("SELECT * FROM chunks ORDER BY chunk_id").fetchall()

            return [
                {
                    "chunk_id": r["chunk_id"],
                    "namespace": r["namespace"],
                    "source_id": r["source_id"],
                    "source_type": r["source_type"],
                    "position": r["position"],
                    "text": r["text"],
                    "metadata": json.loads(r["meta_json"]),
                }
                for r in rows
            ]


def extract_year(date_str: str | None) -> int | None:
    """Extract 4-digit year from ISO date string."""
    if not date_str:
        return None
    try:
        parts = date_str.split("-")
        if len(parts) >= 1 and len(parts[0]) == 4 and parts[0].isdigit():
            return int(parts[0])
    except Exception:
        pass
    return None


def generate_chunks() -> list[dict[str, Any]]:
    """Produce all chunks for CVE, CWE, CAPEC, Technique, and Mitigation."""
    splitter = RecursiveCharacterTextSplitter(chunk_size=800, chunk_overlap=100)
    all_chunks: list[dict[str, Any]] = []

    # 1. CVE Chunks (namespace: cve)
    cve_path = Path("data/processed/cve.jsonl")
    if cve_path.exists():
        with cve_path.open("r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                r = json.loads(line)
                cve_id = r["id"]
                desc = r.get("description", "").strip()
                prods = r.get("affected_products", [])
                prod_str = ", ".join(prods) if prods else "None"
                text = f"{cve_id}. {desc} Affected: {prod_str}"

                year = extract_year(r.get("published"))
                cwe_ids = r.get("cwe_ids", [])
                severity = r.get("cvss_severity")
                in_kev = bool(r.get("in_kev", False))

                chunk_id = f"cve:{cve_id}:0"
                metadata = {
                    "source_id": cve_id,
                    "source_type": "cve",
                    "title": cve_id,
                    "year": year,
                    "cwe_ids": cwe_ids,
                    "severity": severity,
                    "in_kev": in_kev,
                    "text_preview": text[:300],
                }
                all_chunks.append({
                    "chunk_id": chunk_id,
                    "namespace": "cve",
                    "source_id": cve_id,
                    "source_type": "cve",
                    "position": 0,
                    "text": text,
                    "metadata": metadata,
                })

    # 2. Attack namespace: CWE, CAPEC, Technique, Mitigation
    # CWE
    cwe_path = Path("data/processed/cwe.jsonl")
    if cwe_path.exists():
        with cwe_path.open("r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                r = json.loads(line)
                cwe_id = r["id"]
                name = r.get("name", "").strip()
                desc = r.get("description", "").strip()
                full_text = f"{cwe_id}: {name}. {desc}" if name else f"{cwe_id}: {desc}"
                splits = splitter.split_text(full_text) if len(full_text) > 800 else [full_text]

                for pos, chunk_text in enumerate(splits):
                    chunk_id = f"attack:{cwe_id}:{pos}"
                    metadata = {
                        "source_id": cwe_id,
                        "source_type": "cwe",
                        "title": f"{cwe_id}: {name}"[:200],
                        "year": None,
                        "cwe_ids": [],
                        "severity": None,
                        "in_kev": False,
                        "text_preview": chunk_text[:300],
                    }
                    all_chunks.append({
                        "chunk_id": chunk_id,
                        "namespace": "attack",
                        "source_id": cwe_id,
                        "source_type": "cwe",
                        "position": pos,
                        "text": chunk_text,
                        "metadata": metadata,
                    })

    # CAPEC
    capec_path = Path("data/processed/capec.jsonl")
    if capec_path.exists():
        with capec_path.open("r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                r = json.loads(line)
                capec_id = r["id"]
                name = r.get("name", "").strip()
                desc = r.get("description", "").strip()
                full_text = f"{capec_id}: {name}. {desc}" if name else f"{capec_id}: {desc}"
                splits = splitter.split_text(full_text) if len(full_text) > 800 else [full_text]

                for pos, chunk_text in enumerate(splits):
                    chunk_id = f"attack:{capec_id}:{pos}"
                    metadata = {
                        "source_id": capec_id,
                        "source_type": "capec",
                        "title": f"{capec_id}: {name}"[:200],
                        "year": None,
                        "cwe_ids": r.get("cwe_ids", []),
                        "severity": r.get("severity"),
                        "in_kev": False,
                        "text_preview": chunk_text[:300],
                    }
                    all_chunks.append({
                        "chunk_id": chunk_id,
                        "namespace": "attack",
                        "source_id": capec_id,
                        "source_type": "capec",
                        "position": pos,
                        "text": chunk_text,
                        "metadata": metadata,
                    })

    # ATT&CK (Techniques and Mitigations)
    attack_path = Path("data/processed/attack.jsonl")
    if attack_path.exists():
        with attack_path.open("r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                r = json.loads(line)
                rtype = r.get("type")
                if rtype not in ("technique", "mitigation"):
                    continue

                source_id = r["id"]
                name = r.get("name", "").strip()
                desc = r.get("description", "").strip()
                full_text = f"{source_id}: {name}. {desc}" if name else f"{source_id}: {desc}"
                splits = splitter.split_text(full_text) if len(full_text) > 800 else [full_text]

                for pos, chunk_text in enumerate(splits):
                    chunk_id = f"attack:{source_id}:{pos}"
                    metadata = {
                        "source_id": source_id,
                        "source_type": rtype,
                        "title": f"{source_id}: {name}"[:200],
                        "year": None,
                        "cwe_ids": [],
                        "severity": None,
                        "in_kev": False,
                        "text_preview": chunk_text[:300],
                    }
                    all_chunks.append({
                        "chunk_id": chunk_id,
                        "namespace": "attack",
                        "source_id": source_id,
                        "source_type": rtype,
                        "position": pos,
                        "text": chunk_text,
                        "metadata": metadata,
                    })

    return all_chunks


def batch_iterate(items: Iterable[Any], size: int = 1000) -> Generator[list[Any], None, None]:
    batch: list[Any] = []
    for item in items:
        batch.append(item)
        if len(batch) >= size:
            yield batch
            batch = []
    if batch:
        yield batch


def sync_chunks_to_neo4j(chunks: list[dict[str, Any]], driver: Driver | None = None, batch_size: int = 2000) -> None:
    """Create :Chunk nodes and [:DESCRIBES] edges in Neo4j."""
    d = driver or get_neo4j_driver()
    logger.info("Syncing %d chunks to Neo4j as (:Chunk) and [:DESCRIBES]...", len(chunks))

    # Separate by source type for fast labeled MATCH
    by_type: dict[str, list[dict[str, Any]]] = {}
    for c in chunks:
        by_type.setdefault(c["source_type"], []).append({
            "chunk_id": c["chunk_id"],
            "namespace": c["namespace"],
            "source_id": c["source_id"],
            "position": c["position"],
        })

    label_map = {
        "cve": "CVE",
        "cwe": "CWE",
        "capec": "CAPEC",
        "technique": "Technique",
        "mitigation": "Mitigation",
    }

    with d.session() as session:
        for stype, rows in by_type.items():
            label = label_map.get(stype)
            if not label:
                continue

            query = f"""
            UNWIND $batch AS row
            MERGE (ch:Chunk {{chunk_id: row.chunk_id}})
            SET ch.namespace = row.namespace,
                ch.source_id = row.source_id,
                ch.position = row.position
            WITH ch, row
            MATCH (target:{label} {{id: row.source_id}})
            MERGE (ch)-[:DESCRIBES]->(target)
            """
            for batch in batch_iterate(rows, batch_size):
                session.run(query, {"batch": batch})

    logger.info("Successfully synced chunks to Neo4j.")


def run_chunking_and_storage(sync_neo4j: bool = True) -> tuple[Docstore, dict[str, int]]:
    """Execute complete chunk generation, SQLite persistence, and Neo4j sync."""
    t0 = time.time()
    chunks = generate_chunks()
    logger.info("Generated %d total chunks in %.2fs", len(chunks), time.time() - t0)

    # 1. SQLite docstore
    docstore = Docstore()
    t1 = time.time()
    for batch in batch_iterate(chunks, 2000):
        docstore.upsert_chunks(batch)
    logger.info("Saved %d chunks to SQLite docstore in %.2fs", len(chunks), time.time() - t1)

    # 2. Neo4j Chunk nodes & DESCRIBES
    if sync_neo4j:
        t2 = time.time()
        sync_chunks_to_neo4j(chunks)
        logger.info("Neo4j Chunk sync finished in %.2fs", time.time() - t2)

    counts = docstore.get_namespace_counts()
    return docstore, counts


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    docstore, counts = run_chunking_and_storage(sync_neo4j=True)
    print("\n--- Docstore Namespace Counts ---")
    for ns, cnt in counts.items():
        print(f"  Namespace {ns:12s}: {cnt:6d} chunks")
    print("---------------------------------\n")
