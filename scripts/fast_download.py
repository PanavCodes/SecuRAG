"""Multi-threaded accelerated downloader for BAAI/bge-reranker-v2-m3 model.safetensors."""

import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests

TARGET_DIR = r"C:\Users\panav\.cache\huggingface\hub\models--BAAI--bge-reranker-v2-m3\snapshots\953dc6f6f85a1b2dbfca4c34a2796e7dde08d41e"
TARGET_FILE = os.path.join(TARGET_DIR, "model.safetensors")
TEMP_FILE = TARGET_FILE + ".part"
URL = "https://huggingface.co/BAAI/bge-reranker-v2-m3/resolve/main/model.safetensors"
NUM_WORKERS = 16
CHUNK_SIZE = 16 * 1024 * 1024  # 16 MB per range chunk


def download_chunk(part_id: int, start: int, end: int, total_chunks: int) -> int:
    """Download a specific byte range and write to pre-allocated file."""
    headers = {"Range": f"bytes={start}-{end}", "User-Agent": "Mozilla/5.0"}
    for attempt in range(5):
        try:
            r = requests.get(URL, headers=headers, stream=True, timeout=30)
            if r.status_code in (200, 206):
                content = r.content
                with open(TEMP_FILE, "r+b") as f:
                    f.seek(start)
                    f.write(content)
                return len(content)
            else:
                time.sleep(1)
        except Exception as e:
            if attempt == 4:
                raise
            time.sleep(1.5)
    return 0


def main():
    os.makedirs(TARGET_DIR, exist_ok=True)
    if os.path.exists(TARGET_FILE) and os.path.getsize(TARGET_FILE) > 2_000_000_000:
        print(f"[OK] model.safetensors already complete ({os.path.getsize(TARGET_FILE):,} bytes).")
        return

    print("=" * 65)
    print("Multi-Threaded Accelerated Downloader (16 Workers)")
    print("URL:", URL)
    print("Target:", TARGET_FILE)
    print("=" * 65)

    # 1. Get total length
    resp = requests.head(URL, headers={"User-Agent": "Mozilla/5.0"}, allow_redirects=True, timeout=15)
    total_size = int(resp.headers.get("content-length", 2271071852))
    total_mb = total_size / (1024 * 1024)
    print(f"Total size: {total_mb:.1f} MB ({total_size:,} bytes)")

    # 2. Pre-allocate temp file
    if not os.path.exists(TEMP_FILE) or os.path.getsize(TEMP_FILE) != total_size:
        print(f"Pre-allocating {total_mb:.1f} MB placeholder file...")
        with open(TEMP_FILE, "wb") as f:
            f.seek(total_size - 1)
            f.write(b"\0")

    # 3. Build chunk plan
    chunks = []
    chunk_id = 0
    start = 0
    while start < total_size:
        end = min(start + CHUNK_SIZE - 1, total_size - 1)
        chunks.append((chunk_id, start, end))
        chunk_id += 1
        start = end + 1

    total_chunks = len(chunks)
    print(f"Divided into {total_chunks} chunks of ~16 MB across {NUM_WORKERS} concurrent threads.")

    downloaded = 0
    t0 = time.time()
    last_print = t0

    with ThreadPoolExecutor(max_workers=NUM_WORKERS) as executor:
        futures = {
            executor.submit(download_chunk, cid, s, e, total_chunks): (cid, s, e)
            for cid, s, e in chunks
        }
        for future in as_completed(futures):
            bytes_written = future.result()
            downloaded += bytes_written
            now = time.time()
            if now - last_print >= 3.0 or downloaded == total_size:
                elapsed = now - t0
                speed_mb = (downloaded / (1024 * 1024)) / max(elapsed, 0.001)
                dl_mb = downloaded / (1024 * 1024)
                pct = (downloaded / total_size) * 100
                rem_sec = (total_mb - dl_mb) / max(speed_mb, 0.001)
                print(
                    f"Progress: {dl_mb:.1f}/{total_mb:.1f} MB ({pct:.1f}%) | Speed: {speed_mb:.2f} MB/s | ETA: {rem_sec:.0f}s",
                    flush=True,
                )
                last_print = now

    # 4. Finalize file
    if os.path.exists(TARGET_FILE):
        os.remove(TARGET_FILE)
    os.rename(TEMP_FILE, TARGET_FILE)
    print(f"\n[COMPLETE] Successfully assembled {TARGET_FILE} in {time.time()-t0:.1f}s!", flush=True)

    # 5. Quick CrossEncoder test
    print("\nValidating CrossEncoder on GPU with downloaded weights...")
    from sentence_transformers import CrossEncoder
    reranker = CrossEncoder("BAAI/bge-reranker-v2-m3", device="cuda")
    pairs = [
        ["What is CVE-2024-1234?", "CVE-2024-1234 is a critical vulnerability."],
        ["What is CVE-2024-1234?", "The sky is blue."],
    ]
    scores = reranker.predict(pairs)
    print(f"[OK] Reranker initialized on GPU! Relevant: {scores[0]:.4f}, Irrelevant: {scores[1]:.4f}")


if __name__ == "__main__":
    main()
