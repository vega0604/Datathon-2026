"""
Comprehensive Verification Suite for Tiger Data Backend (SHE-75, SHE-76, SHE-77).
Tests bulk COPY loading, vendor monthly activity aggregates, and pgvector HNSW similarity queries.
"""
import datetime
import math
import os
import sys
import time
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import duckdb
from src.db import get_connection
from src.load_tiger import load_table, get_database_storage_bytes, MAX_STORAGE_BYTES
from src.analytics import ensure_vendor_aggregates, refresh_vendor_activity, get_top_active_vendors, get_vendor_trend
from src.similarity import get_similar_past_exploits, get_similar_by_vector


def generate_test_parquet_fixtures(fixture_dir: Path):
    """Generates synthetic test Parquet datasets for verification."""
    fixture_dir.mkdir(parents=True, exist_ok=True)
    con = duckdb.connect()

    # 1. vulnerabilities.parquet
    con.execute(f"""
        CREATE OR REPLACE TABLE test_vulns AS
        SELECT 
            'CVE-2024-1000' || i AS cve_id,
            DATE '2024-01-15' + INTERVAL (i) DAY AS published,
            'CWE-79, CWE-89' AS cwe_ids,
            'Synthetic test vulnerability ' || i AS description
        FROM range(1, 26) t(i);
        
        COPY test_vulns TO '{fixture_dir.as_posix()}/vulnerabilities.parquet' (FORMAT PARQUET);
    """)

    # 2. known_exploited.parquet
    con.execute(f"""
        CREATE OR REPLACE TABLE test_kev AS
        SELECT 
            'CVE-2024-1000' || i AS cve_id,
            CASE WHEN i % 2 = 0 THEN 'cisco' ELSE 'fortinet' END AS vendor,
            'firewall_os' AS product,
            DATE '2023-01-01' + INTERVAL (i * 10) DAY AS date_added,
            'Actively exploited remote code execution in ' || (CASE WHEN i % 2 = 0 THEN 'cisco' ELSE 'fortinet' END) AS short_description
        FROM range(1, 16) t(i);

        COPY test_kev TO '{fixture_dir.as_posix()}/known_exploited.parquet' (FORMAT PARQUET);
    """)

    # 3. scoreboard.parquet
    con.execute(f"""
        CREATE OR REPLACE TABLE test_scoreboard AS
        SELECT 
            'CVE-2024-1000' || i AS cve_id,
            DATE '2024-01-15' AS published,
            '2024-03' AS snapshot_month,
            0.85::FLOAT AS epss,
            1::SMALLINT AS exploitdb,
            0::SMALLINT AS metasploit,
            1::SMALLINT AS nuclei,
            1::SMALLINT AS poc_github
        FROM range(1, 21) t(i);

        COPY test_scoreboard TO '{fixture_dir.as_posix()}/scoreboard.parquet' (FORMAT PARQUET);
    """)

    # 4. exploit_signals.parquet
    con.execute(f"""
        CREATE OR REPLACE TABLE test_signals AS
        SELECT 
            TIMESTAMPTZ '2024-02-01 00:00:00+00' + INTERVAL (m) MONTH AS snapshot_month,
            'CVE-2024-1000' || i AS cve_id,
            (0.1 * i)::FLOAT AS epss,
            (0.04 * i)::FLOAT AS epss_pct,
            (i % 2)::SMALLINT AS in_kev,
            1::SMALLINT AS exploitdb,
            0::SMALLINT AS metasploit,
            1::SMALLINT AS nuclei,
            (i % 2)::SMALLINT AS poc_github
        FROM range(1, 16) t1(i), range(0, 3) t2(m);

        COPY test_signals TO '{fixture_dir.as_posix()}/exploit_signals.parquet' (FORMAT PARQUET);
    """)

    print(f"[+] Synthetic test parquet datasets generated in {fixture_dir}")


def test_bulk_loader(fixture_dir: Path):
    """Verifies SHE-75: PostgreSQL COPY streaming and row count validation."""
    print("\n--- [TEST SHE-75]: Bulk Loader via COPY ... FROM STDIN ---")
    tables = [
        ("vulnerabilities", fixture_dir / "vulnerabilities.parquet"),
        ("known_exploited", fixture_dir / "known_exploited.parquet"),
        ("scoreboard", fixture_dir / "scoreboard.parquet"),
        ("exploit_signals", fixture_dir / "exploit_signals.parquet"),
    ]

    for table, path in tables:
        count = load_table(table, path)
        print(f"  [PASS] {table} loaded and verified with {count} rows.")

    db_bytes, db_pretty = get_database_storage_bytes()
    print(f"  [PASS] Total Database Storage: {db_pretty} ({db_bytes:,} bytes)")
    assert db_bytes < MAX_STORAGE_BYTES, f"Storage budget exceeded! {db_pretty} > 750 MB"
    print("  [PASS] Storage strictly under 750 MB limit.")


def test_vendor_aggregates():
    """Verifies SHE-76: Timescale / PostgreSQL vendor monthly activity aggregate."""
    print("\n--- [TEST SHE-76]: Vendor Activity Materialized View ---")
    ensure_vendor_aggregates()
    refresh_vendor_activity()

    top_vendors = get_top_active_vendors(limit=5)
    print(f"  [+] Top active vendors query returned {len(top_vendors)} rows:")
    for v in top_vendors:
        print(f"      - Vendor: {v['vendor']} | Exploited CVEs: {v['total_exploited_cves']} | KEV Adds: {v['total_kev_additions']}")
    assert len(top_vendors) > 0, "Expected non-empty vendor aggregate results."

    # Test trend for one vendor
    vendor_name = top_vendors[0]["vendor"]
    trend = get_vendor_trend(vendor_name)
    print(f"  [+] Vendor trend for '{vendor_name}' returned {len(trend)} months of history.")
    assert len(trend) > 0, "Expected vendor trend history."
    print("  [PASS] Vendor monthly activity aggregates functioning correctly.")


def test_similarity_queries():
    """Verifies SHE-77: pgvector cosine distance retrieval with sub-second latency."""
    print("\n--- [TEST SHE-77]: pgvector HNSW Similarity Retrieval ---")
    
    # Insert sample 384-dimensional embeddings for the test CVEs into cve_embeddings
    print("  [*] Seeding test embeddings with dimension 384...")
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE known_exploited SET date_added = '2023-06-01' WHERE cve_id LIKE 'CVE-2024-1000%';")
            for i in range(1, 16):
                cve_id = f"CVE-2024-1000{i}"
                # Generate deterministic 384-dimensional normalized vector
                raw_vec = [math.sin(i * 0.1 + j * 0.05) for j in range(384)]
                norm = math.sqrt(sum(x * x for x in raw_vec))
                unit_vec = [x / norm for x in raw_vec]
                vec_str = "[" + ",".join(f"{x:.6f}" for x in unit_vec) + "]"
                
                cur.execute("""
                    INSERT INTO cve_embeddings (cve_id, embedding)
                    VALUES (%s, %s::vector)
                    ON CONFLICT (cve_id) DO UPDATE SET embedding = EXCLUDED.embedding;
                """, (cve_id, vec_str))
        conn.commit()

    # Query similar past exploits for CVE-2024-10005
    target_cve = "CVE-2024-10005"
    t0 = time.perf_counter()
    results = get_similar_past_exploits(target_cve, limit=5)
    latency_ms = (time.perf_counter() - t0) * 1000.0

    print(f"  [+] Similarity search for {target_cve} completed in {latency_ms:.2f} ms:")
    for r in results:
        print(f"      - Match: {r['cve_id']} | Vendor: {r['vendor']} | Date: {r['date_added']} | Sim: {r['similarity_score']} | Dist: {r['cosine_distance']}")

    assert len(results) > 0, "Expected similarity query to find matches."
    assert latency_ms < 1000.0, f"Query latency ({latency_ms:.2f} ms) exceeded 1.0s limit!"
    print(f"  [PASS] Sub-second latency verified ({latency_ms:.2f} ms < 1000 ms).")

    # Test direct vector search
    sample_vec = [1.0 / math.sqrt(384)] * 384
    vec_results = get_similar_by_vector(sample_vec, limit=3)
    assert len(vec_results) > 0, "Expected direct vector similarity results."
    print("  [PASS] Direct vector similarity query verified.")


def main():
    test_fixture_dir = PROJECT_ROOT / "data" / "parquet" / "test_fixtures"
    try:
        generate_test_parquet_fixtures(test_fixture_dir)
        test_bulk_loader(test_fixture_dir)
        test_vendor_aggregates()
        test_similarity_queries()
        print("\n=======================================================")
        print("[ALL TESTS PASSED]: SHE-75, SHE-76, SHE-77 VERIFIED LIVE!")
        print("=======================================================")
    finally:
        # Clean up temporary test parquet files from disk
        if test_fixture_dir.exists():
            import shutil
            shutil.rmtree(test_fixture_dir, ignore_errors=True)
            print("[*] Temporary test fixtures cleaned up.")


if __name__ == "__main__":
    main()
