"""SHE-18 to SHE-22: clean the typed Parquet tables into data/clean/.

Run after `uv run python -m backend.pipeline.load`:

    uv run python -m backend.pipeline.clean

Each step is a function that returns SQL, so it can be unit-tested on tiny tables
(tests/test_clean.py) without the real data. main() runs the steps on the real
tables, writes data/clean/*.parquet, and records row counts in
outputs/logs/clean_log.json (checked by tests/test_clean_data.py).
"""

import json

import duckdb

from backend.core.config import CLEAN_DIR, LOGS_DIR, PARQUET_DIR
from backend.db.warehouse import connect


def write_parquet(con: duckdb.DuckDBPyConnection, query: str, name: str) -> int:
    CLEAN_DIR.mkdir(parents=True, exist_ok=True)
    path = (CLEAN_DIR / f"{name}.parquet").as_posix()
    con.execute(f"COPY ({query}) TO '{path}' (FORMAT parquet, COMPRESSION zstd)")
    return con.execute(f"SELECT count(*) FROM read_parquet('{path}')").fetchone()[0]


def count(con: duckdb.DuckDBPyConnection, table: str) -> int:
    return con.execute(f"SELECT count(*) FROM {table}").fetchone()[0]


# --- SHE-18: weakness types, one row per CVE-CWE pair -------------------------

UNKNOWN_CWE = "unknown"
PLACEHOLDER_CWES = ("NVD-CWE-Other", "NVD-CWE-noinfo")


def cwe_long_sql(vulns: str = "vulnerabilities") -> str:
    """One row per (cve_id, cwe_id). Blank cwe_ids and NIST's placeholders become
    'unknown', so every CVE has at least one row."""
    placeholders = ", ".join(f"'{c}'" for c in PLACEHOLDER_CWES)
    return f"""
        SELECT DISTINCT
            cve_id,
            CASE WHEN cwe = '' OR cwe IN ({placeholders}) THEN '{UNKNOWN_CWE}' ELSE cwe END
                AS cwe_id
        FROM (
            SELECT cve_id, trim(cwe) AS cwe
            FROM (
                SELECT cve_id, unnest(string_split(coalesce(cwe_ids, ''), ';')) AS cwe
                FROM {vulns}
            )
        )
        ORDER BY cve_id, cwe_id
    """


# --- SHE-19 to SHE-21: monthly exploit signals ---------------------------------


def signals_union_sql() -> str:
    return "SELECT * FROM exploit_signals_2024 UNION ALL SELECT * FROM exploit_signals_2025"


def drop_rejected_sql(src: str, vulns: str = "vulnerabilities") -> str:
    """SHE-19: drop rows whose ID isn't in vulnerabilities (rejected IDs)."""
    return f"SELECT * FROM {src} WHERE cve_id IN (SELECT cve_id FROM {vulns})"


def fill_feb_2025_sql(src: str) -> str:
    """SHE-20: February 2025 is missing ~14,500 CVEs. A CVE present in January and
    March but not February gets January's values for February, with filled_gap = 1."""
    return f"""
        SELECT *, 0::UTINYINT AS filled_gap FROM {src}
        UNION ALL
        SELECT * REPLACE ('2025-02' AS month), 1::UTINYINT AS filled_gap
        FROM {src}
        WHERE month = '2025-01'
          AND cve_id IN (SELECT cve_id FROM {src} WHERE month = '2025-03')
          AND cve_id NOT IN (SELECT cve_id FROM {src} WHERE month = '2025-02')
    """


def add_epss_pct_sql(src: str) -> str:
    """SHE-21: EPSS changed its model in March 2025, so raw scores aren't comparable
    across months. epss_pct ranks each score within its month (0 = lowest, 1 = highest).
    NULL where the CVE had no EPSS score that month."""
    return f"""
        SELECT
            *,
            CASE
                WHEN epss IS NULL THEN NULL
                ELSE percent_rank() OVER (PARTITION BY month, epss IS NULL ORDER BY epss)
            END AS epss_pct
        FROM {src}
    """


# Applied in order to the 2024 + 2025 signals. Each entry: (log name, step).
SIGNAL_STEPS = [
    ("drop_rejected", drop_rejected_sql),
    ("fill_feb_2025", fill_feb_2025_sql),
    ("epss_pct", add_epss_pct_sql),
]


def build_signals(con: duckdb.DuckDBPyConnection, log: dict[str, int]) -> int:
    con.execute(f"CREATE OR REPLACE TEMP TABLE signals AS {signals_union_sql()}")
    log["signals_raw"] = count(con, "signals")
    for name, step in SIGNAL_STEPS:
        con.execute(f"CREATE OR REPLACE TEMP TABLE signals_next AS {step('signals')}")
        con.execute("DROP TABLE signals")
        con.execute("ALTER TABLE signals_next RENAME TO signals")
        log[f"signals_after_{name}"] = count(con, "signals")
    return write_parquet(con, "SELECT * FROM signals ORDER BY month, cve_id", "exploit_signals")


# --- SHE-22: vendor names -------------------------------------------------------

# Linux distributions repackage other vendors' software, so they are never alias targets.
REDISTRIBUTORS = ("debian", "fedoraproject", "canonical", "redhat", "suse", "opensuse")


def vendor_key_sql(expr: str) -> str:
    """A comparable vendor key: lowercase letters and digits only.
    'Palo Alto Networks' -> 'paloaltonetworks'; 'TP-Link' and 'tp-link' -> 'tplink'."""
    return f"regexp_replace(lower({expr}), '[^a-z0-9]', '', 'g')"


def vendor_aliases_sql(kev: str = "known_exploited", affected: str = "affected_products") -> str:
    """Derive aliases from the data: CISA vendor name -> NIST (CPE) vendor name.

    A KEV vendor needs an alias only if its key never matches the vendor of a vulnerable
    product on any of its own CVEs (e.g. 'Android', whose CVEs list 'google'). Its alias
    is the CPE vendor on the most of its CVEs, ignoring Linux distributions. Ties go to
    the candidate whose key contains the KEV key or vice versa ('Git' -> 'git-scm').
    No alias if the winner is still tied, or appears on fewer than half its CVEs.
    """
    kev_key = vendor_key_sql("k.vendor")
    cpe_key = vendor_key_sql("a.vendor")
    redistributors = ", ".join(f"'{v}'" for v in REDISTRIBUTORS)
    return f"""
        WITH pairs AS (
            SELECT DISTINCT
                k.vendor AS kev_vendor, {kev_key} AS kev_key, k.cve_id,
                a.vendor AS cpe_vendor, {cpe_key} AS cpe_key
            FROM {kev} AS k
            JOIN {affected} AS a ON a.cve_id = k.cve_id AND a.vulnerable = 'Y'
        ),
        needs_alias AS (
            SELECT kev_vendor, count(DISTINCT cve_id) AS kev_cves
            FROM pairs
            GROUP BY kev_vendor
            HAVING NOT bool_or(cpe_key = kev_key)
        ),
        candidates AS (
            SELECT
                p.kev_vendor,
                p.cpe_vendor,
                n.kev_cves,
                count(DISTINCT p.cve_id) AS cves,
                contains(p.cpe_key, p.kev_key) OR contains(p.kev_key, p.cpe_key) AS name_match
            FROM pairs AS p
            JOIN needs_alias AS n ON n.kev_vendor = p.kev_vendor
            WHERE p.cpe_key NOT IN ({redistributors})
            GROUP BY p.kev_vendor, p.kev_key, p.cpe_vendor, p.cpe_key, n.kev_cves
        ),
        ranked AS (
            SELECT
                *,
                row_number() OVER (
                    PARTITION BY kev_vendor ORDER BY cves DESC, name_match DESC, cpe_vendor
                ) AS pos,
                count(*) OVER (PARTITION BY kev_vendor, cves, name_match) AS tied
            FROM candidates
        )
        SELECT kev_vendor, cpe_vendor, cves, kev_cves
        FROM ranked
        WHERE pos = 1 AND tied = 1 AND cves * 2 >= kev_cves
        ORDER BY kev_vendor
    """


def kev_with_vendor_key_sql(kev: str = "known_exploited", aliases: str = "vendor_aliases") -> str:
    """KEV plus vendor_key, using the alias where vendor_aliases_sql() found one."""
    key = vendor_key_sql("coalesce(a.cpe_vendor, k.vendor)")
    return f"""
        SELECT k.*, {key} AS vendor_key
        FROM {kev} AS k
        LEFT JOIN {aliases} AS a ON a.kev_vendor = k.vendor
        ORDER BY k.date_added, k.cve_id
    """


def affected_with_vendor_key_sql(affected: str = "affected_products") -> str:
    return f"SELECT *, {vendor_key_sql('vendor')} AS vendor_key FROM {affected}"


def kev_vendor_matches_sql(kev: str, affected: str) -> str:
    """KEV rows whose vendor_key matches a vulnerable product's vendor on the same CVE."""
    return f"""
        SELECT count(*) FROM {kev} AS k
        WHERE EXISTS (
            SELECT 1 FROM {affected} AS a
            WHERE a.cve_id = k.cve_id AND a.vulnerable = 'Y' AND a.vendor_key = k.vendor_key
        )
    """


def clean_parquet(name: str) -> str:
    return f"read_parquet('{(CLEAN_DIR / f'{name}.parquet').as_posix()}')"


def build_vendors(con: duckdb.DuckDBPyConnection, log: dict[str, int]) -> None:
    log["vendor_aliases"] = write_parquet(con, vendor_aliases_sql(), "vendor_aliases")
    kev_sql = kev_with_vendor_key_sql(aliases=clean_parquet("vendor_aliases"))
    log["kev"] = write_parquet(con, kev_sql, "kev")
    log["affected_products"] = write_parquet(
        con, affected_with_vendor_key_sql(), "affected_products"
    )
    matches = kev_vendor_matches_sql(clean_parquet("kev"), clean_parquet("affected_products"))
    log["kev_vendor_matches"] = con.execute(matches).fetchone()[0]


def main() -> None:
    if not (PARQUET_DIR / "vulnerabilities.parquet").exists():
        raise SystemExit("No Parquet data. Run `uv run python -m backend.pipeline.load` first.")
    con = connect()
    log: dict[str, int] = {}
    log["cwe"] = write_parquet(con, cwe_long_sql(), "cwe")
    log["exploit_signals"] = build_signals(con, log)
    build_vendors(con, log)
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    (LOGS_DIR / "clean_log.json").write_text(json.dumps(log, indent=2) + "\n")
    for name, value in log.items():
        print(f"{name:<32} {value:>10,}")


if __name__ == "__main__":
    main()
