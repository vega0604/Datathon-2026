"""SHE-27 to SHE-33: one feature row per population row, for every fold.

Run after `uv run python -m backend.pipeline.population`:

    uv run python -m backend.pipeline.features

Every feature uses only what was known at the end of the row's snapshot month.
All folds go through the same SQL, so the 2026 benchmark rows are built exactly
like the backtest rows. Writes data/features/features.parquet.
"""

import json

import duckdb

from backend.core.config import FEATURES_DIR, LOGS_DIR
from backend.db.warehouse import connect

FLAGS = ("exploitdb", "metasploit", "nuclei", "poc_github")


def features_parquet(name: str) -> str:
    return f"read_parquet('{(FEATURES_DIR / f'{name}.parquet').as_posix()}')"


def write_parquet(con: duckdb.DuckDBPyConnection, query: str, name: str) -> int:
    FEATURES_DIR.mkdir(parents=True, exist_ok=True)
    path = (FEATURES_DIR / f"{name}.parquet").as_posix()
    con.execute(f"COPY ({query}) TO '{path}' (FORMAT parquet, COMPRESSION zstd)")
    return con.execute(f"SELECT count(*) FROM read_parquet('{path}')").fetchone()[0]


def count(con: duckdb.DuckDBPyConnection, table: str) -> int:
    return con.execute(f"SELECT count(*) FROM {table}").fetchone()[0]


# --- SHE-27: exploit signals at the snapshot -------------------------------------


def signals_at_snapshot_sql(
    src: str, signals: str = "clean.exploit_signals", scoreboard: str = "scoreboard_2026"
) -> str:
    """EPSS and exploit-code flags at the end of the snapshot month. History folds read
    the cleaned monthly signals; the benchmark reads the scoreboard's frozen values.
    No signal row: EPSS stays NULL and the flags are 0, as in the scoreboard."""
    flags = ", ".join(FLAGS)
    flag_columns = ",\n".join(f"coalesce(s.{f}, 0)::UTINYINT AS {f}" for f in FLAGS)
    any_code = " OR ".join(f"coalesce(s.{f}, 0) = 1" for f in FLAGS)
    return f"""
        WITH snapshot_signals AS (
            SELECT cve_id, month AS snapshot_month, epss, {flags} FROM {signals}
            UNION ALL
            SELECT cve_id, snapshot_month, epss, {flags} FROM {scoreboard}
        )
        SELECT
            p.*,
            s.epss,
            {flag_columns},
            CAST({any_code} AS UTINYINT) AS any_exploit_code
        FROM {src} AS p
        LEFT JOIN snapshot_signals AS s
          ON s.cve_id = p.cve_id AND s.snapshot_month = p.snapshot_month
    """


def add_epss_pct_sql(src: str) -> str:
    """EPSS percentile among the same fold's vulnerabilities with the same snapshot month
    (0 = lowest, 1 = highest). The scoreboard can only be ranked against itself, so every
    fold uses the same kind of group. NULL where EPSS is NULL."""
    return f"""
        SELECT
            *,
            CASE
                WHEN epss IS NULL THEN NULL
                ELSE percent_rank() OVER (
                    PARTITION BY fold, snapshot_month, epss IS NULL ORDER BY epss
                )
            END AS epss_pct
        FROM {src}
    """


# --- SHE-28: exposure time --------------------------------------------------------


def add_exposure_sql(src: str) -> str:
    """Days between the snapshot and the fold's label cutoff: how long the vulnerability
    has to reach KEV and still count."""
    return f"SELECT *, date_diff('day', snapshot_end, cutoff) AS days_to_cutoff FROM {src}"


# --- SHE-29: assigner history ------------------------------------------------------


def add_assigner_history_sql(
    src: str, vulns: str = "vulnerabilities", kev: str = "known_exploited"
) -> str:
    """For the vulnerability's assigner (set at publication; the vendor for vendor CNAs),
    as of snapshot_end: KEV entries added so far, vulnerabilities published so far, and
    their ratio. ASOF joins read the latest running total at or before snapshot_end."""
    return f"""
        WITH kev_daily AS (
            SELECT v.assigner, k.date_added AS day, count(*) AS n
            FROM {kev} AS k
            JOIN {vulns} AS v ON v.cve_id = k.cve_id
            GROUP BY ALL
        ),
        kev_running AS (
            SELECT assigner, day, sum(n) OVER (PARTITION BY assigner ORDER BY day) AS total
            FROM kev_daily
        ),
        cve_daily AS (
            SELECT assigner, published AS day, count(*) AS n FROM {vulns} GROUP BY ALL
        ),
        cve_running AS (
            SELECT assigner, day, sum(n) OVER (PARTITION BY assigner ORDER BY day) AS total
            FROM cve_daily
        ),
        scored AS (
            SELECT p.*, v.assigner FROM {src} AS p JOIN {vulns} AS v ON v.cve_id = p.cve_id
        )
        SELECT
            s.*,
            coalesce(kr.total, 0) AS assigner_kev_prior,
            coalesce(cr.total, 0) AS assigner_cves_prior,
            coalesce(kr.total, 0) / nullif(cr.total, 0) AS assigner_kev_rate
        FROM scored AS s
        ASOF LEFT JOIN kev_running AS kr ON kr.assigner = s.assigner AND s.snapshot_end >= kr.day
        ASOF LEFT JOIN cve_running AS cr ON cr.assigner = s.assigner AND s.snapshot_end >= cr.day
    """


# --- SHE-31: severity and weakness type --------------------------------------------

NVD_SOURCE = "nvd@nist.gov"
CVSS3_COLUMNS = (
    "cvss3_score",
    "attack_vector",
    "attack_complexity",
    "privileges_required",
    "user_interaction",
    "scope",
    "confidentiality_impact",
    "integrity_impact",
    "availability_impact",
)


def add_severity_sql(src: str, vulns: str = "vulnerabilities") -> str:
    """CVSS 3 only when the assigner supplied it: NIST's own score appears after its
    analysis, which favours exploited vulnerabilities. Plus CVSS 4, the primary CWE
    ('unknown' if blank or a NIST placeholder) and the number of CWEs."""
    cvss3 = ",\n".join(
        f"CASE WHEN v.cvss3_source = '{NVD_SOURCE}' THEN NULL ELSE v.{c} END AS {c}"
        for c in CVSS3_COLUMNS
    )
    first_cwe = "trim(split_part(coalesce(v.cwe_ids, ''), ';', 1))"
    return f"""
        SELECT
            p.*,
            {cvss3},
            v.cvss4_score,
            CASE
                WHEN {first_cwe} IN ('', 'NVD-CWE-Other', 'NVD-CWE-noinfo') THEN 'unknown'
                ELSE {first_cwe}
            END AS cwe_primary,
            CASE
                WHEN coalesce(v.cwe_ids, '') = '' THEN 0
                ELSE len(string_split(v.cwe_ids, ';'))
            END AS n_cwes
        FROM {src} AS p
        JOIN {vulns} AS v ON v.cve_id = p.cve_id
    """


# --- SHE-32: description keywords ---------------------------------------------------

KEYWORDS = {
    "kw_unauthenticated": "unauthenticated|without authentication|no authentication",
    "kw_remote_code_execution": "remote code execution|execute arbitrary code|code execution",
    "kw_command_injection": "command injection|arbitrary command|os command",
    "kw_pre_auth": "pre-auth|pre-authentication|before authentication",
    "kw_default_config": "default configuration|default install",
    "kw_auth_bypass": "authentication bypass|bypass authentication|bypass the authentication",
    "kw_path_traversal": "path traversal|directory traversal",
    "kw_deserialization": "deserializ",
    "kw_privilege_escalation": "privilege escalation|elevation of privilege|escalate privilege",
    "kw_sql_injection": "sql injection",
    # Descriptions can be edited after an attack: the leakage audit (SHE-54) checks this one.
    "kw_exploited": "exploited|in the wild",
}


def add_keywords_sql(src: str, vulns: str = "vulnerabilities") -> str:
    """0/1 flags for phrases in the description (case-insensitive)."""
    flags = ",\n".join(
        f"CAST(coalesce(regexp_matches(lower(v.description), '{pattern}'), false) AS UTINYINT)"
        f" AS {name}"
        for name, pattern in KEYWORDS.items()
    )
    return f"""
        SELECT p.*, {flags}
        FROM {src} AS p
        JOIN {vulns} AS v ON v.cve_id = p.cve_id
    """


# Applied in order to the population. Each step keeps one row per population row.
FEATURE_STEPS = [
    ("signals", signals_at_snapshot_sql),
    ("epss_pct", add_epss_pct_sql),
    ("exposure", add_exposure_sql),
    ("assigner_history", add_assigner_history_sql),
    ("severity", add_severity_sql),
    ("keywords", add_keywords_sql),
]


def build_features(con: duckdb.DuckDBPyConnection, log: dict[str, int]) -> int:
    con.execute(
        f"CREATE OR REPLACE TEMP TABLE features AS SELECT * FROM {features_parquet('population')}"
    )
    log["population"] = count(con, "features")
    for name, step in FEATURE_STEPS:
        con.execute(f"CREATE OR REPLACE TEMP TABLE features_next AS {step('features')}")
        con.execute("DROP TABLE features")
        con.execute("ALTER TABLE features_next RENAME TO features")
        log[f"after_{name}"] = count(con, "features")
    columns = [row[0] for row in con.execute("DESCRIBE features").fetchall()]
    log["columns"] = len(columns)
    return write_parquet(con, "SELECT * FROM features ORDER BY fold, cve_id", "features")


def main() -> None:
    if not (FEATURES_DIR / "population.parquet").exists():
        raise SystemExit("No population. Run `uv run python -m backend.pipeline.population` first.")
    con = connect()
    log: dict[str, int] = {}
    log["features"] = build_features(con, log)
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    (LOGS_DIR / "features_log.json").write_text(json.dumps(log, indent=2) + "\n")
    for name, value in log.items():
        print(f"{name:<32} {value:>10,}")


if __name__ == "__main__":
    main()
