"""
SHE-76: Monthly Vendor Activity Analytics.
Provides management and fast analytical queries for the vendor_monthly_activity aggregate.
"""
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional
from src.db import get_connection

logger = logging.getLogger(__name__)

MIGRATION_PATH = Path(__file__).resolve().parent / "migrations" / "05_vendor_aggregates.sql"


def ensure_vendor_aggregates() -> None:
    """Ensures the vendor_monthly_activity materialized view and indexes exist in Tiger Data."""
    if not MIGRATION_PATH.exists():
        raise FileNotFoundError(f"Migration file not found: {MIGRATION_PATH}")

    with open(MIGRATION_PATH, "r", encoding="utf-8") as f:
        sql = f.read()

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql)
        conn.commit()
    logger.info("Ensured vendor_monthly_activity aggregate exists.")


def refresh_vendor_activity(concurrently: bool = False) -> None:
    """
    Refreshes the vendor_monthly_activity materialized view.
    If concurrently is True, refreshes without locking concurrent SELECT operations
    (requires unique index and populated view).
    """
    concurrent_clause = "CONCURRENTLY" if concurrently else ""
    query = f"REFRESH MATERIALIZED VIEW {concurrent_clause} vendor_monthly_activity;"

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(query)
        conn.commit()
    logger.info(f"Refreshed vendor_monthly_activity (concurrently={concurrently}).")


def get_top_active_vendors(limit: int = 10) -> List[Dict[str, Any]]:
    """
    Retrieves the top active vendors based on exploit code appearances and KEV additions.
    """
    query = """
    SELECT 
        vendor,
        SUM(kev_additions) AS total_kev_additions,
        SUM(cves_with_exploit_code) AS total_exploited_cves,
        SUM(total_exploitdb_hits + total_metasploit_hits + total_nuclei_hits + total_poc_github_hits) AS total_exploit_hits,
        MAX(activity_month) AS latest_activity_month
    FROM vendor_monthly_activity
    GROUP BY vendor
    ORDER BY total_exploited_cves DESC, total_kev_additions DESC
    LIMIT %(limit)s;
    """
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(query, {"limit": limit})
            columns = [desc[0] for desc in cur.description]
            return [dict(zip(columns, row)) for row in cur.fetchall()]


def get_vendor_trend(vendor: str) -> List[Dict[str, Any]]:
    """
    Retrieves the month-by-month exploit and KEV trend for a specific vendor.
    """
    query = """
    SELECT 
        vendor,
        activity_month,
        kev_additions,
        monitored_cves,
        cves_with_exploit_code,
        total_poc_github_hits,
        avg_epss
    FROM vendor_monthly_activity
    WHERE LOWER(vendor) = LOWER(%(vendor)s)
    ORDER BY activity_month ASC;
    """
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(query, {"vendor": vendor.strip().lower()})
            columns = [desc[0] for desc in cur.description]
            return [dict(zip(columns, row)) for row in cur.fetchall()]


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    print("[*] Initializing and verifying vendor monthly activity aggregates...")
    ensure_vendor_aggregates()
    refresh_vendor_activity()
    top_vendors = get_top_active_vendors(limit=5)
    print(f"[+] Top active vendors retrieved: {top_vendors}")
