"""
SHE-75: Migration Runner for Tiger Data / Timescale Cloud.
Applies schema migrations sequentially in an idempotent manner.
"""
import os
import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.db import get_connection


def run_all_migrations():
    """Discovers and executes SQL migrations in numerical order."""
    migrations_dir = PROJECT_ROOT / "src" / "migrations"
    migration_files = sorted(migrations_dir.glob("*.sql"))

    if not migration_files:
        print("[!] No migration files found in src/migrations/")
        return

    print(f"[*] Found {len(migration_files)} migration files.")

    with get_connection() as conn:
        with conn.cursor() as cur:
            for sql_path in migration_files:
                filename = sql_path.name
                print(f"[*] Applying migration: {filename}...")
                with open(sql_path, "r", encoding="utf-8") as f:
                    sql_content = f.read()
                cur.execute(sql_content)
                print(f"[+] Successfully applied: {filename}")
        conn.commit()

    print("[SUCCESS] All Tiger Data migrations successfully executed.")


if __name__ == "__main__":
    run_all_migrations()