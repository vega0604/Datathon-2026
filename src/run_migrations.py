import os
import glob
from src.db import get_connection

def run_all_migrations():
    migration_files = sorted(glob.glob("src/migrations/*.sql"))
    if not migration_files:
        print("[!] No migration files found in src/migrations/")
        return

    with get_connection() as conn:
        with conn.cursor() as cur:
            for sql_path in migration_files:
                filename = os.path.basename(sql_path)
                print(f"[*] Applying migration: {filename}...")
                with open(sql_path, "r", encoding="utf-8") as f:
                    cur.execute(f.read())
                print(f"[+] Successfully applied: {filename}")
        conn.commit()
    print("[SUCCESS] All Tiger Data migrations successfully executed.")

if __name__ == "__main__":
    run_all_migrations()