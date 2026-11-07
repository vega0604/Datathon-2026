import os
import psycopg
from dotenv import load_dotenv

load_dotenv()

def get_connection():
    """Returns a connection to Tiger Data (Timescale Cloud)."""
    return psycopg.connect(
        host=os.getenv("TIGER_HOST", "localhost"),
        port=os.getenv("TIGER_PORT", "5432"),
        dbname=os.getenv("TIGER_DB", "tigerdata"),
        user=os.getenv("TIGER_USER", "postgres"),
        password=os.getenv("TIGER_PASSWORD", "postgres"),
        sslmode=os.getenv("TIGER_SSLMODE", "prefer"),
        autocommit=True
    )

if __name__ == "__main__":
    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT version();")
                print("[Tiger Data Connected]:", cur.fetchone()[0])
    except Exception as e:
        print("[Connection Error]:", e)
