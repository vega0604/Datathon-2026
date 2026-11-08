"""Project folders. Everything is resolved from this file, so scripts and notebooks
work from any working directory."""

import os
from pathlib import Path

from dotenv import load_dotenv

BACKEND_DIR = Path(__file__).resolve().parents[3]  # src/backend/core/config.py -> backend/
DATA_DIR = BACKEND_DIR / "data"
RAW_DIR = DATA_DIR / "raw"  # the 8 CSVs from data.zip (gitignored)
PARQUET_DIR = DATA_DIR / "parquet"  # typed copies of the raw CSVs (SHE-16)
CLEAN_DIR = DATA_DIR / "clean"  # cleaned tables (SHE-18 to SHE-22)
OUTPUTS_DIR = BACKEND_DIR / "outputs"
LOGS_DIR = OUTPUTS_DIR / "logs"

# Settings (override in backend/.env, see .env.example)
load_dotenv(BACKEND_DIR / ".env")
DATA_BACKEND = os.getenv("DATA_BACKEND", "duckdb")  # "duckdb" now; "tiger" arrives with SHE-10
APP_DB_PATH = Path(os.getenv("APP_DB_PATH", DATA_DIR / "app.duckdb"))  # uploaded SBOMs
