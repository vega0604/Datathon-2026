"""Project folders. Everything is resolved from this file, so scripts and notebooks
work from any working directory."""

from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[2]  # src/backend/paths.py -> backend/
DATA_DIR = BACKEND_DIR / "data"
RAW_DIR = DATA_DIR / "raw"  # the 8 CSVs from data.zip (gitignored)
PARQUET_DIR = DATA_DIR / "parquet"  # typed copies of the raw CSVs (SHE-16)
CLEAN_DIR = DATA_DIR / "clean"  # cleaned tables (SHE-18 to SHE-22)
OUTPUTS_DIR = BACKEND_DIR / "outputs"
LOGS_DIR = OUTPUTS_DIR / "logs"
