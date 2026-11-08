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
FEATURES_DIR = DATA_DIR / "features"
OUTPUTS_DIR = BACKEND_DIR / "outputs"
LOGS_DIR = OUTPUTS_DIR / "logs"

# Settings (override in backend/.env, see .env.example)
load_dotenv(BACKEND_DIR / ".env")
DATA_BACKEND = os.getenv("DATA_BACKEND", "duckdb")  # "duckdb" now; "tiger" arrives with SHE-10
APP_DB_PATH = Path(os.getenv("APP_DB_PATH", DATA_DIR / "app.duckdb"))  # uploaded SBOMs
DEMO_DIR = BACKEND_DIR / "demo"

# Granite (SHE-7). Credentials come only from backend/.env; never commit them.
WATSONX_APIKEY = os.getenv("WATSONX_APIKEY", "")
WATSONX_PROJECT_ID = os.getenv("WATSONX_PROJECT_ID", "")
WATSONX_URL = os.getenv("WATSONX_URL", "")
WATSONX_MODEL_ID = os.getenv("WATSONX_MODEL_ID", "ibm/granite-4-h-small")
# Safety cap on watsonx tokens per process run (the free trial quota is small).
WATSONX_TOKEN_BUDGET = int(os.getenv("WATSONX_TOKEN_BUDGET", "50000"))
EMBEDDING_MODEL_ID = os.getenv(
    "EMBEDDING_MODEL_ID", "ibm-granite/granite-embedding-small-english-r2"
)
# CPU speed settings, chosen by the SHE-37 benchmark. Backend: torch, onnx or openvino.
EMBEDDING_MAX_SEQ_LENGTH = int(os.getenv("EMBEDDING_MAX_SEQ_LENGTH", "256"))
EMBEDDING_BACKEND = os.getenv("EMBEDDING_BACKEND", "torch")
EMBEDDING_BATCH_SIZE = int(os.getenv("EMBEDDING_BATCH_SIZE", "32"))
