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

# SBOM queue scoring (predictions.parquet from backend.modeling.serving).
PREDICTIONS_PATH = Path(os.getenv("PREDICTIONS_PATH", FEATURES_DIR / "predictions.parquet"))
# A queue item whose scores describe a month older than this many days is marked stale.
SCORE_STALE_DAYS = int(os.getenv("SCORE_STALE_DAYS", "62"))
# Opt-in: fetch today's EPSS from FIRST (api.first.org) for matched CVEs and re-score.
EPSS_LIVE = os.getenv("EPSS_LIVE", "false").lower() == "true"
# Opt-in: let Granite on watsonx confirm description-only matches (uses tokens).
GRANITE_MATCH_CHECK = os.getenv("GRANITE_MATCH_CHECK", "false").lower() == "true"
MAX_MATCH_CHECKS = int(os.getenv("MAX_MATCH_CHECKS", "25"))  # per SBOM upload

# Opt-in: Granite rewrites the "In plain words" explanation of the top rows of each queue
# (cached per CVE, so each one costs tokens once).
GRANITE_EXPLANATIONS = os.getenv("GRANITE_EXPLANATIONS", "false").lower() == "true"
GRANITE_EXPLAIN_TOP = int(os.getenv("GRANITE_EXPLAIN_TOP", "10"))

# Benchmark-wide numbers for the Insights pages (backend.modeling.insights writes it).
INSIGHTS_PATH = Path(os.getenv("INSIGHTS_PATH", FEATURES_DIR / "insights.json"))

# Push to Linear. The key stays on the backend; never commit it.
LINEAR_API_KEY = os.getenv("LINEAR_API_KEY", "")
LINEAR_TEAM_KEY = os.getenv("LINEAR_TEAM_KEY", "")  # e.g. "SHE"

# The signed-in user shown in the header (there is no login yet).
ME_NAME = os.getenv("ME_NAME", "Jane Doe")
ME_ROLE = os.getenv("ME_ROLE", "Security lead")
ME_AVATAR_URL = os.getenv("ME_AVATAR_URL") or None

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
