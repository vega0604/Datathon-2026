# Backend

Data pipeline, ranking model, Granite enrichment and dashboard for **Before the Breach** (IBM track, Sheridan Datathon 2026). Managed with [uv](https://docs.astral.sh/uv/).

## Setup

1. **Install uv** (once per machine):

   ```powershell
   # Windows (PowerShell)
   powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
   ```

   ```bash
   # macOS / Linux
   curl -LsSf https://astral.sh/uv/install.sh | sh
   ```

2. **Install the project.** From this `backend/` folder:

   ```bash
   uv sync
   ```

   This downloads Python 3.12 if you don't have it, creates `.venv/`, and installs everything pinned in `uv.lock`. You don't need to activate the venv; prefix commands with `uv run`.

   The Granite group (torch, transformers) is a large download. If you're only working on the dashboard or data cleaning, skip it:

   ```bash
   uv sync --no-group granite
   ```

3. **Add the data.** Unzip `data.zip` into `backend/data/raw/` so you have `backend/data/raw/vulnerabilities.csv` and the other 7 CSVs. This folder is gitignored; never commit data.

4. **Check it works:**

   ```bash
   uv run backend
   uv run pytest
   ```

## Everyday commands

| Task | Command |
| --- | --- |
| Run a module | `uv run python -m backend.pipeline.load` |
| Run the API | `uv run uvicorn backend.api.app:app --reload` (docs at `/docs`) |
| Run tests | `uv run pytest` |
| Run tests that need no data | `uv run pytest tests/unit` |
| Rebuild the data | `uv run python -m backend.pipeline.load`, then `uv run python -m backend.pipeline.clean` |
| Lint and format | `uv run ruff check .` / `uv run ruff format .` |
| Add a package | `uv add polars` (or `uv add --group granite peft`) |
| Remove a package | `uv remove polars` |
| Update after pulling | `uv sync` |
| Use in Jupyter / VS Code | Select the `backend/.venv` interpreter as the kernel |

Always add packages with `uv add`, never `pip install`, so `pyproject.toml` and `uv.lock` stay in sync. Commit both files whenever they change.

## Dependency groups

| Group | What it's for | Story |
| --- | --- | --- |
| *(core)* | duckdb, polars, pandas, pyarrow, scikit-learn, lightgbm, shap, plotly | everyone |
| `dev` | pytest, ruff, ipykernel | everyone |
| `granite` | torch, transformers, sentence-transformers | SHE-7 |
| `app` | empty: the API dependencies (fastapi, uvicorn) are in core and Streamlit is gone | SHE-78 |
| `tiger` | psycopg | SHE-10 |

`uv sync` installs all groups by default. Skip one with `--no-group <name>`.

## Layout

```text
backend/
├── pyproject.toml          # dependencies and tool config
├── uv.lock                 # exact versions; commit it
├── .python-version         # 3.12
├── src/backend/            # the Python package
│   ├── core/config.py      # paths shared by everything
│   ├── db/warehouse.py     # connect(): one DuckDB connection over data/parquet and data/clean
│   └── pipeline/           # offline data jobs, run with `uv run python -m ...`
│       ├── load.py         #   raw CSVs -> data/parquet
│       └── clean.py        #   data/parquet -> data/clean
├── tests/
│   ├── unit/               # no data needed; runs anywhere
│   └── data/               # checks on the real data; skipped until it's built
├── notebooks/              # exploration (numbered: 01_sanity.ipynb, ...)
├── data/                   # gitignored: raw/, parquet/, clean/
└── outputs/                # generated results; only top500.csv and charts/*.png are committed
```

### Where new code goes

The REST API for the frontend dashboard will be FastAPI, inside this same package. Create each folder only when the first code that needs it lands.

| Code | Goes in | Rule |
| --- | --- | --- |
| API app and routers | `src/backend/api/` (`app.py`, `routes/<resource>.py`) | Routes parse requests and call services. No SQL in routes. |
| Business logic (ranking, SBOM matching, alerts) | `src/backend/services/` | Plain functions that take a DuckDB connection. No FastAPI imports, so they're testable without a server. |
| Request and response models | `src/backend/schemas/` | Pydantic models. |
| Data access | `src/backend/db/` | The only place that opens connections. The API gets one per request through a dependency that calls `warehouse.connect()`. |
| Offline jobs | `src/backend/pipeline/` | Batch steps that write files. Never imported by the API. |
| Paths and settings | `src/backend/core/config.py` | |

## Git workflow

One story = one branch, one sub-issue = one commit, prefixed with the Linear ID:

```bash
git commit -m "SHE-16 feat(data): convert raw CSVs to Parquet"
```

See the project plan for every story and commit.
