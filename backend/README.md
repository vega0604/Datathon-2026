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
| Run tests | `uv run pytest` |
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
| `app` | streamlit | SHE-11 |
| `tiger` | psycopg | SHE-10 |

`uv sync` installs all groups by default. Skip one with `--no-group <name>`.

## Layout

```
backend/
├── pyproject.toml      # dependencies and tool config
├── uv.lock             # exact versions; commit it
├── .python-version     # 3.12
├── src/backend/        # the Python package: load, clean, features, model, granite, ...
├── tests/              # pytest tests
├── notebooks/          # exploration (numbered: 01_sanity.ipynb, ...)
├── data/               # gitignored: raw/ for the CSVs, parquet/ for converted files
└── outputs/            # generated results; only top500.csv and charts/*.png are committed
```

## Git workflow

One story = one branch, one sub-issue = one commit, prefixed with the Linear ID:

```bash
git commit -m "SHE-16 feat(data): convert raw CSVs to Parquet"
```

See the project plan for every story and commit.
