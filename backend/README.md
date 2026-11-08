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

## Fix-First queue for an SBOM

One request uploads a CycloneDX SBOM (JSON) and returns its ranked queue:

```bash
uv run uvicorn backend.api.app:app --reload
curl -F "file=@demo/acme_sbom.cdx.json" "http://127.0.0.1:8000/api/sboms/fix-first?limit=20"
```

PowerShell: `curl.exe -F "file=@demo/acme_sbom.cdx.json" "http://127.0.0.1:8000/api/sboms/fix-first?limit=20"`.
Later pages: `GET /api/sboms/{sbom_id}/queue?limit=20&offset=20`.

How it works:

1. **Matching.** Components match vulnerabilities through NIST's product lists (CPE or purl, with version ranges), and, for vulnerabilities NIST hasn't analysed yet (no product list), through their description (`match_methods: ["description"]`, version unverified). Set `GRANITE_MATCH_CHECK=true` to let Granite on watsonx confirm or drop description matches (at most `MAX_MATCH_CHECKS` per upload).
2. **Ranking.** Vulnerabilities on CISA KEV first, then `score`: the submitted ranking (LightGBM rank-blended with the safety ranker) from `data/features/predictions.parquet`, on one scale for every vulnerability. Each item has up to 3 `reasons`, `p_exploit` (the model's rough chance), `basis` and `as_of` (the month the scores describe) and `stale` (older than `SCORE_STALE_DAYS`).
3. **Freshness.** `EPSS_LIVE=true` fetches today's EPSS for the matched CVEs from FIRST (`api.first.org`) and re-ranks with `score_live`. To refresh everything after new monthly signal files arrive: rerun `pipeline.clean`, `pipeline.features`, then `uv run python -m backend.modeling.serving`.

Without `predictions.parquet` the queue falls back to a placeholder ranking (KEV, EPSS, CVSS): build it with `uv run python -m backend.modeling.select` (or `serving`).

## Endpoints for the frontend

Everything the React app reads (see the frontend API handoff). Build the data once:
`uv run python -m backend.modeling.select` (models, `predictions.parquet`), then
`uv run python -m backend.modeling.insights` (`insights.json`).

| Method and path | What it returns |
| --- | --- |
| `GET /api/sboms/{id}/queue` | Queue rows (default `limit` 1000, `offset`) with `total` and `counts` for the whole queue, and per row: rank, component, score, severity, CVSS rank, warning `signal`, `status`, Linear `ticket`, plain-words `explanation`, 3 `reasons` bars (`kind`, `label`, SHAP `value`), KEV and CWE facts. Optional `q` (CVE id or component name), `view` (`all`, `critical`, `not_in_linear`, `warning_signs`) and `sort` (`rank`, `cvss_desc`, `cvss_asc`) run over every row; `matched` counts the rows they select. The full queue is cached per SBOM for 5 minutes and dropped on every write |
| `PATCH /api/sboms/{id}/queue/{cve_id}` | `{"status": "to_do" \| "in_progress" \| "done"}`; returns the updated row |
| `POST /api/sboms/{id}/queue/{cve_id}/linear` | Creates the Linear issue (201) or returns the existing one (200); 502 if Linear isn't set up or fails |
| `POST /api/sboms` | Upload CycloneDX JSON or XML (max 10 MB, 413 above); returns the SBOM with every component and its `risk`. Same filename replaces the earlier upload |
| `GET /api/sboms` | Saved SBOMs, newest first |
| `GET /api/sboms/{id}/components` | The SBOM with `spec_version`, `risk_checked`, `cve_total` (distinct CVEs) and each component's `part`, `rank`, `match_methods` and `risk` (CVE count, severity mix, max CVSS and EPSS, `fixed_in`, KEV entries, top 3 CVEs). `uploaded_at` is UTC (`Z`) |
| `DELETE /api/sboms/{id}` | 204; removes its components, matches, statuses and tickets |
| `GET /api/insights/summary`, `/catch-rate`, `/vendors` | The Insights pages, from `insights.json`. If it's missing, the API builds it in the background at startup (about 30 s; `INSIGHTS_BUILD_ON_START=false` turns that off) and answers 503 until it's written |
| `GET /api/benchmark` | The "About this data" facts |
| `GET /api/me` | The header user, from `ME_NAME` / `ME_ROLE` / `ME_AVATAR_URL` (no login yet) |

Settings in `backend/.env` (see `.env.example`): `LINEAR_API_KEY` and `LINEAR_TEAM_KEY` for Push to Linear; `GRANITE_EXPLANATIONS=true` to let Granite write the explanation of the top `GRANITE_EXPLAIN_TOP` rows of each queue (cached per CVE). There is no IBM X-Force integration: `xforce` is always `null`, so the panel shows the KEV facts.

Warning signs (`signal`, the first that applies at the row's `as_of` month): `exploit_code` (public exploit code appeared that month), `vendor_attacked` (another CVE in one of the same vulnerable products went onto KEV in the 30 days before), `score_jump` (EPSS rose by 0.1 or more since the month before).

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
