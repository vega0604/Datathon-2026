"""SHE-46: how similar is each vulnerability to the ones already on KEV at its snapshot?

    uv run python -m backend.pipeline.similarity

For a population row with snapshot_end S, the reference set is every KEV entry added on
or before S, minus the row's own cve_id. kev_sim_max is the highest cosine similarity to
that set, kev_sim_top5 the mean of the 5 highest (all of them if fewer). Both are NULL
when the row has no embedding (or no reference exists). Writes
data/features/similarity.parquet: one row per population row.
"""

import json
import time

import numpy as np
import pandas as pd
import pyarrow.parquet as pq

from backend.core.config import FEATURES_DIR, LOGS_DIR
from backend.db.warehouse import connect

TOP_N = 5
ROW_BLOCK = 8_192  # rows per matrix product, to bound memory
OUTPUT = FEATURES_DIR / "similarity.parquet"


def top_scores(sims: np.ndarray, top_n: int = TOP_N) -> tuple[np.ndarray, np.ndarray]:
    """Row-wise max and mean of the top `top_n` finite values; -inf marks an excluded
    reference. NaN where a row has no finite value."""
    if sims.shape[1] == 0:
        nan = np.full(sims.shape[0], np.nan)
        return nan, nan.copy()
    k = min(top_n, sims.shape[1])
    top = -np.partition(-sims, k - 1, axis=1)[:, :k]
    finite = np.isfinite(top)
    counts = finite.sum(axis=1)
    total = np.where(finite, top, 0.0).sum(axis=1)
    with np.errstate(invalid="ignore", divide="ignore"):
        mean = np.where(counts > 0, total / counts, np.nan)
    best = np.where(counts > 0, np.where(finite, top, -np.inf).max(axis=1), np.nan)
    return best, mean


def kev_similarity(
    population: pd.DataFrame,
    vectors: dict[str, np.ndarray],
    kev: pd.DataFrame,
    top_n: int = TOP_N,
) -> pd.DataFrame:
    """population: cve_id, fold, snapshot_end. vectors: cve_id -> unit vector.
    kev: cve_id, date_added. Returns cve_id, fold, kev_sim_max, kev_sim_top5 in
    population order."""
    kev = kev[kev["cve_id"].isin(vectors.keys())].sort_values(["date_added", "cve_id"])
    kev_ids = kev["cve_id"].to_numpy()
    kev_dates = kev["date_added"].to_numpy(dtype="datetime64[D]")
    dims = len(next(iter(vectors.values()))) if vectors else 0
    kev_matrix = (
        np.stack([vectors[c] for c in kev_ids]).astype(np.float32)
        if len(kev_ids)
        else np.zeros((0, dims), np.float32)
    )
    kev_position = {cve: i for i, cve in enumerate(kev_ids)}

    best = np.full(len(population), np.nan)
    mean = np.full(len(population), np.nan)
    ids = population["cve_id"].to_numpy()
    ends = population["snapshot_end"].to_numpy(dtype="datetime64[D]")
    has_vector = np.array([cve in vectors for cve in ids], dtype=bool)
    for end in np.unique(ends):
        n_refs = int(np.searchsorted(kev_dates, end, side="right"))  # date_added <= end
        refs = kev_matrix[:n_refs]
        rows = np.flatnonzero((ends == end) & has_vector)
        for start in range(0, len(rows), ROW_BLOCK):
            block = rows[start : start + ROW_BLOCK]
            matrix = np.stack([vectors[c] for c in ids[block]]).astype(np.float32)
            sims = matrix @ refs.T
            for i, cve in enumerate(ids[block]):
                own = kev_position.get(cve)
                if own is not None and own < n_refs:
                    sims[i, own] = -np.inf
            # float32 dot products of unit vectors can land a hair outside [-1, 1].
            best[block], mean[block] = (np.clip(s, -1.0, 1.0) for s in top_scores(sims, top_n))
    return pd.DataFrame(
        {
            "cve_id": ids,
            "fold": population["fold"].to_numpy(),
            "kev_sim_max": best,
            "kev_sim_top5": mean,
        }
    )


def load_vectors(path) -> dict[str, np.ndarray]:
    """cve_id -> embedding, read straight from Arrow (no per-row Python lists)."""
    table = pq.read_table(path, columns=["cve_id", "embedding"])
    column = table["embedding"].combine_chunks()
    matrix = column.flatten().to_numpy().reshape(len(column), column.type.list_size)
    return dict(zip(table["cve_id"].to_pylist(), matrix.astype(np.float32), strict=True))


def main() -> None:
    embeddings = FEATURES_DIR / "embeddings.parquet"
    if not embeddings.exists():
        raise SystemExit("No embeddings. Run `uv run python -m backend.pipeline.embeddings` first.")
    start = time.perf_counter()
    con = connect()
    population = con.execute(
        "SELECT cve_id, fold, snapshot_end "
        f"FROM read_parquet('{(FEATURES_DIR / 'population.parquet').as_posix()}')"
    ).df()
    vectors = load_vectors(embeddings)
    kev = con.execute("SELECT cve_id, date_added FROM known_exploited").df()
    result = kev_similarity(population, vectors, kev)
    result.to_parquet(OUTPUT, index=False, compression="zstd")
    log = {
        "rows": len(result),
        "rows_with_similarity": int(result["kev_sim_max"].notna().sum()),
        "kev_references": int(kev["cve_id"].isin(vectors.keys()).sum()),
        "snapshot_ends": int(population["snapshot_end"].nunique()),
        "seconds": round(time.perf_counter() - start, 1),
    }
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    (LOGS_DIR / "similarity_log.json").write_text(json.dumps(log, indent=2) + "\n")
    for name, value in log.items():
        print(f"{name:<24} {value:>10,}" if isinstance(value, int) else f"{name:<24} {value}")


if __name__ == "__main__":
    main()
