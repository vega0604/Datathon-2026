"""SHE-35: score any ranking of a backtest fold the way the judges score the benchmark.

    from backend.modeling.evaluate import evaluate, ranked_sql
    ranking = ranked_sql(source, fold=2025, order_by="score DESC")
    evaluate(con, 2025, ranking)

The benchmark asks for the top 500 of 72,670 vulnerabilities. A fold of a different size
is graded at the same pick rate (the scaled K), and also at a flat 500.
"""

import duckdb

from backend.core.config import FEATURES_DIR

BENCHMARK_ROWS = 72_670
BENCHMARK_PICKS = 500


def scaled_k(rows: int) -> int:
    """Top-K with the benchmark's pick rate (500 of 72,670)."""
    return round(BENCHMARK_PICKS * rows / BENCHMARK_ROWS)


def population_parquet() -> str:
    return f"read_parquet('{(FEATURES_DIR / 'population.parquet').as_posix()}')"


def ranked_sql(source: str, fold: int, order_by: str) -> str:
    """Rank one fold of `source` (a table name or subquery) by `order_by`. Ties are broken
    by cve_id, so the same ranking always gets the same score."""
    return f"""
        SELECT cve_id, row_number() OVER (ORDER BY {order_by}, cve_id) AS rank
        FROM {source} AS ranked_source
        WHERE fold = {fold}
    """


def evaluate(
    con: duckdb.DuckDBPyConnection,
    fold: int,
    ranking: str,
    population: str | None = None,
    k: int | None = None,
) -> dict:
    """Score `ranking` (a query returning cve_id and rank, 1 = fix first) on a labelled fold."""
    population = population or population_parquet()
    rows, positives = con.execute(
        f"SELECT count(*), sum(label) FROM {population} WHERE fold = {fold}"
    ).fetchone()
    if rows == 0 or positives is None:
        raise ValueError(f"Fold {fold} has no labelled rows; only backtest folds can be scored.")
    ranked_rows = con.execute(f"SELECT count(DISTINCT cve_id) FROM ({ranking})").fetchone()[0]
    if ranked_rows != rows:
        raise ValueError(f"Ranking covers {ranked_rows} vulnerabilities; fold {fold} has {rows}.")
    k = scaled_k(rows) if k is None else k
    hits_k, hits_500 = con.execute(
        f"""
        SELECT
            count(*) FILTER (WHERE r.rank <= {k} AND p.label = 1),
            count(*) FILTER (WHERE r.rank <= {BENCHMARK_PICKS} AND p.label = 1)
        FROM ({ranking}) AS r
        JOIN {population} AS p ON p.cve_id = r.cve_id AND p.fold = {fold}
        """
    ).fetchone()
    positives = int(positives)
    return {
        "fold": fold,
        "rows": rows,
        "positives": positives,
        "k": k,
        "hits_at_k": hits_k,
        "hits_at_500": hits_500,
        "precision_at_500": hits_500 / BENCHMARK_PICKS,
        "recall_at_k": hits_k / positives if positives else 0.0,
    }


def evaluate_frame(
    con: duckdb.DuckDBPyConnection,
    fold: int,
    scores,
    order_by: str = "score DESC NULLS LAST",
    population: str | None = None,
) -> dict:
    """Score a pandas DataFrame with cve_id and the columns in `order_by` (higher first),
    holding one fold's rows. Ties fall to cve_id, as in ranked_sql."""
    cursor = con.cursor()  # its own registration, closed with it
    try:
        cursor.register("_scores_frame", scores.assign(fold=fold))
        return evaluate(
            cursor, fold, ranked_sql("_scores_frame", fold, order_by), population=population
        )
    finally:
        cursor.close()
