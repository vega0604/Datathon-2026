"""SHE-45: checks on the real embeddings. Skipped until
`uv run python -m backend.pipeline.embeddings` has finished (CPU, a few hours)."""

import json

import numpy as np
import pyarrow.parquet as pq
import pytest

from backend.core.config import FEATURES_DIR, LOGS_DIR
from backend.db.warehouse import connect
from backend.pipeline.embeddings import DIMENSIONS, OUTPUT, in_scope_sql

pytestmark = pytest.mark.skipif(
    not OUTPUT.exists(),
    reason="no embeddings: run `uv run python -m backend.pipeline.embeddings` first",
)
EMBEDDINGS = f"read_parquet('{OUTPUT.as_posix()}')"


def test_every_in_scope_description_is_embedded():
    con = connect()
    expected = con.execute(
        f"SELECT count(*) FROM ({in_scope_sql()}) WHERE description IS NOT NULL"
    ).fetchone()[0]
    rows, distinct = con.execute(
        f"SELECT count(*), count(DISTINCT cve_id) FROM {EMBEDDINGS}"
    ).fetchone()
    assert rows == distinct == expected
    log = json.loads((LOGS_DIR / "embeddings_log.json").read_text())
    assert log["embedded"] == expected
    assert log["input"] == expected + log["skipped_blank"]


def test_vectors_are_384_long_and_unit_norm():
    column = pq.read_table(OUTPUT, columns=["embedding"])["embedding"].combine_chunks()
    assert column.type.list_size == DIMENSIONS
    matrix = column.flatten().to_numpy().reshape(len(column), DIMENSIONS)
    norms = np.linalg.norm(matrix, axis=1)
    assert np.allclose(norms, 1.0, atol=1e-3)


def test_manifest_matches_the_log():
    manifest = json.loads((FEATURES_DIR / "embeddings" / "manifest.json").read_text())
    log = json.loads((LOGS_DIR / "embeddings_log.json").read_text())
    assert {key: log[key] for key in manifest} == manifest
