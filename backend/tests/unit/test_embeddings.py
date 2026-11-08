"""Unit tests for the SHE-45 chunking, resume and settings guard. A fake encoder stands in
for Granite: no model is loaded."""

import json

import duckdb
import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from backend.pipeline import embeddings as em

SETTINGS = {"model": "granite", "backend": "torch", "max_seq_length": 256}


class FakeEncoder:
    """Returns fixed unit vectors and counts how many texts it was asked to encode."""

    def __init__(self, dims=4):
        self.dims = dims
        self.calls = []

    def __call__(self, texts):
        self.calls.append(len(texts))
        vectors = np.zeros((len(texts), self.dims), dtype=np.float32)
        vectors[:, 0] = 1.0
        return vectors


def rows(n):
    return [(f"CVE-{i:04d}", f"description {i}") for i in range(n)]


def test_chunk_sizes():
    assert [len(c) for c in em.chunk(list(range(12)), 5)] == [5, 5, 2]
    assert em.chunk([], 5) == []


def test_parts_hold_ids_and_vectors(tmp_path):
    em.prepare_parts_dir(tmp_path, SETTINGS)
    stats = em.embed_in_chunks(rows(7), FakeEncoder(), tmp_path, size=3, progress=lambda _: None)
    assert stats["chunks"] == 3
    assert stats["chunks_encoded"] == 3
    table = pq.read_table(em.part_path(tmp_path, 0))
    assert table["cve_id"].to_pylist() == ["CVE-0000", "CVE-0001", "CVE-0002"]
    assert table.schema.field("embedding").type.list_size == 4
    merged = tmp_path / "all.parquet"
    assert em.merge_parts(duckdb.connect(), tmp_path, merged) == 7


def test_resume_skips_finished_chunks(tmp_path):
    em.prepare_parts_dir(tmp_path, SETTINGS)
    em.embed_in_chunks(rows(7), FakeEncoder(), tmp_path, size=3, progress=lambda _: None)
    em.part_path(tmp_path, 1).unlink()  # as if the run died during chunk 2
    encoder = FakeEncoder()
    em.prepare_parts_dir(tmp_path, SETTINGS)
    stats = em.embed_in_chunks(rows(7), encoder, tmp_path, size=3, progress=lambda _: None)
    assert encoder.calls == [3]  # only the missing chunk is encoded again
    assert stats["chunks_resumed"] == 2
    assert stats["rows_encoded_this_run"] == 3


def test_changed_settings_refuse_to_resume(tmp_path):
    em.prepare_parts_dir(tmp_path, SETTINGS)
    em.embed_in_chunks(rows(4), FakeEncoder(), tmp_path, size=3, progress=lambda _: None)
    with pytest.raises(em.SettingsChanged, match="Delete"):
        em.prepare_parts_dir(tmp_path, {**SETTINGS, "max_seq_length": 512})
    assert em.part_path(tmp_path, 0).exists()  # nothing was deleted


def unit_rows(n, dims=em.DIMENSIONS):
    matrix = np.random.default_rng(0).normal(size=(n, dims)).astype(np.float32)
    return matrix / np.linalg.norm(matrix, axis=1, keepdims=True)


def test_check_vectors_accepts_a_good_file():
    ids = ["CVE-1", "CVE-2", "CVE-3"]
    em.check_vectors(ids, unit_rows(3), expected_ids=ids)


def test_check_vectors_lists_every_problem():
    matrix = unit_rows(3)
    matrix[0] *= 2  # not normalised
    with pytest.raises(em.ImportCheckFailed) as error:
        em.check_vectors(["CVE-1", "CVE-1", "CVE-9"], matrix, ["CVE-1", "CVE-2"])
    message = str(error.value)
    assert "3 rows; the export has 2" in message
    assert "1 duplicate" in message
    assert "1 exported ids missing" in message
    assert "norm away from 1" in message


def test_check_vectors_rejects_wrong_dimensions():
    with pytest.raises(em.ImportCheckFailed, match="expected"):
        em.check_vectors(["CVE-1"], unit_rows(1, dims=768), ["CVE-1"])


def test_read_embeddings_fixed_and_plain_lists(tmp_path):
    fixed = tmp_path / "fixed.parquet"
    em.write_part(fixed, ["CVE-1", "CVE-2"], unit_rows(2))
    ids, matrix, _ = em.read_embeddings(fixed)
    assert ids == ["CVE-1", "CVE-2"]
    assert matrix.shape == (2, em.DIMENSIONS)
    plain = tmp_path / "plain.parquet"
    table = pa.table({"cve_id": ["CVE-1"], "embedding": [unit_rows(1)[0].tolist()]})
    table = table.replace_schema_metadata({b"backend": b"torch-cuda", b"seconds": b"12.5"})
    pq.write_table(table, plain)
    ids, matrix, metadata = em.read_embeddings(plain)
    assert matrix.shape == (1, em.DIMENSIONS)
    assert metadata == {"backend": "torch-cuda", "seconds": "12.5"}


def test_check_sample_is_fixed():
    rows = [(f"CVE-{i:05d}", f"text {i}") for i in range(1_000)]
    sample = em.sample_rows(rows)
    assert len(sample) == em.CHECK_SAMPLE
    assert sample == em.sample_rows(list(reversed(rows)))  # order of the input doesn't matter


def test_parts_without_a_manifest_are_deleted(tmp_path):
    em.write_part(em.part_path(tmp_path, 0), ["CVE-OLD"], np.ones((1, 4)))
    assert em.prepare_parts_dir(tmp_path, SETTINGS) == 1
    assert not em.part_path(tmp_path, 0).exists()
    assert json.loads((tmp_path / em.MANIFEST).read_text()) == SETTINGS
