"""SHE-45: a Granite embedding for every in-scope vulnerability description.

In scope: the distinct vulnerabilities in population.parquet plus every KEV entry (the
similarity reference set). The result is data/features/embeddings.parquet
(cve_id, embedding FLOAT[384]). Two ways to build it:

On a Colab GPU (minutes; see scripts/colab_embed.py):

    uv run python -m backend.pipeline.embeddings --export     # writes embed_input.parquet
    # run scripts/colab_embed.py on Colab, download embeddings.parquet, then:
    uv run python -m backend.pipeline.embeddings --import path/to/embeddings.parquet

--import checks the row count, ids, dimensions and norms, re-embeds a fixed 200-row
sample locally (mean cosine must be >= 0.99), then installs the file.

Locally on CPU (hours):

    uv run python -m backend.pipeline.embeddings

Work is checkpointed in chunks of 5,000 sorted by cve_id under data/features/embeddings/;
a rerun skips finished chunks. The model settings are written to
data/features/embeddings/manifest.json, and a rerun with different settings stops rather
than mixing vectors; delete the folder to start over.
"""

import argparse
import json
import random
import time
from collections.abc import Callable, Sequence
from pathlib import Path

import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq

from backend.core import config
from backend.core.config import FEATURES_DIR, LOGS_DIR
from backend.db.warehouse import connect
from backend.pipeline.granite_benchmark import MIN_COSINE, mean_cosine

CHUNK_SIZE = 5_000
DIMENSIONS = 384
PARTS_DIR = FEATURES_DIR / "embeddings"
MANIFEST = "manifest.json"
OUTPUT = FEATURES_DIR / "embeddings.parquet"
EXPORT_INPUT = FEATURES_DIR / "embed_input.parquet"
NORM_TOLERANCE = 1e-3
CHECK_SAMPLE = 200
CHECK_SEED = 45

Encoder = Callable[[list[str]], np.ndarray]


class SettingsChanged(RuntimeError):
    pass


def current_settings() -> dict:
    return {
        "model": config.EMBEDDING_MODEL_ID,
        "backend": config.EMBEDDING_BACKEND,
        "max_seq_length": config.EMBEDDING_MAX_SEQ_LENGTH,
    }


def in_scope_sql() -> str:
    """Distinct population vulnerabilities plus every KEV entry, with their description
    (NULL when the description is missing or blank)."""
    population = (FEATURES_DIR / "population.parquet").as_posix()
    return f"""
        SELECT s.cve_id, nullif(trim(v.description), '') AS description
        FROM (
            SELECT cve_id FROM read_parquet('{population}')
            UNION
            SELECT cve_id FROM known_exploited
        ) AS s
        LEFT JOIN vulnerabilities AS v USING (cve_id)
        ORDER BY s.cve_id
    """


def chunk(rows: Sequence, size: int = CHUNK_SIZE) -> list[Sequence]:
    return [rows[i : i + size] for i in range(0, len(rows), size)]


def part_path(parts_dir: Path, n: int) -> Path:
    return parts_dir / f"part-{n:04d}.parquet"


def prepare_parts_dir(parts_dir: Path, settings: dict) -> int:
    """Make sure every part in `parts_dir` was built with `settings`. Parts from a run with
    no manifest are deleted; a manifest with other settings stops the run. Returns the
    number of stale parts deleted."""
    parts_dir.mkdir(parents=True, exist_ok=True)
    manifest = parts_dir / MANIFEST
    if manifest.exists():
        saved = json.loads(manifest.read_text())
        if saved != settings:
            raise SettingsChanged(
                f"{parts_dir} holds embeddings built with {saved}, but the current settings "
                f"are {settings}. Delete {parts_dir} to start over with the new settings."
            )
        return 0
    stale = list(parts_dir.glob("part-*.parquet")) + list(parts_dir.glob("part-*.tmp"))
    for path in stale:
        path.unlink()
    manifest.write_text(json.dumps(settings, indent=2) + "\n")
    return len(stale)


def write_part(path: Path, ids: list[str], vectors: np.ndarray) -> None:
    """Write one checkpoint atomically: a crash never leaves a half-written part."""
    vectors = np.asarray(vectors, dtype=np.float32)
    flat = pa.array(vectors.reshape(-1), type=pa.float32())
    table = pa.table(
        {
            "cve_id": pa.array(ids, type=pa.string()),
            "embedding": pa.FixedSizeListArray.from_arrays(flat, vectors.shape[1]),
        }
    )
    tmp = path.with_suffix(".tmp")
    pq.write_table(table, tmp, compression="zstd")
    tmp.replace(path)


def embed_in_chunks(
    rows: Sequence[tuple[str, str]],
    encode: Encoder,
    parts_dir: Path = PARTS_DIR,
    size: int = CHUNK_SIZE,
    progress: Callable[[str], None] = print,
) -> dict[str, int]:
    """Encode (cve_id, description) rows chunk by chunk, skipping chunks already on disk."""
    chunks = chunk(rows, size)
    encoded = resumed = rows_encoded = 0
    for n, part in enumerate(chunks):
        path = part_path(parts_dir, n)
        if path.exists():
            resumed += 1
            progress(f"chunk {n + 1}/{len(chunks)}: already done")
            continue
        start = time.perf_counter()
        write_part(path, [cve for cve, _ in part], encode([text for _, text in part]))
        encoded += 1
        rows_encoded += len(part)
        progress(
            f"chunk {n + 1}/{len(chunks)}: {len(part):,} in {time.perf_counter() - start:,.0f}s"
        )
    return {
        "chunks": len(chunks),
        "chunks_encoded": encoded,
        "chunks_resumed": resumed,
        "rows_encoded_this_run": rows_encoded,
    }


def merge_parts(con, parts_dir: Path = PARTS_DIR, output: Path = OUTPUT) -> int:
    parts = (parts_dir / "part-*.parquet").as_posix()
    con.execute(
        f"COPY (SELECT * FROM read_parquet('{parts}') ORDER BY cve_id) "
        f"TO '{output.as_posix()}' (FORMAT parquet, COMPRESSION zstd)"
    )
    return con.execute(f"SELECT count(*) FROM read_parquet('{output.as_posix()}')").fetchone()[0]


def granite_encoder() -> Encoder:
    from backend.services.embedding_model import load_embedding_model

    model = load_embedding_model()

    def encode(texts: list[str]) -> np.ndarray:
        return model.encode(
            texts, batch_size=config.EMBEDDING_BATCH_SIZE, normalize_embeddings=True
        )

    return encode


# --- Colab: export the input, import and check the result ---------------------------


class ImportCheckFailed(ValueError):
    pass


def export_input(con, path: Path = EXPORT_INPUT) -> int:
    """Write the exact embedding input (cve_id, description; blanks left out), sorted by
    cve_id, for scripts/colab_embed.py."""
    path.parent.mkdir(parents=True, exist_ok=True)
    con.execute(
        f"COPY (SELECT cve_id, description FROM ({in_scope_sql()}) "
        f"WHERE description IS NOT NULL ORDER BY cve_id) "
        f"TO '{path.as_posix()}' (FORMAT parquet, COMPRESSION zstd)"
    )
    return con.execute(f"SELECT count(*) FROM read_parquet('{path.as_posix()}')").fetchone()[0]


def check_vectors(ids: list[str], matrix: np.ndarray, expected_ids: list[str]) -> None:
    """Raise ImportCheckFailed listing every problem with an imported embeddings file."""
    problems = []
    if len(ids) != len(expected_ids):
        problems.append(f"{len(ids):,} rows; the export has {len(expected_ids):,}")
    if len(set(ids)) != len(ids):
        problems.append(f"{len(ids) - len(set(ids)):,} duplicate cve_ids")
    if set(ids) != set(expected_ids):
        missing, extra = set(expected_ids) - set(ids), set(ids) - set(expected_ids)
        problems.append(f"{len(missing):,} exported ids missing, {len(extra):,} unexpected ids")
    if matrix.ndim != 2 or matrix.shape[1] != DIMENSIONS:
        problems.append(f"vectors have shape {matrix.shape}, expected (n, {DIMENSIONS})")
    else:
        norms = np.linalg.norm(matrix, axis=1)
        off = int((np.abs(norms - 1) > NORM_TOLERANCE).sum())
        if off:
            problems.append(f"{off:,} vectors have a norm away from 1 (tolerance {NORM_TOLERANCE})")
    if problems:
        raise ImportCheckFailed("Imported embeddings rejected: " + "; ".join(problems))


def read_embeddings(path: Path) -> tuple[list[str], np.ndarray, dict]:
    """ids, an (n, dims) float32 matrix, and the file's key-value metadata."""
    table = pq.read_table(path, columns=["cve_id", "embedding"])
    column = table["embedding"].combine_chunks()
    if pa.types.is_fixed_size_list(column.type):
        width = column.type.list_size
        matrix = column.flatten().to_numpy().reshape(len(column), width)
    else:  # a variable-length list: rows must still all be the same length
        matrix = np.array(column.to_pylist(), dtype=np.float32)
    raw = table.schema.metadata or {}
    metadata = {k.decode(): v.decode() for k, v in raw.items() if not k.startswith(b"ARROW")}
    return table["cve_id"].to_pylist(), matrix.astype(np.float32), metadata


def sample_rows(rows: list[tuple[str, str]], n: int = CHECK_SAMPLE) -> list[tuple[str, str]]:
    """A fixed sample of (cve_id, description) rows for the local re-embedding check."""
    return random.Random(CHECK_SEED).sample(sorted(rows), min(n, len(rows)))


def import_embeddings(source: Path, encode: Encoder | None = None) -> dict:
    """Check a Colab embeddings file, re-embed a sample locally, then install it."""
    con = connect()
    rows = con.execute(in_scope_sql()).fetchall()
    with_text = [(cve, text) for cve, text in rows if text is not None]
    ids, matrix, metadata = read_embeddings(source)
    check_vectors(ids, matrix, [cve for cve, _ in with_text])
    for key, expected in (
        ("model", config.EMBEDDING_MODEL_ID),
        ("max_seq_length", str(config.EMBEDDING_MAX_SEQ_LENGTH)),
    ):
        if key in metadata and metadata[key] != expected:
            raise ImportCheckFailed(f"file was built with {key}={metadata[key]}, not {expected}")

    sample = sample_rows(with_text)
    position = {cve: i for i, cve in enumerate(ids)}
    local = (encode or granite_encoder())([text for _, text in sample])
    imported = matrix[[position[cve] for cve, _ in sample]]
    cosine = mean_cosine(np.asarray(local, dtype=np.float32), imported)
    if cosine < MIN_COSINE:
        raise ImportCheckFailed(
            f"mean cosine with local {config.EMBEDDING_BACKEND} vectors on {len(sample)} rows "
            f"is {cosine:.5f}, below {MIN_COSINE}"
        )

    order = np.argsort(np.array(ids))
    write_part(OUTPUT, [ids[i] for i in order], matrix[order])
    PARTS_DIR.mkdir(parents=True, exist_ok=True)
    settings = {
        "model": metadata.get("model", config.EMBEDDING_MODEL_ID),
        "backend": metadata.get("backend", "torch-cuda"),
        "max_seq_length": int(metadata.get("max_seq_length", config.EMBEDDING_MAX_SEQ_LENGTH)),
        "source": "colab-t4",
    }
    (PARTS_DIR / MANIFEST).write_text(json.dumps(settings, indent=2) + "\n")
    return {
        "input": len(rows),
        "embedded": len(ids),
        "skipped_blank": len(rows) - len(with_text),
        **settings,
        "batch_size": int(metadata.get("batch_size", 0)) or None,
        "device": metadata.get("device"),
        "seconds": float(metadata["seconds"]) if "seconds" in metadata else None,
        "check_sample": len(sample),
        "check_local_backend": config.EMBEDDING_BACKEND,
        "check_mean_cosine": round(cosine, 6),
    }


def write_log(log: dict) -> None:
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    (LOGS_DIR / "embeddings_log.json").write_text(json.dumps(log, indent=2) + "\n")
    for name, value in log.items():
        print(f"{name:<24} {value}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--export", action="store_true", help=f"write {EXPORT_INPUT.name}")
    group.add_argument("--import", dest="source", type=Path, help="install a Colab result")
    args = parser.parse_args()
    if not (FEATURES_DIR / "population.parquet").exists():
        raise SystemExit("No population. Run `uv run python -m backend.pipeline.population` first.")
    if args.export:
        print(f"wrote {export_input(connect()):,} rows to {EXPORT_INPUT}")
        return
    if args.source:
        try:
            write_log(import_embeddings(args.source))
        except ImportCheckFailed as error:
            raise SystemExit(str(error)) from error
        return
    settings = current_settings()
    try:
        stale = prepare_parts_dir(PARTS_DIR, settings)
    except SettingsChanged as error:
        raise SystemExit(str(error)) from error
    con = connect()
    rows = con.execute(in_scope_sql()).fetchall()
    with_text = [(cve, text) for cve, text in rows if text is not None]
    start = time.perf_counter()
    stats = embed_in_chunks(with_text, granite_encoder())
    encode_seconds = time.perf_counter() - start
    embedded = merge_parts(con)
    log = {
        "input": len(rows),
        "embedded": embedded,
        "skipped_blank": len(rows) - len(with_text),
        **settings,
        "batch_size": config.EMBEDDING_BATCH_SIZE,
        "stale_parts_deleted": stale,
        **stats,
        "seconds": round(time.perf_counter() - start, 1),
        "desc_per_second": (
            round(stats["rows_encoded_this_run"] / encode_seconds, 2)
            if stats["rows_encoded_this_run"]
            else None
        ),
        "source": "local",
    }
    write_log(log)


if __name__ == "__main__":
    main()
