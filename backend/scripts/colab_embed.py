"""SHE-45 on a Colab GPU: Granite embeddings for every in-scope description, in minutes.

Standalone: imports nothing from `backend`, and needs only sentence-transformers (Colab
already has torch, pandas and pyarrow).

Steps
1. Locally, write the input:
       uv run python -m backend.pipeline.embeddings --export
   This creates backend/data/features/embed_input.parquet.
2. In Colab: Runtime > Change runtime type > T4 GPU > Save.
3. Upload embed_input.parquet and this script with the Files panel (left sidebar), into
   /content.
4. In a cell, run:
       !pip install -q sentence-transformers
       !python colab_embed.py
   It prints the row count and runtime and writes /content/embeddings.parquet.
5. Download embeddings.parquet (Files panel > right-click > Download), then locally:
       uv run python -m backend.pipeline.embeddings --import path/to/embeddings.parquet

Settings match the local pipeline: same model, float32, max_seq_length 256, normalised
vectors. They are stored in the output file's metadata, which --import checks.
"""

import sys
import time

import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq
import torch
from sentence_transformers import SentenceTransformer

MODEL_ID = "ibm-granite/granite-embedding-small-english-r2"
MAX_SEQ_LENGTH = 256
BATCH_SIZE = 256
DIMENSIONS = 384
INPUT = "embed_input.parquet"
OUTPUT = "embeddings.parquet"


def main() -> None:
    if not torch.cuda.is_available():
        sys.exit("No GPU: set Runtime > Change runtime type > T4 GPU, then rerun.")
    device = torch.cuda.get_device_name(0)
    table = pq.read_table(INPUT, columns=["cve_id", "description"])
    ids = table["cve_id"].to_pylist()
    texts = table["description"].to_pylist()
    print(f"{len(ids):,} descriptions on {device}", flush=True)

    model = SentenceTransformer(MODEL_ID, device="cuda", model_kwargs={"dtype": torch.float32})
    # The checkpoint is stored in bfloat16; .float() makes float32 certain on any
    # transformers version (the upcast is exact).
    model = model.float()
    model.max_seq_length = MAX_SEQ_LENGTH
    print(f"dtype {next(model.parameters()).dtype}, max_seq_length {model.max_seq_length}")
    start = time.perf_counter()
    vectors = model.encode(
        texts,
        batch_size=BATCH_SIZE,
        normalize_embeddings=True,
        convert_to_numpy=True,
        show_progress_bar=True,
    ).astype(np.float32)
    seconds = time.perf_counter() - start
    if vectors.shape != (len(ids), DIMENSIONS):
        sys.exit(f"Unexpected output shape {vectors.shape}")

    flat = pa.array(vectors.reshape(-1), type=pa.float32())
    out = pa.table(
        {
            "cve_id": pa.array(ids, type=pa.string()),
            "embedding": pa.FixedSizeListArray.from_arrays(flat, DIMENSIONS),
        }
    )
    metadata = {
        "model": MODEL_ID,
        "backend": "torch-cuda",
        "max_seq_length": str(MAX_SEQ_LENGTH),
        "batch_size": str(BATCH_SIZE),
        "device": device,
        "seconds": f"{seconds:.1f}",
    }
    out = out.replace_schema_metadata({k.encode(): v.encode() for k, v in metadata.items()})
    pq.write_table(out, OUTPUT, compression="zstd")
    print(f"rows {len(ids):,}")
    print(f"runtime {seconds:,.1f} s ({len(ids) / seconds:,.0f} descriptions/s)")
    print(f"wrote {OUTPUT}")


if __name__ == "__main__":
    main()
