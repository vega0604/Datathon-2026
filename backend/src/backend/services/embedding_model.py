"""Load the Granite embedding model the same way everywhere (SHE-37, SHE-45).

model = load_embedding_model()  # settings from backend/.env
vectors = model.encode(texts, batch_size=EMBEDDING_BATCH_SIZE, normalize_embeddings=True)
"""

from backend.core import config

BACKENDS = ("torch", "onnx", "openvino")


def load_embedding_model(
    backend: str | None = None,
    max_seq_length: int | None = None,
    device: str | None = None,
):
    """A SentenceTransformer for EMBEDDING_MODEL_ID on CPU. `device` is only for
    OpenVINO (for example "GPU" for an integrated GPU); torch always runs on CPU."""
    backend = backend or config.EMBEDDING_BACKEND
    if backend not in BACKENDS:
        raise ValueError(f"EMBEDDING_BACKEND must be one of {', '.join(BACKENDS)}, not {backend!r}")
    from sentence_transformers import SentenceTransformer  # heavy import, only when used

    model_kwargs = {}
    if backend == "torch":
        import torch

        # The model defaults to bfloat16, which most CPUs emulate very slowly.
        model_kwargs["dtype"] = torch.float32
    elif backend == "openvino" and device:
        model_kwargs["device"] = device
    model = SentenceTransformer(
        config.EMBEDDING_MODEL_ID, device="cpu", backend=backend, model_kwargs=model_kwargs
    )
    model.max_seq_length = max_seq_length or config.EMBEDDING_MAX_SEQ_LENGTH
    return model
