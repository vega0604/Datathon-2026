"""Development server: `uv run dev` (API on http://127.0.0.1:8000, docs at /docs).

Reloads when backend code changes. Set HOST / PORT to change where it listens.
"""

import multiprocessing
import os

import uvicorn


def main() -> None:
    uvicorn.run(
        "backend.api.app:app",
        host="0.0.0.0",
        port=int(os.getenv("PORT", "8000")),
        workers=int(os.getenv("WORKERS", multiprocessing.cpu_count())),
        loop="uvloop",
        http="httptools",
        limit_concurrency=1000,
        limit_max_requests=5000,
        timeout_keep_alive=5,
        backlog=2048,
        log_level="info"
    )


if __name__ == "__main__":
    main()
