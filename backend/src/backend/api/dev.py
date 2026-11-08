"""Development server: `uv run dev` (API on http://127.0.0.1:8000, docs at /docs).

Reloads when backend code changes. Set HOST / PORT to change where it listens.
"""

import os
from pathlib import Path

import uvicorn


def main() -> None:
    src = Path(__file__).resolve().parents[2]  # backend/src
    uvicorn.run(
        "backend.api.app:app",
        host=os.getenv("HOST", "127.0.0.1"),
        port=int(os.getenv("PORT", "8000")),
        reload=True,
        reload_dirs=[str(src)],
    )


if __name__ == "__main__":
    main()
