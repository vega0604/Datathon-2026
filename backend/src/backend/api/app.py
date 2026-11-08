"""FastAPI app. Run with `uv run uvicorn backend.api.app:app --reload`."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.api.routes import health

# Vite dev server origins.
CORS_ORIGINS = ["http://localhost:5173", "http://127.0.0.1:5173"]


def create_app(con=None) -> FastAPI:
    app = FastAPI(title="Before the Breach API", version="1.0")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=CORS_ORIGINS,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(health.router)
    return app


app = create_app()
