"""FastAPI app. Run with `uv run uvicorn backend.api.app:app --reload`."""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.api.routes import health, meta, sboms
from backend.db.store import open_database

# Vite dev server origins.
CORS_ORIGINS = ["http://localhost:5173", "http://127.0.0.1:5173"]


def create_app(con=None) -> FastAPI:
    """`con` lets tests pass their own connection; otherwise one is opened at startup."""

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.db = con if con is not None else open_database()
        try:
            yield
        finally:
            if con is None:
                app.state.db.close()

    app = FastAPI(title="Before the Breach API", version="1.0", lifespan=lifespan)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=CORS_ORIGINS,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(health.router)
    app.include_router(meta.router)
    app.include_router(sboms.router)
    return app


app = create_app()
