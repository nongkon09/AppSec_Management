from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import api_router
from app.core.config import get_settings
from app.core.scheduler import shutdown_scheduler, start_scheduler

settings = get_settings()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    # FR-3.1/FR-2.4: background Dependency-Track sync + staleness sweep. No-op unless
    # ENABLE_SCHEDULER=true (see app.core.scheduler / app.core.config).
    start_scheduler()
    yield
    shutdown_scheduler()


app = FastAPI(
    title="AppSec Management Platform API",
    version="0.3.0",
    description="Central Aggregation & Orchestration Platform for Application Security "
    "(see Requirement.md for full specification).",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router)


@app.get("/health", tags=["health"])
def health() -> dict[str, str]:
    return {"status": "ok", "env": settings.app_env}
