"""Cyber Sentinel Multi-Agent Platform — FastAPI Application Entrypoint."""

import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from apps.api.config import settings
from security.headers import SecurityHeadersMiddleware
from security.tracing import configure_tracing
from apps.api.routes.health import router as health_router
from apps.api.routes.investigation import router as investigation_router
from apps.api.routes.hitl import router as hitl_router
from apps.api.routes.chat import router as chat_router
from apps.api.routes.deception import router as deception_router
import structlog

logger = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize observability & tracing
    configure_tracing(
        enable_langsmith=True,
        project_name=settings.LANGCHAIN_PROJECT,
        api_key=settings.LANGCHAIN_API_KEY
    )
    logger.info(
        "Cyber Sentinel API initialized",
        host=settings.API_HOST,
        port=settings.API_PORT,
        provider=settings.LLM_PROVIDER
    )
    yield
    logger.info("Cyber Sentinel API shutdown complete")


app = FastAPI(
    title="Cyber Sentinel Multi-Agent Platform",
    description="Autonomous Threat Hunting, OSINT, Phishing, and TIP Orchestrator built on LangGraph",
    version="1.0.0",
    lifespan=lifespan
)

# 1. Enforce Production Security Headers
app.add_middleware(SecurityHeadersMiddleware)

# 2. Strict CORS Configuration (Restrict to localhost origins, prevent wildcards)
allowed_origins = [
    f"http://127.0.0.1:{settings.API_PORT}",
    f"http://localhost:{settings.API_PORT}",
    "http://127.0.0.1:3000",
    "http://localhost:3000"
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# 3. Mount API Routers
app.include_router(health_router, prefix="/api")
app.include_router(investigation_router, prefix="/api")
app.include_router(hitl_router, prefix="/api")
app.include_router(chat_router, prefix="/api")
app.include_router(deception_router, prefix="/api")

# 4. Mount Static Web Dashboard
static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.isdir(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

    @app.get("/", include_in_schema=False)
    async def serve_index():
        index_file = os.path.join(static_dir, "index.html")
        if os.path.exists(index_file):
            return FileResponse(index_file)
        return {"message": "Cyber Sentinel API Operational. Static frontend index not found."}

