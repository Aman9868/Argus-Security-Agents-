"""Health and Service Liveness Endpoints."""

from fastapi import APIRouter
from apps.api.config import settings

router = APIRouter(tags=["Health"])


@router.get("/health")
async def health_check():
    return {
        "status": "HEALTHY",
        "environment": settings.ENVIRONMENT,
        "llm_provider": settings.LLM_PROVIDER,
        "langsmith_tracing": bool(settings.LANGCHAIN_API_KEY),
        "host": settings.API_HOST,
        "port": settings.API_PORT
    }

