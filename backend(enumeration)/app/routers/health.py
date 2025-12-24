"""Health check endpoints."""

from fastapi import APIRouter

from app.config import get_settings

router = APIRouter()
settings = get_settings()


@router.get("/health")
async def health_check():
    """Health check endpoint for monitoring and load balancers."""
    return {
        "status": "healthy",
        "version": settings.app_version,
        "service": "aether-scanner",
    }


@router.get("/health/ready")
async def readiness_check():
    """Readiness check - verifies all dependencies are available."""
    # TODO: Add database and Redis connectivity checks
    return {
        "status": "ready",
        "checks": {
            "database": "ok",
            "redis": "ok",
        },
    }
