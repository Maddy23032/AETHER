"""
AETHER Mobile Security Backend
FastAPI application for mobile app security analysis using MobSF
"""
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import get_settings
from app.routes.scan import router as scan_router
from app.services.mobsf_service import get_mobsf_service
from app.models import HealthResponse

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan handler.
    Fetches MobSF API key on startup since it changes on each Docker restart.
    """
    print("\n" + "=" * 60)
    print("  AETHER Mobile Security Backend Starting...")
    print("=" * 60)
    
    # Initialize MobSF service and fetch API key
    mobsf = get_mobsf_service()
    
    try:
        if await mobsf.is_ready():
            api_key = await mobsf.get_api_key()
            print(f"  ✓ MobSF connected at {settings.mobsf_url}")
            print(f"  ✓ API Key obtained: {api_key[:8]}...")
        else:
            print(f"  ✗ MobSF not available at {settings.mobsf_url}")
            print("    Start MobSF: docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf")
    except Exception as e:
        print(f"  ✗ Failed to initialize MobSF: {e}")
    
    print("=" * 60)
    print(f"  Server running at http://{settings.host}:{settings.port}")
    print(f"  API Docs: http://{settings.host}:{settings.port}/docs")
    print("=" * 60 + "\n")
    
    yield  # App runs
    
    print("\n  Shutting down AETHER Mobile Security Backend...\n")


# Create FastAPI app
app = FastAPI(
    title="AETHER Mobile Security API",
    description="Mobile application security analysis powered by MobSF",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(scan_router, prefix="/api/v1")


@app.get("/", tags=["Root"])
async def root():
    """Root endpoint."""
    return {
        "service": "AETHER Mobile Security Backend",
        "version": "1.0.0",
        "docs": "/docs"
    }


@app.get("/health", response_model=HealthResponse, tags=["Health"])
async def health_check():
    """
    Health check endpoint.
    Verifies MobSF connectivity and API key availability.
    """
    mobsf = get_mobsf_service()
    
    mobsf_ready = await mobsf.is_ready()
    api_key_available = mobsf._api_key is not None
    
    return HealthResponse(
        status="healthy" if mobsf_ready else "degraded",
        mobsf_connected=mobsf_ready,
        api_key_available=api_key_available
    )


@app.post("/api/v1/refresh-key", tags=["Admin"])
async def refresh_api_key():
    """
    Force refresh the MobSF API key.
    Use this after MobSF Docker container is restarted.
    """
    mobsf = get_mobsf_service()
    
    try:
        api_key = await mobsf.get_api_key(force_refresh=True)
        return {
            "success": True,
            "message": "API key refreshed",
            "key_preview": api_key[:8] + "..."
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }
