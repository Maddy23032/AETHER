"""
AETHER Intelligence API
RAG-powered security analysis assistant backend

Port: 8002 (to avoid conflict with recon:8000 and enumeration:8001)
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

from app.routers import chat, references, ingest

# Load environment variables
load_dotenv()

app = FastAPI(
    title="AETHER Intelligence API",
    description="RAG-powered security analysis assistant for AETHER platform",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS middleware for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(chat.router, prefix="/api/intelligence", tags=["Chat"])
app.include_router(references.router, prefix="/api/intelligence", tags=["References"])
app.include_router(ingest.router, prefix="/api/intelligence", tags=["Ingestion"])


@app.get("/")
async def root():
    return {
        "service": "AETHER Intelligence API",
        "status": "online",
        "version": "1.0.0",
        "endpoints": {
            "chat": "/api/intelligence/chat",
            "references": "/api/intelligence/references",
            "ingest": "/api/intelligence/ingest",
            "health": "/api/intelligence/health"
        }
    }


@app.get("/api/intelligence/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "intelligence",
        "rag_enabled": True
    }
