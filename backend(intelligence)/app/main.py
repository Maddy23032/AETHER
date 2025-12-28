"""
AETHER Intelligence API
RAG-powered security analysis assistant backend

Port: 8002 (to avoid conflict with recon:8000 and enumeration:8001)
"""

import os
import warnings

# Set TensorFlow/Keras environment variables BEFORE any imports that might trigger TF loading
os.environ['TF_USE_LEGACY_KERAS'] = '1'
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'  # Suppress TF info/warning logs

# Suppress protobuf version warnings
warnings.filterwarnings('ignore', message='.*Protobuf gencode version.*')

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

from app.routers import chat, references, ingest, graph
from app.services.rag_service import rag_service


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize services on startup"""
    # Initialize the vector store on startup
    print("Initializing RAG vector store...")
    success = await rag_service.initialize_vector_store()
    if success:
        print("RAG vector store initialized successfully")
        
        # Load all scans from Supabase into the vector store
        print("Loading scans from Supabase...")
        try:
            scans_loaded = await rag_service.load_scans_from_supabase()
            print(f"Loaded {scans_loaded} scans from Supabase")
        except Exception as e:
            print(f"Warning: Failed to load scans from Supabase: {e}")
    else:
        print("Warning: RAG vector store initialization failed")
    yield
    # Cleanup on shutdown (if needed)
    print("Shutting down Intelligence API...")


app = FastAPI(
    title="AETHER Intelligence API",
    description="RAG-powered security analysis assistant for AETHER platform",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
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
app.include_router(graph.router, prefix="/api/intelligence", tags=["Graph Sitemap"])


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
