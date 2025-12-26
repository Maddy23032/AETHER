"""
AETHER Reconnaissance API
Main FastAPI application entry point
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routers import (
    nmap,
    whatweb,
    nikto,
    dirsearch,
    gobuster,
    amass,
    theharvester,
    dnsenum,
    subfinder,
    httpx
)

app = FastAPI(
    title="AETHER Reconnaissance API",
    description="Secure API for web reconnaissance tools",
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
app.include_router(nmap.router, prefix="/api/recon", tags=["nmap"])
app.include_router(whatweb.router, prefix="/api/recon", tags=["whatweb"])
app.include_router(nikto.router, prefix="/api/recon", tags=["nikto"])
app.include_router(dirsearch.router, prefix="/api/recon", tags=["dirsearch"])
app.include_router(gobuster.router, prefix="/api/recon", tags=["gobuster"])
app.include_router(amass.router, prefix="/api/recon", tags=["amass"])
app.include_router(theharvester.router, prefix="/api/recon", tags=["theharvester"])
app.include_router(dnsenum.router, prefix="/api/recon", tags=["dnsenum"])
app.include_router(subfinder.router, prefix="/api/recon", tags=["subfinder"])
app.include_router(httpx.router, prefix="/api/recon", tags=["httpx"])

@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "service": "AETHER Reconnaissance API",
        "status": "operational",
        "version": "1.0.0"
    }

@app.get("/api/tools")
async def list_tools():
    """List all available reconnaissance tools"""
    return {
        "tools": [
            {"name": "nmap", "endpoint": "/api/recon/nmap"},
            {"name": "whatweb", "endpoint": "/api/recon/whatweb"},
            {"name": "nikto", "endpoint": "/api/recon/nikto"},
            {"name": "dirsearch", "endpoint": "/api/recon/dirsearch"},
            {"name": "gobuster", "endpoint": "/api/recon/gobuster"},
            {"name": "amass", "endpoint": "/api/recon/amass"},
            {"name": "theharvester", "endpoint": "/api/recon/theharvester"},
            {"name": "dnsenum", "endpoint": "/api/recon/dnsenum"},
            {"name": "subfinder", "endpoint": "/api/recon/subfinder"},
            {"name": "httpx", "endpoint": "/api/recon/httpx"}
        ]
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
