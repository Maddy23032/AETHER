"""
Ingestion Router - Handles ingesting documents and scan results into the vector store
"""

from fastapi import APIRouter, HTTPException

from app.models.intelligence import (
    IngestDocumentRequest,
    IngestScanRequest,
    IngestResponse
)
from app.services.rag_service import rag_service


router = APIRouter()


@router.post("/ingest/document", response_model=IngestResponse)
async def ingest_document(request: IngestDocumentRequest):
    """
    Ingest a document into the vector store for RAG retrieval.
    """
    try:
        doc_id, chunks_created = await rag_service.ingest_document(
            title=request.title,
            content=request.content,
            source_type=request.source_type,
            metadata=request.metadata
        )
        
        return IngestResponse(
            success=True,
            document_id=doc_id,
            chunks_created=chunks_created,
            message=f"Successfully ingested document '{request.title}' with {chunks_created} chunks"
        )
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ingestion error: {str(e)}")


@router.post("/ingest/scan", response_model=IngestResponse)
async def ingest_scan(request: IngestScanRequest):
    """
    Ingest scan results into the vector store for RAG retrieval.
    This allows the AI to reference scan data when answering questions.
    """
    try:
        doc_id, chunks_created = await rag_service.ingest_scan_results(
            scan_id=request.scan_id,
            scan_type=request.scan_type,
            target=request.target,
            results=request.results,
            metadata=request.metadata
        )
        
        return IngestResponse(
            success=True,
            document_id=doc_id,
            chunks_created=chunks_created,
            message=f"Successfully ingested {request.scan_type} scan for '{request.target}' with {chunks_created} chunks"
        )
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan ingestion error: {str(e)}")


@router.post("/initialize")
async def initialize_vector_store():
    """
    Initialize or reload the vector store.
    Call this on startup or when resetting the knowledge base.
    """
    try:
        success = await rag_service.initialize_vector_store()
        
        if success:
            return {"status": "initialized", "message": "Vector store initialized successfully"}
        else:
            raise HTTPException(status_code=500, detail="Failed to initialize vector store")
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Initialization error: {str(e)}")
