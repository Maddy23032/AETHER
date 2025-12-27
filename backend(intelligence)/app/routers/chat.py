"""
Chat Router - Handles RAG-powered chat interactions
"""

import time
from fastapi import APIRouter, HTTPException
from typing import List

from app.models.intelligence import (
    ChatRequest,
    ChatResponse,
    SuggestedPrompt,
    AnalysisContextStats
)
from app.services.rag_service import rag_service


router = APIRouter()


@router.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest):
    """
    Send a message to the RAG-powered security assistant.
    Returns AI response with source references.
    """
    start_time = time.time()
    
    try:
        response_text, sources, thinking = await rag_service.chat(
            message=request.message,
            conversation_history=request.conversation_history,
            include_scan_context=request.include_scan_context
        )
        
        processing_time = (time.time() - start_time) * 1000
        
        return ChatResponse(
            message=response_text,
            sources=sources,
            thinking=thinking,
            processing_time_ms=processing_time
        )
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Chat error: {str(e)}")


@router.get("/suggested-prompts", response_model=List[SuggestedPrompt])
async def get_suggested_prompts():
    """
    Get suggested prompts for the user based on available context.
    """
    prompts = [
        SuggestedPrompt(
            text="Analyze the latest reconnaissance scan results and identify potential attack vectors",
            category="recon"
        ),
        SuggestedPrompt(
            text="What are the most critical vulnerabilities found in recent scans?",
            category="vulnerability"
        ),
        SuggestedPrompt(
            text="Summarize the security posture based on all available scan data",
            category="security"
        ),
        SuggestedPrompt(
            text="What open ports pose the highest security risk?",
            category="recon"
        ),
        SuggestedPrompt(
            text="Generate a remediation plan for the identified vulnerabilities",
            category="vulnerability"
        ),
        SuggestedPrompt(
            text="Are there any indicators of compromise in the scan results?",
            category="security"
        ),
        SuggestedPrompt(
            text="What additional reconnaissance should be performed?",
            category="recon"
        ),
        SuggestedPrompt(
            text="Explain the CVSS scores of the detected vulnerabilities",
            category="vulnerability"
        )
    ]
    
    return prompts


@router.get("/context-stats", response_model=AnalysisContextStats)
async def get_context_stats():
    """
    Get statistics about the analysis context (documents, scans, etc.)
    """
    stats = rag_service.get_stats()
    
    return AnalysisContextStats(
        total_documents=stats["total_documents"],
        recon_scans_count=stats["recon_scans_count"],
        enum_scans_count=stats["enum_scans_count"],
        mobile_scans_count=stats["mobile_scans_count"],
        total_chunks=stats["total_chunks"],
        vector_store_status=stats["vector_store_status"]
    )


@router.get("/debug/documents")
async def debug_documents():
    """
    Debug endpoint to see all documents in the metadata store.
    """
    docs = []
    for doc_id, meta in rag_service._document_metadata.items():
        source_type = meta.get("source_type")
        if hasattr(source_type, 'value'):
            source_type = source_type.value
        
        created_at = meta.get("created_at")
        if hasattr(created_at, 'isoformat'):
            created_at = created_at.isoformat()
        
        docs.append({
            "id": doc_id,
            "title": meta.get("title"),
            "source_type": source_type,
            "chunks": meta.get("chunks"),
            "created_at": created_at,
            "metadata": meta.get("metadata")
        })
    
    # Sort by created_at (newest first)
    docs.sort(key=lambda x: x.get("created_at") or "", reverse=True)
    
    return {
        "total": len(docs),
        "documents": docs
    }


@router.post("/refresh-scans")
async def refresh_scans():
    """
    Manually reload all scans from Supabase into the RAG vector store.
    Use this when you want to ensure all scans are available for analysis.
    """
    try:
        scans_loaded = await rag_service.load_scans_from_supabase()
        stats = rag_service.get_stats()
        
        return {
            "success": True,
            "scans_loaded": scans_loaded,
            "total_documents": stats["total_documents"],
            "recon_scans": stats["recon_scans_count"],
            "enum_scans": stats["enum_scans_count"],
            "mobile_scans": stats["mobile_scans_count"]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to refresh scans: {str(e)}")
