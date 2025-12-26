"""
References Router - Handles document and scan references
"""

from fastapi import APIRouter, HTTPException, Query
from typing import Optional, List
from datetime import datetime

from app.models.intelligence import (
    Reference,
    ReferencesResponse,
    ReferenceFilter,
    SourceType
)
from app.services.rag_service import rag_service


router = APIRouter()


@router.get("/references", response_model=ReferencesResponse)
async def get_references(
    source_types: Optional[List[str]] = Query(None, description="Filter by source types"),
    search_query: Optional[str] = Query(None, description="Search within references"),
    limit: int = Query(20, ge=1, le=100, description="Maximum results to return")
):
    """
    Get list of available references (scan results, documents).
    These can be displayed in the UI for the user to see what data is available.
    """
    try:
        references = []
        
        for doc_id, doc_meta in rag_service._document_metadata.items():
            # Apply source type filter
            if source_types:
                doc_source_type = doc_meta.get("source_type")
                if hasattr(doc_source_type, 'value'):
                    doc_source_type = doc_source_type.value
                if doc_source_type not in source_types:
                    continue
            
            # Apply search filter
            if search_query:
                title = doc_meta.get("title", "").lower()
                if search_query.lower() not in title:
                    continue
            
            # Build reference object
            source_type = doc_meta.get("source_type")
            if isinstance(source_type, str):
                source_type = SourceType(source_type)
            
            created_at = doc_meta.get("created_at")
            if isinstance(created_at, str):
                created_at = datetime.fromisoformat(created_at)
            elif created_at is None:
                created_at = datetime.utcnow()
            
            metadata = doc_meta.get("metadata", {})
            
            # Generate summary based on source type
            if source_type == SourceType.RECON_SCAN:
                summary = f"Reconnaissance scan targeting {metadata.get('target', 'unknown target')}"
            elif source_type == SourceType.ENUM_SCAN:
                summary = f"Enumeration scan with vulnerability assessment for {metadata.get('target', 'unknown target')}"
            elif source_type == SourceType.MOBILE_SCAN:
                summary = f"Mobile security analysis for {metadata.get('target', metadata.get('filename', 'unknown app'))}"
            else:
                summary = f"Document with {doc_meta.get('chunks', 0)} chunks"
            
            # Extract tags from metadata
            tags = []
            if metadata.get("scan_type"):
                tags.append(metadata["scan_type"])
            if metadata.get("target"):
                tags.append(metadata["target"])
            
            references.append(Reference(
                id=doc_id,
                title=doc_meta.get("title", "Untitled"),
                source_type=source_type,
                summary=summary,
                metadata=metadata,
                created_at=created_at,
                tags=tags
            ))
        
        # Sort by created_at (newest first)
        references.sort(key=lambda x: x.created_at, reverse=True)
        
        # Apply limit
        total_count = len(references)
        references = references[:limit]
        
        return ReferencesResponse(
            references=references,
            total_count=total_count,
            has_more=total_count > limit
        )
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching references: {str(e)}")


@router.get("/references/{reference_id}", response_model=Reference)
async def get_reference(reference_id: str):
    """
    Get a specific reference by ID.
    """
    if reference_id not in rag_service._document_metadata:
        raise HTTPException(status_code=404, detail="Reference not found")
    
    doc_meta = rag_service._document_metadata[reference_id]
    
    source_type = doc_meta.get("source_type")
    if isinstance(source_type, str):
        source_type = SourceType(source_type)
    
    created_at = doc_meta.get("created_at")
    if isinstance(created_at, str):
        created_at = datetime.fromisoformat(created_at)
    elif created_at is None:
        created_at = datetime.utcnow()
    
    metadata = doc_meta.get("metadata", {})
    
    return Reference(
        id=reference_id,
        title=doc_meta.get("title", "Untitled"),
        source_type=source_type,
        summary=f"Document with {doc_meta.get('chunks', 0)} chunks",
        metadata=metadata,
        created_at=created_at,
        tags=[]
    )


@router.post("/references/search")
async def search_references(
    query: str = Query(..., description="Search query"),
    limit: int = Query(10, ge=1, le=50)
):
    """
    Semantic search across all references.
    Returns references ranked by relevance to the query.
    """
    try:
        results = await rag_service.retrieve_context(query, k=limit)
        
        references = []
        seen_ids = set()
        
        for doc, score in results:
            doc_id = doc.metadata.get("doc_id")
            
            # Skip duplicates and system docs
            if doc_id in seen_ids or doc.metadata.get("type") == "system":
                continue
            seen_ids.add(doc_id)
            
            source_type_str = doc.metadata.get("source_type", "document")
            try:
                source_type = SourceType(source_type_str)
            except ValueError:
                source_type = SourceType.DOCUMENT
            
            references.append({
                "id": doc_id,
                "title": doc.metadata.get("title", "Unknown"),
                "source_type": source_type.value,
                "preview": doc.page_content[:300] + "..." if len(doc.page_content) > 300 else doc.page_content,
                "relevance_score": 1.0 - (score / 2.0),
                "metadata": doc.metadata
            })
        
        return {"results": references, "query": query}
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Search error: {str(e)}")
