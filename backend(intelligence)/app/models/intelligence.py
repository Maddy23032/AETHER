"""
Pydantic models for Intelligence API requests and responses
"""

from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum


class MessageRole(str, Enum):
    USER = "user"
    ASSISTANT = "assistant"
    SYSTEM = "system"


class SourceType(str, Enum):
    RECON_SCAN = "recon_scan"
    ENUM_SCAN = "enum_scan"
    MOBILE_SCAN = "mobile_scan"
    DOCUMENT = "document"
    KNOWLEDGE_BASE = "knowledge_base"


# ===== Chat Models =====

class ChatMessage(BaseModel):
    """Single chat message"""
    role: MessageRole
    content: str
    timestamp: Optional[datetime] = None


class ChatRequest(BaseModel):
    """Request to send a message to the RAG chat"""
    message: str = Field(..., description="The user's message")
    conversation_history: Optional[List[ChatMessage]] = Field(
        default=[], 
        description="Previous messages for context"
    )
    include_scan_context: bool = Field(
        default=True, 
        description="Whether to include scan results in RAG context"
    )


class SourceReference(BaseModel):
    """A reference/source used to generate the response"""
    id: str
    title: str
    source_type: SourceType
    content_preview: str = Field(..., description="Snippet of the source content")
    relevance_score: float = Field(..., ge=0.0, le=1.0)
    metadata: Optional[Dict[str, Any]] = None
    created_at: Optional[datetime] = None


class ChatResponse(BaseModel):
    """Response from the RAG chat"""
    message: str = Field(..., description="AI generated response")
    sources: List[SourceReference] = Field(
        default=[], 
        description="Sources used to generate the response"
    )
    thinking: Optional[str] = Field(
        default=None, 
        description="AI thinking/reasoning process"
    )
    processing_time_ms: Optional[float] = None


# ===== References Models =====

class ReferenceFilter(BaseModel):
    """Filters for fetching references"""
    source_types: Optional[List[SourceType]] = None
    date_from: Optional[datetime] = None
    date_to: Optional[datetime] = None
    search_query: Optional[str] = None
    limit: int = Field(default=20, ge=1, le=100)


class Reference(BaseModel):
    """A reference document or scan result"""
    id: str
    title: str
    source_type: SourceType
    summary: str
    content: Optional[str] = None
    metadata: Dict[str, Any] = {}
    created_at: datetime
    tags: List[str] = []


class ReferencesResponse(BaseModel):
    """Response containing list of references"""
    references: List[Reference]
    total_count: int
    has_more: bool


# ===== Ingestion Models =====

class IngestDocumentRequest(BaseModel):
    """Request to ingest a document into the vector store"""
    title: str
    content: str
    source_type: SourceType = SourceType.DOCUMENT
    metadata: Optional[Dict[str, Any]] = None


class IngestScanRequest(BaseModel):
    """Request to ingest scan results into the vector store"""
    scan_id: str
    scan_type: str  # "recon" or "enumeration"
    target: str
    results: Dict[str, Any]
    metadata: Optional[Dict[str, Any]] = None


class IngestResponse(BaseModel):
    """Response after ingesting content"""
    success: bool
    document_id: str
    chunks_created: int
    message: str


# ===== Context/Stats Models =====

class AnalysisContextStats(BaseModel):
    """Statistics about the analysis context"""
    total_documents: int
    recon_scans_count: int
    enum_scans_count: int
    mobile_scans_count: int
    total_chunks: int
    last_updated: Optional[datetime] = None
    vector_store_status: str = "active"


class SuggestedPrompt(BaseModel):
    """A suggested prompt for the user"""
    text: str
    category: str  # e.g., "security", "recon", "vulnerability"
