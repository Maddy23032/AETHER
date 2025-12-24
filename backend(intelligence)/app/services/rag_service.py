"""
RAG Service for AETHER Intelligence
Handles document embedding, vector storage, and retrieval-augmented generation
"""

import os
import uuid
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime

from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_groq import ChatGroq
from langchain_community.vectorstores import FAISS
from langchain_core.documents import Document
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.messages import HumanMessage, AIMessage, SystemMessage

from app.models.intelligence import (
    SourceReference, 
    SourceType, 
    ChatMessage,
    MessageRole
)


class RAGService:
    """
    RAG (Retrieval Augmented Generation) service for security analysis.
    Uses FAISS for vector storage and Groq for LLM inference.
    """
    
    def __init__(self):
        # Configuration from environment
        self.embed_model_name = os.getenv("EMBED_MODEL", "all-MiniLM-L6-v2")
        self.llm_model_name = os.getenv("LLM_MODEL", "qwen/qwen3-32b")
        self.groq_api_key = os.getenv("GROQ_API_KEY")
        
        # RAG parameters
        self.chunk_size = int(os.getenv("CHUNK_SIZE", "1000"))
        self.chunk_overlap = int(os.getenv("CHUNK_OVERLAP", "200"))
        self.retrieval_k = int(os.getenv("RETRIEVAL_K", "5"))
        
        # Initialize components
        self._embeddings: Optional[HuggingFaceEmbeddings] = None
        self._llm: Optional[ChatGroq] = None
        self._vector_store: Optional[FAISS] = None
        self._text_splitter: Optional[RecursiveCharacterTextSplitter] = None
        
        # Document metadata storage (in-memory for now)
        self._document_metadata: Dict[str, Dict[str, Any]] = {}
        
        # Vector store path
        self._vector_store_path = os.getenv("VECTOR_STORE_PATH", "./vector_store")
    
    @property
    def embeddings(self) -> HuggingFaceEmbeddings:
        """Lazy load embeddings model"""
        if self._embeddings is None:
            self._embeddings = HuggingFaceEmbeddings(
                model_name=self.embed_model_name,
                model_kwargs={'device': 'cpu'},
                encode_kwargs={'normalize_embeddings': True}
            )
        return self._embeddings
    
    @property
    def llm(self) -> ChatGroq:
        """Lazy load LLM"""
        if self._llm is None:
            self._llm = ChatGroq(
                model=self.llm_model_name,
                api_key=self.groq_api_key,
                temperature=0.7,
                max_tokens=2048
            )
        return self._llm
    
    @property
    def text_splitter(self) -> RecursiveCharacterTextSplitter:
        """Lazy load text splitter"""
        if self._text_splitter is None:
            self._text_splitter = RecursiveCharacterTextSplitter(
                chunk_size=self.chunk_size,
                chunk_overlap=self.chunk_overlap,
                length_function=len,
                separators=["\n\n", "\n", " ", ""]
            )
        return self._text_splitter
    
    def _get_system_prompt(self) -> str:
        """Get the system prompt for the security analysis assistant"""
        return """You are AETHER, an advanced AI-powered cybersecurity analysis assistant.
Your role is to help security professionals analyze scan results, identify vulnerabilities,
and provide actionable security recommendations.

When analyzing security data:
1. Identify potential vulnerabilities and their severity (Critical, High, Medium, Low)
2. Explain the security implications in clear terms
3. Provide specific remediation recommendations
4. Reference relevant security standards (OWASP, CVE, CWE) when applicable
5. Consider the broader attack surface and potential attack chains

When provided with context from previous scans, use that information to give
more accurate and contextual responses. Always cite which scan results or
documents you're referencing in your analysis.

If you don't have enough information to make a security assessment, ask for
clarification or recommend additional reconnaissance steps.

Be concise but thorough. Security professionals need actionable intelligence, not fluff."""

    async def initialize_vector_store(self) -> bool:
        """Initialize or load the vector store"""
        try:
            if os.path.exists(self._vector_store_path):
                self._vector_store = FAISS.load_local(
                    self._vector_store_path,
                    self.embeddings,
                    allow_dangerous_deserialization=True
                )
                print(f"Loaded existing vector store from {self._vector_store_path}")
            else:
                # Create empty vector store with a placeholder document
                placeholder = Document(
                    page_content="AETHER Intelligence System Initialized",
                    metadata={"type": "system", "id": "init"}
                )
                self._vector_store = FAISS.from_documents([placeholder], self.embeddings)
                self._save_vector_store()
                print("Created new vector store")
            return True
        except Exception as e:
            print(f"Error initializing vector store: {e}")
            return False
    
    def _save_vector_store(self):
        """Save vector store to disk"""
        if self._vector_store:
            os.makedirs(self._vector_store_path, exist_ok=True)
            self._vector_store.save_local(self._vector_store_path)
    
    async def ingest_document(
        self,
        title: str,
        content: str,
        source_type: SourceType,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Tuple[str, int]:
        """
        Ingest a document into the vector store.
        Returns (document_id, chunks_created)
        """
        doc_id = str(uuid.uuid4())
        
        # Split content into chunks
        chunks = self.text_splitter.split_text(content)
        
        # Create documents with metadata
        documents = []
        for i, chunk in enumerate(chunks):
            doc_metadata = {
                "doc_id": doc_id,
                "title": title,
                "source_type": source_type.value,
                "chunk_index": i,
                "total_chunks": len(chunks),
                "created_at": datetime.utcnow().isoformat(),
                **(metadata or {})
            }
            documents.append(Document(page_content=chunk, metadata=doc_metadata))
        
        # Store document metadata
        self._document_metadata[doc_id] = {
            "title": title,
            "source_type": source_type,
            "chunks": len(chunks),
            "created_at": datetime.utcnow(),
            "metadata": metadata
        }
        
        # Add to vector store
        if self._vector_store is None:
            await self.initialize_vector_store()
        
        self._vector_store.add_documents(documents)
        self._save_vector_store()
        
        return doc_id, len(chunks)
    
    async def ingest_scan_results(
        self,
        scan_id: str,
        scan_type: str,
        target: str,
        results: Dict[str, Any],
        metadata: Optional[Dict[str, Any]] = None
    ) -> Tuple[str, int]:
        """
        Ingest scan results into the vector store.
        Formats scan results as readable text for embedding.
        """
        # Format scan results as text
        content_parts = [
            f"# {scan_type.upper()} Scan Results",
            f"**Target:** {target}",
            f"**Scan ID:** {scan_id}",
            f"**Timestamp:** {datetime.utcnow().isoformat()}",
            ""
        ]
        
        # Format results based on scan type
        if scan_type.lower() == "recon":
            content_parts.extend(self._format_recon_results(results))
        elif scan_type.lower() == "enumeration":
            content_parts.extend(self._format_enum_results(results))
        else:
            content_parts.append(f"```json\n{str(results)}\n```")
        
        content = "\n".join(content_parts)
        
        source_type = (
            SourceType.RECON_SCAN if scan_type.lower() == "recon"
            else SourceType.ENUM_SCAN
        )
        
        doc_metadata = {
            "scan_id": scan_id,
            "scan_type": scan_type,
            "target": target,
            **(metadata or {})
        }
        
        return await self.ingest_document(
            title=f"{scan_type.title()} Scan: {target}",
            content=content,
            source_type=source_type,
            metadata=doc_metadata
        )
    
    def _format_recon_results(self, results: Dict[str, Any]) -> List[str]:
        """Format recon scan results as readable text"""
        parts = []
        
        if "ports" in results:
            parts.append("## Open Ports")
            for port in results.get("ports", []):
                parts.append(f"- Port {port.get('port', 'N/A')}: {port.get('service', 'unknown')} ({port.get('state', 'unknown')})")
        
        if "subdomains" in results:
            parts.append("\n## Subdomains")
            for subdomain in results.get("subdomains", []):
                parts.append(f"- {subdomain}")
        
        if "technologies" in results:
            parts.append("\n## Technologies Detected")
            for tech in results.get("technologies", []):
                parts.append(f"- {tech}")
        
        if "dns" in results:
            parts.append("\n## DNS Records")
            for record_type, records in results.get("dns", {}).items():
                parts.append(f"### {record_type}")
                for record in records:
                    parts.append(f"- {record}")
        
        if "whois" in results:
            parts.append("\n## WHOIS Information")
            parts.append(str(results.get("whois", {})))
        
        return parts
    
    def _format_enum_results(self, results: Dict[str, Any]) -> List[str]:
        """Format enumeration scan results as readable text"""
        parts = []
        
        if "vulnerabilities" in results:
            parts.append("## Vulnerabilities Found")
            for vuln in results.get("vulnerabilities", []):
                severity = vuln.get("severity", "unknown").upper()
                parts.append(f"\n### [{severity}] {vuln.get('name', 'Unknown Vulnerability')}")
                parts.append(f"- **Description:** {vuln.get('description', 'N/A')}")
                parts.append(f"- **CVE:** {vuln.get('cve', 'N/A')}")
                parts.append(f"- **Remediation:** {vuln.get('remediation', 'N/A')}")
        
        if "services" in results:
            parts.append("\n## Services Enumerated")
            for service in results.get("services", []):
                parts.append(f"- {service.get('name', 'Unknown')}: {service.get('version', 'N/A')}")
        
        if "findings" in results:
            parts.append("\n## Additional Findings")
            for finding in results.get("findings", []):
                parts.append(f"- {finding}")
        
        return parts
    
    async def retrieve_context(
        self,
        query: str,
        k: Optional[int] = None
    ) -> List[Tuple[Document, float]]:
        """Retrieve relevant documents for a query"""
        if self._vector_store is None:
            await self.initialize_vector_store()
        
        k = k or self.retrieval_k
        
        # Perform similarity search with scores
        results = self._vector_store.similarity_search_with_score(query, k=k)
        
        return results
    
    async def chat(
        self,
        message: str,
        conversation_history: Optional[List[ChatMessage]] = None,
        include_scan_context: bool = True
    ) -> Tuple[str, List[SourceReference], Optional[str]]:
        """
        Process a chat message with RAG.
        Returns (response, sources, thinking)
        """
        sources: List[SourceReference] = []
        context_text = ""
        
        # Retrieve relevant context if enabled
        if include_scan_context:
            retrieved_docs = await self.retrieve_context(message)
            
            if retrieved_docs:
                context_parts = []
                seen_doc_ids = set()
                
                for doc, score in retrieved_docs:
                    doc_id = doc.metadata.get("doc_id", str(uuid.uuid4()))
                    
                    # Skip placeholder documents
                    if doc.metadata.get("type") == "system":
                        continue
                    
                    context_parts.append(f"[Source: {doc.metadata.get('title', 'Unknown')}]\n{doc.page_content}")
                    
                    # Add to sources if not already added
                    if doc_id not in seen_doc_ids:
                        seen_doc_ids.add(doc_id)
                        sources.append(SourceReference(
                            id=doc_id,
                            title=doc.metadata.get("title", "Unknown Document"),
                            source_type=SourceType(doc.metadata.get("source_type", "document")),
                            content_preview=doc.page_content[:200] + "..." if len(doc.page_content) > 200 else doc.page_content,
                            relevance_score=1.0 - (score / 2.0),  # Convert distance to similarity
                            metadata=doc.metadata
                        ))
                
                context_text = "\n\n---\n\n".join(context_parts)
        
        # Build messages for LLM
        messages = [SystemMessage(content=self._get_system_prompt())]
        
        # Add conversation history
        if conversation_history:
            for msg in conversation_history[-10:]:  # Limit history to last 10 messages
                if msg.role == MessageRole.USER:
                    messages.append(HumanMessage(content=msg.content))
                elif msg.role == MessageRole.ASSISTANT:
                    messages.append(AIMessage(content=msg.content))
        
        # Build the final user message with context
        if context_text:
            user_message = f"""Based on the following security scan data and documents:

{context_text}

---

User Question: {message}

Please analyze this information and provide a detailed security assessment."""
        else:
            user_message = message
        
        messages.append(HumanMessage(content=user_message))
        
        # Generate response
        response = await self.llm.ainvoke(messages)
        response_text = response.content
        
        # Extract thinking if present (for models that support it)
        thinking = None
        if "<think>" in response_text and "</think>" in response_text:
            think_start = response_text.find("<think>") + 7
            think_end = response_text.find("</think>")
            thinking = response_text[think_start:think_end].strip()
            response_text = response_text[think_end + 8:].strip()
        
        return response_text, sources, thinking
    
    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about the vector store"""
        total_docs = len(self._document_metadata)
        recon_count = sum(
            1 for d in self._document_metadata.values()
            if d.get("source_type") == SourceType.RECON_SCAN
        )
        enum_count = sum(
            1 for d in self._document_metadata.values()
            if d.get("source_type") == SourceType.ENUM_SCAN
        )
        total_chunks = sum(
            d.get("chunks", 0) for d in self._document_metadata.values()
        )
        
        return {
            "total_documents": total_docs,
            "recon_scans_count": recon_count,
            "enum_scans_count": enum_count,
            "total_chunks": total_chunks,
            "vector_store_status": "active" if self._vector_store else "not_initialized"
        }


# Global RAG service instance
rag_service = RAGService()
