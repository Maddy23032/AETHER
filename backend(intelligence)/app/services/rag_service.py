"""
RAG Service for AETHER Intelligence
Handles document embedding, vector storage, and retrieval-augmented generation
"""

import os
import uuid
import json
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime

# Set environment variable to use tf-keras before importing transformers/tensorflow
os.environ['TF_USE_LEGACY_KERAS'] = '1'
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'

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
        # Build a summary of available scans
        scan_summary = self._get_available_scans_summary()
        
        base_prompt = """You are AETHER, an advanced AI-powered cybersecurity analysis assistant.
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

        if scan_summary:
            base_prompt += f"\n\n--- AVAILABLE SCAN DATA ---\n{scan_summary}"
        
        return base_prompt
    
    def _get_available_scans_summary(self) -> str:
        """Generate a summary of all available scans for context"""
        if not self._document_metadata:
            return ""
        
        recon_scans = []
        enum_scans = []
        mobile_scans = []
        
        for doc_id, meta in self._document_metadata.items():
            source_type = meta.get("source_type")
            if isinstance(source_type, str):
                try:
                    source_type = SourceType(source_type)
                except ValueError:
                    continue
            
            title = meta.get("title", "Unknown")
            target = meta.get("metadata", {}).get("target", "Unknown target")
            created_at = meta.get("created_at")
            if isinstance(created_at, datetime):
                created_str = created_at.strftime("%Y-%m-%d %H:%M")
            elif isinstance(created_at, str):
                created_str = created_at[:16] if len(created_at) > 16 else created_at
            else:
                created_str = "Unknown time"
            
            scan_info = f"- {title} (target: {target}, scanned: {created_str})"
            
            if source_type == SourceType.RECON_SCAN:
                recon_scans.append((created_at or "", scan_info, doc_id))
            elif source_type == SourceType.ENUM_SCAN:
                enum_scans.append((created_at or "", scan_info, doc_id))
            elif source_type == SourceType.MOBILE_SCAN:
                mobile_scans.append((created_at or "", scan_info, doc_id))
        
        # Sort by date (newest first)
        recon_scans.sort(reverse=True)
        enum_scans.sort(reverse=True)
        mobile_scans.sort(reverse=True)
        
        parts = []
        if recon_scans:
            parts.append(f"**Reconnaissance Scans ({len(recon_scans)}):**")
            for _, info, _ in recon_scans[:5]:  # Show last 5
                parts.append(info)
        
        if enum_scans:
            parts.append(f"\n**Enumeration/Vulnerability Scans ({len(enum_scans)}):**")
            for _, info, _ in enum_scans[:5]:
                parts.append(info)
        
        if mobile_scans:
            parts.append(f"\n**Mobile Security Scans ({len(mobile_scans)}):**")
            for _, info, _ in mobile_scans[:5]:
                parts.append(info)
        
        return "\n".join(parts) if parts else ""
    
    def _get_latest_scan_context(self, scan_type: Optional[str] = None) -> str:
        """Get the full content of the latest scan(s) for context"""
        if not self._document_metadata:
            return ""
        
        scans_by_type: Dict[str, List[Tuple[Any, str, Dict]]] = {
            "recon": [],
            "enum": [],
            "mobile": []
        }
        
        for doc_id, meta in self._document_metadata.items():
            source_type = meta.get("source_type")
            if isinstance(source_type, str):
                try:
                    source_type = SourceType(source_type)
                except ValueError:
                    continue
            
            created_at = meta.get("created_at", "")
            
            if source_type == SourceType.RECON_SCAN:
                scans_by_type["recon"].append((created_at, doc_id, meta))
            elif source_type == SourceType.ENUM_SCAN:
                scans_by_type["enum"].append((created_at, doc_id, meta))
            elif source_type == SourceType.MOBILE_SCAN:
                scans_by_type["mobile"].append((created_at, doc_id, meta))
        
        # Sort each type by date (newest first)
        for key in scans_by_type:
            scans_by_type[key].sort(reverse=True)
        
        # Determine which scans to include based on scan_type filter
        result_parts = []
        
        if scan_type is None or scan_type == "all":
            # Include latest of each type
            for type_key, type_name in [("recon", "Reconnaissance"), ("enum", "Enumeration"), ("mobile", "Mobile")]:
                if scans_by_type[type_key]:
                    _, doc_id, meta = scans_by_type[type_key][0]
                    result_parts.append(f"\n### Latest {type_name} Scan\n**{meta.get('title', 'Unknown')}**")
        elif scan_type in scans_by_type and scans_by_type[scan_type]:
            _, doc_id, meta = scans_by_type[scan_type][0]
            result_parts.append(f"**{meta.get('title', 'Unknown')}**")
        
        return "\n".join(result_parts)
    
    async def _get_direct_scan_context(
        self,
        scan_types: Optional[List[str]] = None,
        latest_only: bool = True
    ) -> Optional[Dict[str, Any]]:
        """
        Get scan data directly from metadata and vector store for specific scan types.
        Returns dict with 'content' and 'sources'.
        """
        if not self._document_metadata or self._vector_store is None:
            return None
        
        # Categorize scans by type
        scans_by_type: Dict[str, List[Tuple[Any, str, Dict]]] = {
            "recon": [],
            "enum": [],
            "mobile": []
        }
        
        type_mapping = {
            SourceType.RECON_SCAN: "recon",
            SourceType.ENUM_SCAN: "enum",
            SourceType.MOBILE_SCAN: "mobile"
        }
        
        for doc_id, meta in self._document_metadata.items():
            source_type = meta.get("source_type")
            if isinstance(source_type, str):
                try:
                    source_type = SourceType(source_type)
                except ValueError:
                    continue
            
            type_key = type_mapping.get(source_type)
            if type_key:
                created_at = meta.get("created_at", "")
                scans_by_type[type_key].append((created_at, doc_id, meta))
        
        # Sort each by date (newest first)
        for key in scans_by_type:
            scans_by_type[key].sort(reverse=True)
        
        # Determine which scans to retrieve
        scans_to_fetch: List[Tuple[str, Dict]] = []
        
        if scan_types:
            # Get requested types
            for scan_type in scan_types:
                if scan_type in scans_by_type and scans_by_type[scan_type]:
                    if latest_only:
                        _, doc_id, meta = scans_by_type[scan_type][0]
                        scans_to_fetch.append((doc_id, meta))
                    else:
                        for _, doc_id, meta in scans_by_type[scan_type][:3]:  # Limit to 3
                            scans_to_fetch.append((doc_id, meta))
        else:
            # Get latest of each type
            for type_key in ["recon", "enum", "mobile"]:
                if scans_by_type[type_key]:
                    _, doc_id, meta = scans_by_type[type_key][0]
                    scans_to_fetch.append((doc_id, meta))
        
        if not scans_to_fetch:
            return None
        
        # Fetch full content from vector store for each scan
        content_parts = []
        sources: List[SourceReference] = []
        
        for doc_id, meta in scans_to_fetch:
            title = meta.get("title", "Unknown Scan")
            source_type = meta.get("source_type")
            if isinstance(source_type, str):
                source_type = SourceType(source_type)
            
            # Get all chunks for this document by searching with the title
            # and filtering results by doc_id
            try:
                # Fetch more documents to increase chance of finding all chunks
                all_docs = self._vector_store.similarity_search(
                    title,  # Use title as query to find related content
                    k=50,  # Get many results
                )
                
                # Filter by doc_id to get only chunks from this document
                matching_docs = [d for d in all_docs if d.metadata.get("doc_id") == doc_id]
                
                # If we didn't find matching docs, try a more general search
                if not matching_docs:
                    # Get target from metadata for a more specific search
                    target = meta.get("metadata", {}).get("target", "")
                    if target:
                        alt_docs = self._vector_store.similarity_search(target, k=50)
                        matching_docs = [d for d in alt_docs if d.metadata.get("doc_id") == doc_id]
                
                if matching_docs:
                    # Sort by chunk_index if available
                    matching_docs.sort(key=lambda d: d.metadata.get("chunk_index", 0))
                    
                    # Combine chunks
                    combined_content = "\n\n".join([d.page_content for d in matching_docs])
                    content_parts.append(f"### {title}\n{combined_content}")
                    
                    sources.append(SourceReference(
                        id=doc_id,
                        title=title,
                        source_type=source_type,
                        content_preview=combined_content[:300] + "..." if len(combined_content) > 300 else combined_content,
                        relevance_score=1.0,
                        metadata=meta.get("metadata", {})
                    ))
                else:
                    # Fallback: include just the metadata info
                    scan_metadata = meta.get("metadata", {})
                    target = scan_metadata.get("target", "Unknown")
                    fallback_content = f"**Target:** {target}\n**Scan Type:** {source_type.value if hasattr(source_type, 'value') else source_type}"
                    content_parts.append(f"### {title}\n{fallback_content}")
                    
                    sources.append(SourceReference(
                        id=doc_id,
                        title=title,
                        source_type=source_type,
                        content_preview=fallback_content,
                        relevance_score=0.8,
                        metadata=scan_metadata
                    ))
            except Exception as e:
                print(f"Error fetching scan context for {doc_id}: {e}")
                continue
        
        if not content_parts:
            return None
        
        return {
            "content": "\n\n---\n\n".join(content_parts),
            "sources": sources
        }

    async def initialize_vector_store(self) -> bool:
        """Initialize or load the vector store"""
        try:
            # Ensure embeddings can load
            _ = self.embeddings

            if os.path.exists(self._vector_store_path):
                self._vector_store = FAISS.load_local(
                    self._vector_store_path,
                    self.embeddings,
                    allow_dangerous_deserialization=True
                )
                # Load document metadata if it exists
                self._load_document_metadata()
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
            
            print(f"[RAG] Vector store initialized with {len(self._document_metadata)} documents in metadata")
            return True
        except Exception as e:
            print(f"Error initializing vector store: {e}")
            return False
    
    async def load_scans_from_supabase(self) -> int:
        """
        Load all scans from Supabase and ingest them into the vector store.
        Returns the number of scans loaded.
        """
        from app.services.supabase_service import supabase_service
        
        total_loaded = 0
        
        try:
            # Load recon scans
            print("[RAG] Loading recon scans from Supabase...")
            recon_scans = await supabase_service.get_all_recon_scans()
            for scan_data in recon_scans:
                try:
                    scan = scan_data.get("scan", {})
                    findings = scan_data.get("findings", [])
                    results = scan_data.get("results", [])
                    
                    scan_id = scan.get("id", "")
                    target = scan.get("target_url", "Unknown")
                    
                    # Skip if already in metadata
                    existing_ids = [m.get("metadata", {}).get("scan_id") for m in self._document_metadata.values()]
                    if scan_id in existing_ids:
                        continue
                    
                    # Format results for ingestion
                    formatted_results = {
                        "findings": [
                            {
                                "tool": f.get("tool"),
                                "severity": f.get("severity"),
                                "name": f.get("name"),
                                "description": f.get("description"),
                                "endpoint": f.get("endpoint"),
                            }
                            for f in findings
                        ],
                        "tools_executed": list(set(r.get("tool", "") for r in results)),
                        "tool_results": [
                            {
                                "tool": r.get("tool"),
                                "status": r.get("status"),
                                "execution_time": r.get("execution_time"),
                                "parsed_results": r.get("parsed_results"),
                            }
                            for r in results
                        ],
                    }
                    
                    await self.ingest_scan_results(
                        scan_id=scan_id,
                        scan_type="recon",
                        target=target,
                        results=formatted_results,
                        metadata={"scan_id": scan_id, "loaded_from_supabase": True}
                    )
                    total_loaded += 1
                except Exception as e:
                    print(f"[RAG] Error loading recon scan: {e}")
            
            # Load enumeration scans
            print("[RAG] Loading enumeration scans from Supabase...")
            enum_scans = await supabase_service.get_all_enum_scans()
            for scan_data in enum_scans:
                try:
                    scan = scan_data.get("scan", {})
                    vulnerabilities = scan_data.get("vulnerabilities", [])
                    
                    scan_id = scan.get("id", "")
                    target = scan.get("target_url", "Unknown")
                    
                    # Skip if already in metadata
                    existing_ids = [m.get("metadata", {}).get("scan_id") for m in self._document_metadata.values()]
                    if scan_id in existing_ids:
                        continue
                    
                    # Format results for ingestion
                    formatted_results = {
                        "vulnerabilities": [
                            {
                                "name": v.get("name"),
                                "severity": v.get("severity"),
                                "confidence": v.get("confidence"),
                                "owasp_category": v.get("owasp_category"),
                                "cwe_id": v.get("cwe_id"),
                                "endpoint": v.get("endpoint"),
                                "method": v.get("method"),
                                "description": v.get("description"),
                                "remediation": v.get("remediation"),
                            }
                            for v in vulnerabilities
                        ],
                        "stats": scan.get("stats", {}),
                    }
                    
                    await self.ingest_scan_results(
                        scan_id=scan_id,
                        scan_type="enumeration",
                        target=target,
                        results=formatted_results,
                        metadata={"scan_id": scan_id, "loaded_from_supabase": True}
                    )
                    total_loaded += 1
                except Exception as e:
                    print(f"[RAG] Error loading enum scan: {e}")
            
            # Load mobile scans
            print("[RAG] Loading mobile scans from Supabase...")
            mobile_scans = await supabase_service.get_all_mobile_scans()
            for scan in mobile_scans:
                try:
                    scan_id = scan.get("id", scan.get("file_hash", ""))
                    filename = scan.get("filename", "Unknown")
                    
                    # Skip if already in metadata
                    existing_ids = [m.get("metadata", {}).get("scan_id") for m in self._document_metadata.values()]
                    if scan_id in existing_ids:
                        continue
                    
                    # Format results for ingestion - handle None values explicitly
                    formatted_results = {
                        "app_info": {
                            "package_name": scan.get("package_name") or "Unknown",
                            "app_name": scan.get("app_name") or "Unknown",
                            "version": scan.get("version") or "Unknown",
                            "platform": scan.get("platform") or "android",
                        },
                        "security_score": scan.get("security_score") or 0,
                        "grade": scan.get("grade") or "N/A",
                        "permissions": scan.get("permissions") or {},
                        "security_issues": scan.get("security_issues") or [],
                        "scorecard": scan.get("scorecard") or {},
                    }
                    
                    await self.ingest_scan_results(
                        scan_id=scan_id,
                        scan_type="mobile",
                        target=filename,
                        results=formatted_results,
                        metadata={"scan_id": scan_id, "file_hash": scan.get("file_hash"), "loaded_from_supabase": True}
                    )
                    total_loaded += 1
                except Exception as e:
                    print(f"[RAG] Error loading mobile scan: {e}")
            
            print(f"[RAG] Loaded {total_loaded} scans from Supabase into vector store")
            return total_loaded
        except Exception as e:
            print(f"[RAG] Error loading scans from Supabase: {e}")
            return total_loaded
    
    def _save_vector_store(self):
        """Save vector store and metadata to disk"""
        if self._vector_store:
            os.makedirs(self._vector_store_path, exist_ok=True)
            self._vector_store.save_local(self._vector_store_path)
            self._save_document_metadata()
    
    def _save_document_metadata(self):
        """Save document metadata to a JSON file"""
        metadata_path = os.path.join(self._vector_store_path, "document_metadata.json")
        # Convert metadata for JSON serialization
        serializable_metadata = {}
        for doc_id, meta in self._document_metadata.items():
            serializable_meta = {}
            for key, value in meta.items():
                if isinstance(value, datetime):
                    serializable_meta[key] = value.isoformat()
                elif isinstance(value, SourceType):
                    serializable_meta[key] = value.value
                else:
                    serializable_meta[key] = value
            serializable_metadata[doc_id] = serializable_meta
        
        with open(metadata_path, 'w') as f:
            json.dump(serializable_metadata, f, indent=2)
    
    def _load_document_metadata(self):
        """Load document metadata from JSON file"""
        metadata_path = os.path.join(self._vector_store_path, "document_metadata.json")
        if os.path.exists(metadata_path):
            try:
                with open(metadata_path, 'r') as f:
                    loaded_metadata = json.load(f)
                
                # Convert back from JSON
                for doc_id, meta in loaded_metadata.items():
                    restored_meta = {}
                    for key, value in meta.items():
                        if key == "created_at" and value:
                            restored_meta[key] = datetime.fromisoformat(value)
                        elif key == "source_type" and value:
                            try:
                                restored_meta[key] = SourceType(value)
                            except ValueError:
                                restored_meta[key] = value
                        else:
                            restored_meta[key] = value
                    self._document_metadata[doc_id] = restored_meta
                
                print(f"Loaded {len(self._document_metadata)} document metadata entries")
            except Exception as e:
                print(f"Error loading document metadata: {e}")
    
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
        print(f"[RAG] Ingesting {scan_type} scan for target: {target}, scan_id: {scan_id}")
        
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
        elif scan_type.lower() == "mobile":
            content_parts.extend(self._format_mobile_results(results))
        else:
            content_parts.append(f"```json\n{str(results)}\n```")
        
        content = "\n".join(content_parts)
        
        if scan_type.lower() == "recon":
            source_type = SourceType.RECON_SCAN
        elif scan_type.lower() == "mobile":
            source_type = SourceType.MOBILE_SCAN
        else:
            source_type = SourceType.ENUM_SCAN
        
        doc_metadata = {
            "scan_id": scan_id,
            "scan_type": scan_type,
            "target": target,
            **(metadata or {})
        }
        
        doc_id, chunks = await self.ingest_document(
            title=f"{scan_type.title()} Scan: {target}",
            content=content,
            source_type=source_type,
            metadata=doc_metadata
        )
        
        print(f"[RAG] Successfully ingested {scan_type} scan with doc_id: {doc_id}, chunks: {chunks}")
        return doc_id, chunks
    
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
    
    def _format_mobile_results(self, results: Dict[str, Any]) -> List[str]:
        """Format mobile security scan results as readable text"""
        parts = []
        
        # App Information
        if "app_info" in results:
            parts.append("## Application Information")
            info = results["app_info"]
            parts.append(f"- **Package Name:** {info.get('package_name', 'N/A')}")
            parts.append(f"- **App Name:** {info.get('app_name', 'N/A')}")
            parts.append(f"- **Version:** {info.get('version', 'N/A')}")
            parts.append(f"- **Platform:** {info.get('platform', 'N/A')}")
            parts.append(f"- **Min SDK:** {info.get('min_sdk', 'N/A')}")
            parts.append(f"- **Target SDK:** {info.get('target_sdk', 'N/A')}")
        
        # Security Score
        if "security_score" in results:
            parts.append(f"\n## Security Score: {results['security_score']}/100")
            if "grade" in results:
                parts.append(f"**Grade:** {results['grade']}")
        
        # Permissions
        if "permissions" in results:
            perms = results["permissions"] or {}
            if perms and isinstance(perms, dict):
                parts.append("\n## Permissions")
                dangerous = perms.get("dangerous") or []
                if dangerous:
                    parts.append("### Dangerous Permissions")
                    for perm in dangerous:
                        parts.append(f"- ⚠️ {perm}")
                normal = perms.get("normal") or []
                if normal:
                    parts.append("### Normal Permissions")
                    for perm in normal[:10]:  # Limit to 10
                        parts.append(f"- {perm}")
        
        # Security Issues
        if "security_issues" in results:
            security_issues = results.get("security_issues") or []
            if security_issues:
                parts.append("\n## Security Issues")
                for issue in security_issues:
                    if isinstance(issue, dict):
                        severity = issue.get("severity", "info").upper()
                        parts.append(f"\n### [{severity}] {issue.get('title', 'Unknown Issue')}")
                        parts.append(f"- **Description:** {issue.get('description', 'N/A')}")
                        if issue.get("cvss"):
                            parts.append(f"- **CVSS:** {issue['cvss']}")
        
        # Malware Analysis
        if "malware_analysis" in results:
            parts.append("\n## Malware Analysis")
            malware = results["malware_analysis"]
            parts.append(f"- **Detected:** {malware.get('detected', False)}")
            if malware.get("threats"):
                parts.append("### Threats Found")
                for threat in malware["threats"]:
                    parts.append(f"- 🔴 {threat}")
        
        # Hardcoded Secrets
        if "secrets" in results:
            secrets = results.get("secrets") or []
            if secrets:
                parts.append("\n## Hardcoded Secrets/Keys")
                for secret in secrets[:5]:  # Limit to 5
                    if isinstance(secret, dict):
                        parts.append(f"- **{secret.get('type', 'Unknown')}:** {secret.get('file', 'N/A')}")
        
        # URLs and Domains
        if "urls" in results:
            urls = results.get("urls") or []
            if urls:
                parts.append("\n## Embedded URLs")
                for url in urls[:10]:  # Limit to 10
                    parts.append(f"- {url}")
        
        # Components
        if "components" in results:
            parts.append("\n## App Components")
            comps = results["components"]
            if "activities" in comps:
                parts.append(f"- **Activities:** {len(comps['activities'])}")
            if "services" in comps:
                parts.append(f"- **Services:** {len(comps['services'])}")
            if "receivers" in comps:
                parts.append(f"- **Receivers:** {len(comps['receivers'])}")
            if "providers" in comps:
                parts.append(f"- **Providers:** {len(comps['providers'])}")
        
        return parts
    
    async def retrieve_context(
        self,
        query: str,
        k: Optional[int] = None
    ) -> List[Tuple[Document, float]]:
        """Retrieve relevant documents for a query"""
        if self._vector_store is None:
            success = await self.initialize_vector_store()
            if not success or self._vector_store is None:
                raise RuntimeError("Vector store not initialized; check embeddings/model dependencies")
        
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
        print(f"[Chat] Received message: {message[:100]}...")
        print(f"[Chat] Available documents: {len(self._document_metadata)}")
        
        sources: List[SourceReference] = []
        context_text = ""
        
        # Detect if user is asking about specific scan types
        message_lower = message.lower()
        scan_type_keywords = {
            "recon": ["recon", "reconnaissance", "discovery", "subdomain", "port scan"],
            "enum": ["enum", "enumeration", "vulnerability", "vuln scan", "security scan", "web scan"],
            "mobile": ["mobile", "apk", "android", "ios", "app scan", "mobile scan", "ipa"]
        }
        
        requested_scan_types = []
        for scan_type, keywords in scan_type_keywords.items():
            if any(kw in message_lower for kw in keywords):
                requested_scan_types.append(scan_type)
        
        # Check for "latest" or "recent" keywords
        is_asking_latest = any(kw in message_lower for kw in ["latest", "recent", "last", "newest", "current"])
        
        print(f"[Chat] Detected scan types: {requested_scan_types}, is_asking_latest: {is_asking_latest}")
        
        # Retrieve relevant context if enabled
        if include_scan_context:
            # If asking about specific scan types or latest scans, get those directly
            if requested_scan_types or is_asking_latest:
                print(f"[Chat] Fetching direct scan context...")
                direct_context = await self._get_direct_scan_context(
                    scan_types=requested_scan_types if requested_scan_types else None,
                    latest_only=is_asking_latest
                )
                if direct_context:
                    context_text = direct_context["content"]
                    sources = direct_context["sources"]
                    print(f"[Chat] Direct context found: {len(sources)} sources, content length: {len(context_text)}")
                else:
                    print(f"[Chat] No direct context found for scan types: {requested_scan_types}")
            
            # Also do similarity search for additional context
            retrieved_docs = await self.retrieve_context(message)
            print(f"[Chat] Similarity search returned {len(retrieved_docs)} documents")
            
            if retrieved_docs:
                context_parts = [context_text] if context_text else []
                seen_doc_ids = {s.id for s in sources}
                
                for doc, score in retrieved_docs:
                    doc_id = doc.metadata.get("doc_id", str(uuid.uuid4()))
                    
                    # Skip placeholder documents
                    if doc.metadata.get("type") == "system":
                        continue
                    
                    # Skip if already added from direct context
                    if doc_id in seen_doc_ids:
                        continue
                    
                    context_parts.append(f"[Source: {doc.metadata.get('title', 'Unknown')}]\n{doc.page_content}")
                    
                    # Add to sources if not already added
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
        
        print(f"[Chat] Final context text length: {len(context_text)}, total sources: {len(sources)}")
        
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
        mobile_count = sum(
            1 for d in self._document_metadata.values()
            if d.get("source_type") == SourceType.MOBILE_SCAN
        )
        total_chunks = sum(
            d.get("chunks", 0) for d in self._document_metadata.values()
        )
        
        return {
            "total_documents": total_docs,
            "recon_scans_count": recon_count,
            "enum_scans_count": enum_count,
            "mobile_scans_count": mobile_count,
            "total_chunks": total_chunks,
            "vector_store_status": "active" if self._vector_store else "not_initialized"
        }


# Global RAG service instance
rag_service = RAGService()
