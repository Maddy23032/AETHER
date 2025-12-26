/**
 * Intelligence API Service
 * Client for the RAG-powered security analysis assistant backend
 */

const INTELLIGENCE_API_URL = import.meta.env.VITE_INTELLIGENCE_API_URL || 'http://localhost:8002';

// ===== Types =====

export type MessageRole = 'user' | 'assistant' | 'system';

export type SourceType = 'recon_scan' | 'enum_scan' | 'document' | 'knowledge_base';

export interface ChatMessage {
  role: MessageRole;
  content: string;
  timestamp?: string;
}

export interface SourceReference {
  id: string;
  title: string;
  source_type: SourceType;
  content_preview: string;
  relevance_score: number;
  metadata?: Record<string, unknown>;
  created_at?: string;
}

export interface ChatRequest {
  message: string;
  conversation_history?: ChatMessage[];
  include_scan_context?: boolean;
}

export interface ChatResponse {
  message: string;
  sources: SourceReference[];
  thinking?: string;
  processing_time_ms?: number;
}

export interface SuggestedPrompt {
  text: string;
  category: string;
}

export interface AnalysisContextStats {
  total_documents: number;
  recon_scans_count: number;
  enum_scans_count: number;
  total_chunks: number;
  last_updated?: string;
  vector_store_status: string;
}

export interface Reference {
  id: string;
  title: string;
  source_type: SourceType;
  summary: string;
  content?: string;
  metadata: Record<string, unknown>;
  created_at: string;
  tags: string[];
}

export interface ReferencesResponse {
  references: Reference[];
  total_count: number;
  has_more: boolean;
}

export interface IngestScanRequest {
  scan_id: string;
  scan_type: string;
  target: string;
  results: Record<string, unknown>;
  metadata?: Record<string, unknown>;
}

export interface IngestResponse {
  success: boolean;
  document_id: string;
  chunks_created: number;
  message: string;
}

export interface HealthCheck {
  status: string;
  service: string;
  rag_enabled: boolean;
}

// ===== API Functions =====

/**
 * Check if the Intelligence API is healthy
 */
export async function checkHealth(): Promise<HealthCheck> {
  const response = await fetch(`${INTELLIGENCE_API_URL}/api/intelligence/health`);
  if (!response.ok) {
    throw new Error('Intelligence API is not available');
  }
  return response.json();
}

/**
 * Send a message to the AI assistant
 */
export async function sendChatMessage(request: ChatRequest): Promise<ChatResponse> {
  const response = await fetch(`${INTELLIGENCE_API_URL}/api/intelligence/chat`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      message: request.message,
      conversation_history: request.conversation_history || [],
      include_scan_context: request.include_scan_context ?? true,
    }),
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Unknown error' }));
    throw new Error(error.detail || 'Failed to send message');
  }

  return response.json();
}

/**
 * Get suggested prompts
 */
export async function getSuggestedPrompts(): Promise<SuggestedPrompt[]> {
  const response = await fetch(`${INTELLIGENCE_API_URL}/api/intelligence/suggested-prompts`);
  if (!response.ok) {
    throw new Error('Failed to fetch suggested prompts');
  }
  return response.json();
}

/**
 * Get analysis context statistics
 */
export async function getContextStats(): Promise<AnalysisContextStats> {
  const response = await fetch(`${INTELLIGENCE_API_URL}/api/intelligence/context-stats`);
  if (!response.ok) {
    throw new Error('Failed to fetch context stats');
  }
  return response.json();
}

/**
 * Get list of references
 */
export async function getReferences(
  sourceTypes?: SourceType[],
  searchQuery?: string,
  limit?: number
): Promise<ReferencesResponse> {
  const params = new URLSearchParams();
  if (sourceTypes?.length) {
    sourceTypes.forEach((t) => params.append('source_types', t));
  }
  if (searchQuery) {
    params.set('search_query', searchQuery);
  }
  if (limit) {
    params.set('limit', limit.toString());
  }

  const response = await fetch(`${INTELLIGENCE_API_URL}/api/intelligence/references?${params}`);
  if (!response.ok) {
    throw new Error('Failed to fetch references');
  }
  return response.json();
}

/**
 * Search references semantically
 */
export async function searchReferences(query: string, limit?: number): Promise<Reference[]> {
  const params = new URLSearchParams({ query });
  if (limit) {
    params.set('limit', limit.toString());
  }

  const response = await fetch(`${INTELLIGENCE_API_URL}/api/intelligence/references/search?${params}`, {
    method: 'POST',
  });

  if (!response.ok) {
    throw new Error('Failed to search references');
  }

  const data = await response.json();
  return data.results;
}

/**
 * Ingest scan results into the RAG knowledge base
 */
export async function ingestScanResults(request: IngestScanRequest): Promise<IngestResponse> {
  const response = await fetch(`${INTELLIGENCE_API_URL}/api/intelligence/ingest/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(request),
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Unknown error' }));
    throw new Error(error.detail || 'Failed to ingest scan results');
  }

  return response.json();
}

/**
 * Initialize the vector store
 */
export async function initializeVectorStore(): Promise<{ status: string; message: string }> {
  const response = await fetch(`${INTELLIGENCE_API_URL}/api/intelligence/initialize`, {
    method: 'POST',
  });

  if (!response.ok) {
    throw new Error('Failed to initialize vector store');
  }

  return response.json();
}

/**
 * Get source type display info
 */
export function getSourceTypeInfo(sourceType: SourceType): { label: string; icon: string } {
  switch (sourceType) {
    case 'recon_scan':
      return { label: 'Recon Scan', icon: '🔍' };
    case 'enum_scan':
      return { label: 'Enumeration Scan', icon: '🛡️' };
    case 'document':
      return { label: 'Document', icon: '📄' };
    case 'knowledge_base':
      return { label: 'Knowledge Base', icon: '📚' };
    default:
      return { label: 'Unknown', icon: '❓' };
  }
}
