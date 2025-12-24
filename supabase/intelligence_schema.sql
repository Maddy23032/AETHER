-- =====================================================
-- AETHER Intelligence RAG Schema
-- Run this in your Supabase SQL Editor
-- =====================================================

-- Enable UUID extension if not already enabled
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- =====================================================
-- 1. Documents Table - Stores ingested documents/files
-- =====================================================
CREATE TABLE IF NOT EXISTS intelligence_documents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    title TEXT NOT NULL,
    source_type TEXT NOT NULL CHECK (source_type IN ('recon_scan', 'enum_scan', 'document', 'knowledge_base', 'uploaded_file', 'image')),
    original_filename TEXT,
    file_path TEXT,  -- Storage path if file is stored in Supabase Storage
    file_size INTEGER,
    mime_type TEXT,
    content TEXT,  -- Raw text content (for text files)
    summary TEXT,  -- AI-generated summary
    chunk_count INTEGER DEFAULT 0,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- =====================================================
-- 2. Document Chunks Table - Stores embeddings
-- =====================================================
CREATE TABLE IF NOT EXISTS intelligence_chunks (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    document_id UUID NOT NULL REFERENCES intelligence_documents(id) ON DELETE CASCADE,
    chunk_index INTEGER NOT NULL,
    content TEXT NOT NULL,
    embedding VECTOR(384),  -- For all-MiniLM-L6-v2 (384 dimensions)
    token_count INTEGER,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- =====================================================
-- 3. Chat Sessions Table - Stores conversation sessions
-- =====================================================
CREATE TABLE IF NOT EXISTS intelligence_chat_sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    title TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    metadata JSONB DEFAULT '{}'
);

-- =====================================================
-- 4. Chat Messages Table - Stores individual messages
-- =====================================================
CREATE TABLE IF NOT EXISTS intelligence_chat_messages (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id UUID REFERENCES intelligence_chat_sessions(id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK (role IN ('user', 'assistant', 'system')),
    content TEXT NOT NULL,
    attachments JSONB DEFAULT '[]',  -- Array of {type, url, filename, etc.}
    sources JSONB DEFAULT '[]',  -- References used for this message
    thinking TEXT,  -- AI reasoning/thinking
    processing_time_ms FLOAT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- =====================================================
-- 5. Uploaded Files Table - Tracks user uploads
-- =====================================================
CREATE TABLE IF NOT EXISTS intelligence_uploads (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    filename TEXT NOT NULL,
    original_filename TEXT NOT NULL,
    file_path TEXT NOT NULL,  -- Supabase Storage path
    file_size INTEGER NOT NULL,
    mime_type TEXT NOT NULL,
    file_type TEXT NOT NULL CHECK (file_type IN ('image', 'document', 'scan_log', 'other')),
    is_processed BOOLEAN DEFAULT FALSE,
    document_id UUID REFERENCES intelligence_documents(id) ON DELETE SET NULL,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- =====================================================
-- 6. Scan Ingestion Log - Tracks which scans are ingested
-- =====================================================
CREATE TABLE IF NOT EXISTS intelligence_scan_ingestion (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id TEXT NOT NULL UNIQUE,
    scan_type TEXT NOT NULL CHECK (scan_type IN ('recon', 'enumeration')),
    target TEXT NOT NULL,
    document_id UUID REFERENCES intelligence_documents(id) ON DELETE SET NULL,
    ingested_at TIMESTAMPTZ DEFAULT NOW(),
    metadata JSONB DEFAULT '{}'
);

-- =====================================================
-- Indexes for better query performance
-- =====================================================

-- Index on document source type
CREATE INDEX IF NOT EXISTS idx_documents_source_type ON intelligence_documents(source_type);
CREATE INDEX IF NOT EXISTS idx_documents_created_at ON intelligence_documents(created_at DESC);

-- Index on chunks for document lookup
CREATE INDEX IF NOT EXISTS idx_chunks_document_id ON intelligence_chunks(document_id);

-- Index for vector similarity search (requires pgvector extension)
-- CREATE INDEX IF NOT EXISTS idx_chunks_embedding ON intelligence_chunks USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100);

-- Index on chat messages
CREATE INDEX IF NOT EXISTS idx_messages_session_id ON intelligence_chat_messages(session_id);
CREATE INDEX IF NOT EXISTS idx_messages_created_at ON intelligence_chat_messages(created_at DESC);

-- Index on uploads
CREATE INDEX IF NOT EXISTS idx_uploads_file_type ON intelligence_uploads(file_type);
CREATE INDEX IF NOT EXISTS idx_uploads_created_at ON intelligence_uploads(created_at DESC);

-- Index on scan ingestion
CREATE INDEX IF NOT EXISTS idx_scan_ingestion_scan_id ON intelligence_scan_ingestion(scan_id);
CREATE INDEX IF NOT EXISTS idx_scan_ingestion_scan_type ON intelligence_scan_ingestion(scan_type);

-- =====================================================
-- Row Level Security (RLS) - Optional
-- =====================================================
-- Enable RLS on tables (uncomment if you want user-specific access)
-- ALTER TABLE intelligence_documents ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE intelligence_chunks ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE intelligence_chat_sessions ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE intelligence_chat_messages ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE intelligence_uploads ENABLE ROW LEVEL SECURITY;

-- =====================================================
-- Storage Bucket for uploads (run separately)
-- =====================================================
-- INSERT INTO storage.buckets (id, name, public)
-- VALUES ('intelligence-uploads', 'intelligence-uploads', false)
-- ON CONFLICT (id) DO NOTHING;

-- =====================================================
-- Helper Functions
-- =====================================================

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Triggers for updated_at
DROP TRIGGER IF EXISTS update_documents_updated_at ON intelligence_documents;
CREATE TRIGGER update_documents_updated_at
    BEFORE UPDATE ON intelligence_documents
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_sessions_updated_at ON intelligence_chat_sessions;
CREATE TRIGGER update_sessions_updated_at
    BEFORE UPDATE ON intelligence_chat_sessions
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- =====================================================
-- Sample Data (Optional - for testing)
-- =====================================================
-- INSERT INTO intelligence_documents (title, source_type, content, metadata)
-- VALUES 
--     ('Sample Recon Scan', 'recon_scan', 'Port 80: HTTP, Port 443: HTTPS', '{"target": "example.com"}'),
--     ('OWASP Top 10 Guide', 'knowledge_base', 'SQL Injection prevention...', '{"category": "security"}');
