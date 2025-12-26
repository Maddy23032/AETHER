# AETHER Intelligence API

RAG-powered security analysis assistant backend for the AETHER platform.

## Overview

This service provides an AI-powered security analysis assistant that uses Retrieval-Augmented Generation (RAG) to answer questions about your security scan results. It ingests data from recon and enumeration scans, embeds them into a vector store, and uses them as context when generating responses.

## Stack

- **FastAPI** - Modern async web framework
- **LangChain** - LLM orchestration framework
- **Groq** - Fast LLM inference (using qwen/qwen3-32b)
- **HuggingFace Embeddings** - Sentence embeddings (all-MiniLM-L6-v2)
- **FAISS** - Vector similarity search

## Setup

### 1. Create Virtual Environment

```bash
cd "backend (intelligence)"
python -m venv venv
.\venv\Scripts\activate  # Windows
# source venv/bin/activate  # Linux/Mac
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure Environment

Copy `.env.example` to `.env` and update values if needed:

```bash
copy .env.example .env
```

The Groq API key is already configured. You can update other settings as needed.

### 4. Run the Server

```bash
uvicorn app.main:app --reload --port 8002
```

The API will be available at `http://localhost:8002`

## API Endpoints

### Health & Info
- `GET /` - Service info
- `GET /api/intelligence/health` - Health check

### Chat
- `POST /api/intelligence/chat` - Send a message to the AI assistant
- `GET /api/intelligence/suggested-prompts` - Get suggested prompts
- `GET /api/intelligence/context-stats` - Get context statistics

### References
- `GET /api/intelligence/references` - List all references
- `GET /api/intelligence/references/{id}` - Get specific reference
- `POST /api/intelligence/references/search` - Semantic search

### Ingestion
- `POST /api/intelligence/ingest/document` - Ingest a document
- `POST /api/intelligence/ingest/scan` - Ingest scan results
- `POST /api/intelligence/initialize` - Initialize vector store

## Integration with AETHER

### Ingesting Scan Results

When a scan completes in the recon or enumeration backend, send the results to this service:

```python
import httpx

async def ingest_scan_to_intelligence(scan_id, scan_type, target, results):
    async with httpx.AsyncClient() as client:
        response = await client.post(
            "http://localhost:8002/api/intelligence/ingest/scan",
            json={
                "scan_id": scan_id,
                "scan_type": scan_type,  # "recon" or "enumeration"
                "target": target,
                "results": results
            }
        )
        return response.json()
```

### Chat Integration

From the frontend, send chat messages:

```typescript
const response = await fetch('http://localhost:8002/api/intelligence/chat', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
        message: "What vulnerabilities were found?",
        conversation_history: [],
        include_scan_context: true
    })
});

const data = await response.json();
// data.message - AI response
// data.sources - References used
// data.thinking - AI reasoning (if available)
```

## Port Configuration

| Service | Port |
|---------|------|
| Recon Backend | 8000 |
| Enumeration Backend | 8001 |
| **Intelligence Backend** | **8002** |
| Frontend (Vite) | 5173 |

## Vector Store

The vector store is persisted to `./vector_store/` by default. This allows the knowledge base to persist across restarts.

To reset the knowledge base, simply delete the `vector_store/` directory and restart the service.
