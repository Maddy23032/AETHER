# AETHER Reconnaissance API - Setup Guide

## Overview

This backend API provides reconnaissance tools for security testing. It features **intelligent fallback implementations** that work on any operating system (Windows, Linux, macOS) without requiring actual security tools to be installed.

## How It Works

The API automatically detects if reconnaissance tools are installed:
- ✅ **Tool installed** → Uses real CLI tool (faster, more accurate)
- ✅ **Tool not found** → Uses Python fallback implementation (works everywhere)

## Quick Setup

### Prerequisites

- **Python 3.9 or higher**
- **pip** (Python package manager)

### Installation Steps

1. **Navigate to backend folder**
```bash
cd AETHER/back-end
```

2. **Create virtual environment**
```bash
# Windows
python -m venv venv

# Linux/Mac
python3 -m venv venv
```

3. **Activate virtual environment**
```bash
# Windows PowerShell
.\venv\Scripts\Activate.ps1

# Windows Command Prompt
venv\Scripts\activate.bat

# Linux/Mac
source venv/bin/activate
```

4. **Install dependencies**
```bash
pip install -r requirements.txt
```

5. **Install additional libraries (for fallback tools)**
```bash
pip install dnspython requests beautifulsoup4 lxml
```

6. **Run the API**
```bash
# Start the server
uvicorn app.main:app --reload --host 127.0.0.1 --port 3001

# Or with custom host/port
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

7. **Verify it's running**
- Open browser: http://localhost:3001/docs
- Health check: http://localhost:3001/
- Should return: `{"service":"AETHER Reconnaissance API","status":"operational","version":"1.0.0"}`

## Available Tools

All tools have Python fallback implementations:

| Tool | Purpose | Fallback Implementation |
|------|---------|------------------------|
| **nmap** | Port scanning & service detection | Python socket scanner |
| **whatweb** | Web technology identification | Python HTTP analyzer |
| **nikto** | Web vulnerability scanning | Python security checker |
| **gobuster** | Directory/file discovery | Python path brute-forcer |
| **subfinder** | Subdomain enumeration | Python DNS resolver |
| **amass** | Advanced subdomain discovery | Python OSINT aggregator |
| **dnsenum** | DNS enumeration | Python DNS query tool |
| **httpx** | HTTP toolkit | Python HTTP prober |
| **theharvester** | Email/subdomain harvesting | Python search scraper |

## API Endpoints

### Health Check
```bash
GET http://localhost:3001/
```

### List Available Tools
```bash
GET http://localhost:3001/api/tools
```

### Run Tool Scans
```bash
POST http://localhost:3001/api/recon/{tool}
```

### Interactive Documentation
- **Swagger UI**: http://localhost:3001/docs
- **ReDoc**: http://localhost:3001/redoc

## Configuration

### Environment Variables (Optional)

Create a `.env` file in the `back-end/` folder:

```env
# API Configuration
HOST=127.0.0.1
PORT=3001

# Security
RATE_LIMIT_PER_MINUTE=60
MAX_CONCURRENT_SCANS=5

# Tool Paths (optional - only if you have tools installed)
NMAP_PATH=/usr/bin/nmap
NIKTO_PATH=/usr/bin/nikto
GOBUSTER_PATH=/usr/bin/gobuster
```

## Troubleshooting

### Port Already in Use
```bash
# Find and kill process using port 3001
# Windows
netstat -ano | findstr :3001
taskkill /PID <PID> /F

# Linux/Mac
lsof -ti:3001 | xargs kill -9
```

### Import Errors
```bash
# Reinstall dependencies
pip install --upgrade -r requirements.txt
```

### Module Not Found
```bash
# Make sure virtual environment is activated
# Windows
.\venv\Scripts\Activate.ps1

# Verify Python version
python --version  # Should be 3.9+
```

### CORS Errors (from Frontend)
The API already has CORS enabled for all origins. If you still get errors:
- Check if API is running on the correct port
- Verify frontend is using correct API URL in `.env`
- Check browser console for actual error message

## Development

### Project Structure
```
back-end/
├── app/
│   ├── main.py              # FastAPI app entry point
│   ├── core/
│   │   ├── config.py        # Configuration
│   │   ├── executor.py      # Tool execution
│   │   ├── python_tools.py  # Fallback implementations
│   │   └── security.py      # Input validation
│   ├── routers/             # API endpoints
│   │   ├── nmap.py
│   │   ├── nikto.py
│   │   └── ...
│   ├── models/              # Request/response models
│   └── utils/               # Utilities
├── requirements.txt         # Python dependencies
└── SETUP.md                # This file
```

### Adding New Tools

1. Create router in `app/routers/newtool.py`
2. Implement fallback in `app/core/python_tools.py`
3. Register router in `app/main.py`
4. Update `app/main.py` tools list

### Running Tests
```bash
# Install test dependencies
pip install pytest pytest-asyncio httpx

# Run tests
pytest
```

## Production Deployment

### Using Gunicorn (Linux)
```bash
pip install gunicorn
gunicorn app.main:app -w 4 -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:3001
```

### Using Docker
```bash
# Build image
docker build -t aether-api .

# Run container
docker run -p 3001:3001 aether-api
```

### Security Considerations

- ⚠️ The API accepts target URLs for scanning - ensure proper rate limiting
- ⚠️ Configure CORS for production (don't use `allow_origins=["*"]`)
- ⚠️ Use HTTPS in production
- ⚠️ Implement authentication/authorization as needed
- ⚠️ Monitor API usage and implement abuse prevention

## Support

For issues or questions:
1. Check this guide first
2. Review API documentation at `/docs`
3. Check console logs for error details
4. Verify all dependencies are installed

## License

Internal use only - AETHER Security Platform
