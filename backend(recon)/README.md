# AETHER Reconnaissance API

A production-ready Python backend API that exposes multiple Kali Linux reconnaissance tools through secure HTTP endpoints for the AETHER web application.

## 🎯 Overview

AETHER Reconnaissance API is a FastAPI-based service designed to safely execute security reconnaissance tools and return structured JSON results. Built for integration with a React-based web application, it provides a secure, standardized interface to 10 popular reconnaissance tools.

### Key Features

- ✅ **10 Reconnaissance Tools**: nmap, whatweb, nikto, dirsearch, gobuster, amass, theHarvester, dnsenum, subfinder, httpx
- ✅ **Secure Execution**: Input validation, timeout enforcement, subprocess isolation
- ✅ **Standardized Responses**: Consistent JSON format across all tools
- ✅ **Built-in Security**: Blocks localhost, private IPs, and dangerous inputs
- ✅ **OpenAPI Documentation**: Auto-generated interactive API docs
- ✅ **CORS Support**: Ready for React frontend integration

## 🏗️ Architecture

```
aether-recon-api/
├── app/
│   ├── main.py                 # FastAPI application entry point
│   ├── routers/                # Tool-specific endpoints
│   │   ├── nmap.py
│   │   ├── whatweb.py
│   │   ├── nikto.py
│   │   ├── dirsearch.py
│   │   ├── gobuster.py
│   │   ├── amass.py
│   │   ├── theharvester.py
│   │   ├── dnsenum.py
│   │   ├── subfinder.py
│   │   └── httpx.py
│   ├── core/                   # Core functionality
│   │   ├── security.py         # Input validation & sanitization
│   │   ├── executor.py         # Safe subprocess execution
│   │   └── config.py           # Configuration settings
│   ├── models/
│   │   └── responses.py        # Pydantic response models
│   └── utils/
│       └── parsers.py          # Tool output parsers
├── requirements.txt
├── .env.example
└── README.md
```

## 🔧 Available Tools & Endpoints

| Tool | Endpoint | Purpose |
|------|----------|---------|
| **nmap** | `/api/recon/nmap` | Network discovery and port scanning |
| **whatweb** | `/api/recon/whatweb` | Web technology identification |
| **nikto** | `/api/recon/nikto` | Web server vulnerability scanning |
| **dirsearch** | `/api/recon/dirsearch` | Web path and file discovery |
| **gobuster** | `/api/recon/gobuster` | Directory/DNS brute-forcing |
| **amass** | `/api/recon/amass` | Subdomain enumeration (OWASP) |
| **theHarvester** | `/api/recon/theharvester` | OSINT data gathering |
| **dnsenum** | `/api/recon/dnsenum` | DNS enumeration |
| **subfinder** | `/api/recon/subfinder` | Fast passive subdomain discovery |
| **httpx** | `/api/recon/httpx` | Fast HTTP toolkit and probing |

## 📋 Prerequisites

### System Requirements

- **Python**: 3.9 or higher
- **Operating System**: Linux (Kali Linux recommended) or WSL2 on Windows
- **Tools**: All reconnaissance tools must be installed on the system

### Installing Reconnaissance Tools (Kali Linux)

```bash
sudo apt update
sudo apt install -y nmap nikto gobuster amass dnsenum

# WhatWeb
sudo apt install -y whatweb

# Dirsearch
sudo apt install -y dirsearch

# TheHarvester
sudo apt install -y theharvester

# Subfinder
GO111MODULE=on go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# HTTPX
GO111MODULE=on go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```

## 🚀 Setup & Installation

### 1. Clone the Repository

```bash
cd aether-recon-api
```

### 2. Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure Environment

```bash
cp .env.example .env
# Edit .env with your custom settings if needed
```

### 5. Run the API

```bash
# Development mode
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# Production mode
uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4
```

The API will be available at:
- **API**: http://localhost:8000
- **Interactive Docs**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

## 📖 Usage Examples

### Health Check

```bash
curl http://localhost:8000/
```

### List All Tools

```bash
curl http://localhost:8000/api/tools
```

### 1. Nmap - Port Scanning

```bash
curl -X POST http://localhost:8000/api/recon/nmap \
  -H "Content-Type: application/json" \
  -d '{
    "target": "example.com",
    "scan_type": "service",
    "ports": "top-100",
    "timeout": 180
  }'
```

**Scan Types**: `service`, `ping`, `syn`, `full`

### 2. WhatWeb - Technology Detection

```bash
curl -X POST http://localhost:8000/api/recon/whatweb \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://example.com",
    "aggression": 1,
    "timeout": 120
  }'
```

**Aggression Levels**: 1 (stealthy) to 3 (aggressive)

### 3. Nikto - Vulnerability Scanning

```bash
curl -X POST http://localhost:8000/api/recon/nikto \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://example.com",
    "ssl": true,
    "timeout": 240
  }'
```

### 4. Dirsearch - Directory Discovery

```bash
curl -X POST http://localhost:8000/api/recon/dirsearch \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://example.com",
    "wordlist_size": "small",
    "extensions": "php,html,js",
    "timeout": 180
  }'
```

**Wordlist Sizes**: `small`, `medium`

### 5. Gobuster - Directory/DNS Brute-forcing

```bash
curl -X POST http://localhost:8000/api/recon/gobuster \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://example.com",
    "mode": "dir",
    "wordlist_size": "small",
    "timeout": 180
  }'
```

**Modes**: `dir` (directory), `dns` (subdomain)

### 6. Amass - Subdomain Enumeration

```bash
curl -X POST http://localhost:8000/api/recon/amass \
  -H "Content-Type: application/json" \
  -d '{
    "target": "example.com",
    "passive": true,
    "timeout": 180
  }'
```

### 7. TheHarvester - OSINT Gathering

```bash
curl -X POST http://localhost:8000/api/recon/theharvester \
  -H "Content-Type: application/json" \
  -d '{
    "target": "example.com",
    "sources": "google,bing,yahoo",
    "limit": 100,
    "timeout": 180
  }'
```

### 8. DNSenum - DNS Enumeration

```bash
curl -X POST http://localhost:8000/api/recon/dnsenum \
  -H "Content-Type: application/json" \
  -d '{
    "target": "example.com",
    "timeout": 120
  }'
```

### 9. Subfinder - Fast Subdomain Discovery

```bash
curl -X POST http://localhost:8000/api/recon/subfinder \
  -H "Content-Type: application/json" \
  -d '{
    "target": "example.com",
    "silent": true,
    "timeout": 120
  }'
```

### 10. HTTPX - HTTP Probing

```bash
curl -X POST http://localhost:8000/api/recon/httpx \
  -H "Content-Type: application/json" \
  -d '{
    "target": "example.com",
    "tech_detect": true,
    "status_code": true,
    "follow_redirects": true,
    "timeout": 120
  }'
```

## 📤 Response Format

All endpoints return a standardized JSON response:

```json
{
  "tool": "nmap",
  "target": "example.com",
  "status": "success",
  "execution_time": "12.3s",
  "parameters": {
    "ports": "top-100",
    "scan_type": "service"
  },
  "results": {
    "raw": "Raw tool output...",
    "parsed": {
      "hosts": ["example.com"],
      "open_ports": [80, 443],
      "services": [
        {"port": 80, "service": "http"},
        {"port": 443, "service": "https"}
      ]
    }
  },
  "errors": null
}
```

### Response Fields

- **tool**: Name of the reconnaissance tool used
- **target**: Sanitized target that was scanned
- **status**: `success` or `error`
- **execution_time**: Time taken to complete the scan
- **parameters**: Input parameters used for the scan
- **results.raw**: Raw output from the tool
- **results.parsed**: Structured/parsed data (may be empty)
- **errors**: Error message if status is `error`, otherwise `null`

## 🔒 Security Features

### Input Validation

- ✅ Domain and URL format validation
- ✅ Blocks localhost (127.0.0.1, localhost)
- ✅ Blocks private IP ranges (RFC1918)
- ✅ Command injection prevention
- ✅ Argument sanitization

### Execution Safety

- ✅ Subprocess isolation (no shell=True)
- ✅ Timeout enforcement (default 180s, max 300s)
- ✅ Non-root execution (tools don't require elevated privileges)
- ✅ Argument whitelisting per tool

### Target Restrictions

The API blocks the following targets:
- `localhost`, `127.0.0.1`, `0.0.0.0`
- Private IP ranges: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
- Link-local addresses: `169.254.0.0/16`

## ⚖️ Legal & Ethical Disclaimer

**IMPORTANT**: This tool is designed for **authorized security testing only**.

- ✅ Only scan systems you own or have explicit permission to test
- ✅ Respect rate limits and terms of service
- ✅ Comply with local laws and regulations
- ❌ Unauthorized scanning may be illegal in your jurisdiction
- ❌ The developers are not responsible for misuse of this tool

**By using this API, you agree to use it responsibly and ethically.**

## 🛠️ Development

### Running Tests

```bash
# Install development dependencies
pip install pytest pytest-asyncio httpx

# Run tests
pytest
```

### API Documentation

Visit `/docs` for interactive Swagger UI documentation or `/redoc` for ReDoc-style documentation.

### Adding New Tools

1. Create a new router file in `app/routers/`
2. Define request/response models using Pydantic
3. Implement security validation
4. Add parser logic in `app/utils/parsers.py`
5. Register router in `app/main.py`

## 🐛 Troubleshooting

### Tool Not Found Errors

If you receive "Tool not found" errors:

1. Verify tools are installed: `which nmap whatweb nikto`
2. Check tool paths in `.env` file
3. Ensure tools are in system PATH

### Timeout Issues

If scans frequently timeout:

1. Increase timeout values in requests
2. Adjust `DEFAULT_TIMEOUT` in `.env`
3. Use smaller wordlists for directory scanning

### Permission Errors

Some tools may require elevated privileges:

- **nmap SYN scan (-sS)**: Requires root
- **Solution**: Use service scan (-sV) instead or run with sudo (not recommended)

## 📝 Configuration

Edit `.env` file to customize:

```env
DEFAULT_TIMEOUT=180          # Default scan timeout
MAX_TIMEOUT=300             # Maximum allowed timeout
NMAP_PATH=nmap              # Custom tool paths
WORDLIST_SMALL=/path/to/wordlist
CORS_ORIGINS=*              # Allowed CORS origins
```

## 🚀 Deployment

### Production Considerations

1. **Use a reverse proxy** (nginx, Apache)
2. **Enable authentication** (OAuth2, API keys)
3. **Rate limiting** to prevent abuse
4. **HTTPS only** with valid certificates
5. **Restrict CORS** to specific origins
6. **Monitor and log** all requests
7. **Run with limited privileges** (non-root user)

### Docker Deployment (Optional)

```dockerfile
FROM python:3.9-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    nmap nikto whatweb gobuster amass dnsenum && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/
EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch
3. Follow existing code style
4. Add tests for new features
5. Submit a pull request

## 📄 License

This project is intended for educational and authorized security testing purposes. See LICENSE for details.

## 📞 Support

For issues, questions, or contributions, please open an issue on the project repository.

---

**Built for AETHER** - Advanced web reconnaissance platform
