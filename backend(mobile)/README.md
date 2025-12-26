# AETHER Mobile Security Backend

FastAPI-based mobile application security analysis backend that integrates with MobSF (Mobile Security Framework) for comprehensive APK/IPA analysis.

## Features

- 📱 **APK/IPA Upload & Validation** - Secure file upload with magic byte validation
- 🔍 **Static Analysis** - Deep static analysis via MobSF integration
- 📊 **Security Scorecard** - Risk assessment and security scoring
- 🦠 **Malware Detection** - Multi-source malware database checks (MalwareBazaar, ThreatFox, URLhaus)
- 🔄 **Real-time Updates** - WebSocket-based scan progress streaming
- 📄 **PDF Reports** - Downloadable security assessment reports
- 🐳 **Docker Support** - Full containerized deployment with docker-compose

## Quick Start

### Option 1: Docker Compose (Recommended)

```bash
# Start the full stack (API + MobSF)
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

### Option 2: Local Development

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
.\venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt

# Copy environment file
cp .env.example .env

# Start MobSF separately (Docker)
docker run -d -p 8000:8000 --name mobsf opensecurity/mobile-security-framework-mobsf:latest

# Run the API server
python run.py
```

## API Endpoints

### Health & Status
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Basic health check |
| GET | `/health/detailed` | Detailed health with dependencies |
| GET | `/mobsf/status` | MobSF container status |
| POST | `/mobsf/start` | Start MobSF container |
| POST | `/mobsf/stop` | Stop MobSF container |

### Upload
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/upload` | Upload APK/IPA file |
| GET | `/api/upload/{file_id}` | Get upload info |
| DELETE | `/api/upload/{file_id}` | Delete uploaded file |

### Scans
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/scans` | Start a new scan |
| GET | `/api/scans` | List all scans |
| GET | `/api/scans/{scan_id}` | Get scan status |
| DELETE | `/api/scans/{scan_id}` | Cancel/delete scan |

### Reports
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/reports/{scan_id}` | Full compiled report |
| GET | `/api/reports/{scan_id}/summary` | Report summary |
| GET | `/api/reports/{scan_id}/static` | Static analysis only |
| GET | `/api/reports/{scan_id}/scorecard` | Security scorecard |
| GET | `/api/reports/{scan_id}/malware` | Malware analysis |
| GET | `/api/reports/{scan_id}/findings` | Security findings |
| GET | `/api/reports/{scan_id}/pdf` | Download PDF report |

### WebSocket
| Endpoint | Description |
|----------|-------------|
| `WS /ws/scans/{scan_id}` | Real-time scan updates |
| `WS /ws/all` | All scan updates (dashboard) |

## Usage Example

### Upload and Scan an APK

```python
import requests

BASE_URL = "http://localhost:8001"

# 1. Upload APK
with open("app.apk", "rb") as f:
    response = requests.post(f"{BASE_URL}/api/upload", files={"file": f})
    upload_data = response.json()
    print(f"File ID: {upload_data['file_id']}")
    print(f"Hash: {upload_data['hash']}")

# 2. Start scan
response = requests.post(f"{BASE_URL}/api/scans", json={
    "file_id": upload_data["file_id"]
})
scan_data = response.json()
print(f"Scan ID: {scan_data['scan_id']}")

# 3. Check status
response = requests.get(f"{BASE_URL}/api/scans/{scan_data['scan_id']}")
status = response.json()
print(f"Status: {status['state']} ({status['progress']}%)")

# 4. Get report (when complete)
response = requests.get(f"{BASE_URL}/api/reports/{scan_data['scan_id']}")
report = response.json()
print(f"Security Score: {report['security_score']}")
print(f"Risk Level: {report['overall_risk_level']}")
```

### WebSocket Progress Monitoring

```javascript
const ws = new WebSocket(`ws://localhost:8001/ws/scans/${scanId}`);

ws.onmessage = (event) => {
    const data = JSON.parse(event.data);
    console.log(`State: ${data.state}, Progress: ${data.progress}%`);
    
    if (data.state === 'completed') {
        console.log('Scan complete!');
        ws.close();
    }
};
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     AETHER Mobile API                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐       │
│   │ Upload  │   │  Scans  │   │ Reports │   │   WS    │       │
│   │ Router  │   │ Router  │   │ Router  │   │ Router  │       │
│   └────┬────┘   └────┬────┘   └────┬────┘   └────┬────┘       │
│        │             │             │             │             │
│   ┌────┴─────────────┴─────────────┴─────────────┴────┐       │
│   │              SCAN ORCHESTRATOR                     │       │
│   │    (State Machine: IDLE → SCANNING → COMPLETE)    │       │
│   └────┬─────────────┬─────────────┬─────────────┬────┘       │
│        │             │             │             │             │
│   ┌────┴────┐   ┌────┴────┐   ┌────┴────┐   ┌────┴────┐       │
│   │  File   │   │  MobSF  │   │ Malware │   │ Report  │       │
│   │ Handler │   │ Client  │   │Analyzer │   │Compiler │       │
│   └─────────┘   └────┬────┘   └─────────┘   └─────────┘       │
│                      │                                         │
└──────────────────────┼─────────────────────────────────────────┘
                       │
              ┌────────┴────────┐
              │     MobSF       │
              │   Container     │
              └─────────────────┘
```

## Configuration

Environment variables (see `.env.example`):

| Variable | Default | Description |
|----------|---------|-------------|
| `DEBUG` | `false` | Enable debug mode |
| `PORT` | `8001` | API server port |
| `MOBSF_URL` | `http://localhost:8000` | MobSF server URL |
| `MOBSF_AUTO_START` | `true` | Auto-start MobSF container |
| `MAX_UPLOAD_SIZE_MB` | `100` | Max APK file size |
| `MAX_CONCURRENT_SCANS` | `3` | Concurrent scan limit |

## Project Structure

```
backend(mobile)/
├── app/
│   ├── __init__.py
│   ├── main.py              # FastAPI application
│   ├── config.py            # Configuration
│   ├── core/
│   │   ├── exceptions.py    # Custom exceptions
│   │   └── state_machine.py # Scan state management
│   ├── models/
│   │   ├── apk.py           # APK metadata models
│   │   ├── scan.py          # Scan job models
│   │   └── report.py        # Report models
│   ├── routers/
│   │   ├── health.py        # Health endpoints
│   │   ├── uploads.py       # Upload endpoints
│   │   ├── scans.py         # Scan endpoints
│   │   ├── reports.py       # Report endpoints
│   │   └── websocket.py     # WebSocket handlers
│   ├── services/
│   │   ├── docker_manager.py    # Docker container control
│   │   ├── mobsf_client.py      # MobSF API client
│   │   ├── scan_orchestrator.py # Scan coordination
│   │   ├── malware_analyzer.py  # Malware checks
│   │   └── report_compiler.py   # Report aggregation
│   └── utils/
│       └── file_handler.py  # File validation
├── uploads/                 # Uploaded APK storage
├── reports/                 # Generated reports
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── run.py                   # Development runner
└── README.md
```

## License

Part of the AETHER Security Platform.
