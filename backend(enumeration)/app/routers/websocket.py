"""WebSocket endpoints for real-time scan updates."""

import asyncio
from typing import Dict, Set

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
import structlog

router = APIRouter()
logger = structlog.get_logger()

# Active WebSocket connections per scan
active_connections: Dict[str, Set[WebSocket]] = {}


class ConnectionManager:
    """Manages WebSocket connections for real-time updates."""

    def __init__(self):
        self.active_connections: Dict[str, Set[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, scan_id: str):
        """Accept and register a new WebSocket connection."""
        await websocket.accept()
        if scan_id not in self.active_connections:
            self.active_connections[scan_id] = set()
        self.active_connections[scan_id].add(websocket)
        logger.info("WebSocket connected", scan_id=scan_id)

    def disconnect(self, websocket: WebSocket, scan_id: str):
        """Remove a WebSocket connection."""
        if scan_id in self.active_connections:
            self.active_connections[scan_id].discard(websocket)
            if not self.active_connections[scan_id]:
                del self.active_connections[scan_id]
        logger.info("WebSocket disconnected", scan_id=scan_id)

    async def broadcast(self, scan_id: str, message: dict):
        """Broadcast a message to all connections watching a scan."""
        if scan_id not in self.active_connections:
            return
        
        disconnected = set()
        for websocket in self.active_connections[scan_id]:
            try:
                await websocket.send_json(message)
            except Exception:
                disconnected.add(websocket)
        
        # Clean up disconnected sockets
        for ws in disconnected:
            self.active_connections[scan_id].discard(ws)

    async def send_log(self, scan_id: str, log_type: str, message: str):
        """Send a log entry to all connections watching a scan."""
        await self.broadcast(scan_id, {
            "type": "log",
            "data": {
                "log_type": log_type,
                "message": message,
            }
        })

    async def send_progress(self, scan_id: str, current: int, total: int, phase: str):
        """Send progress update to all connections watching a scan."""
        await self.broadcast(scan_id, {
            "type": "progress",
            "data": {
                "current": current,
                "total": total,
                "percentage": round((current / total) * 100, 1) if total > 0 else 0,
                "phase": phase,
            }
        })

    async def send_finding(self, scan_id: str, vulnerability: dict):
        """Send a new vulnerability finding to all connections."""
        await self.broadcast(scan_id, {
            "type": "finding",
            "data": vulnerability,
        })

    async def send_status(self, scan_id: str, status: str):
        """Send status update to all connections watching a scan."""
        await self.broadcast(scan_id, {
            "type": "status",
            "data": {"status": status},
        })


# Global connection manager instance
manager = ConnectionManager()


@router.websocket("/scans/{scan_id}")
async def websocket_scan_updates(websocket: WebSocket, scan_id: str):
    """
    WebSocket endpoint for real-time scan updates.
    
    Connect to receive:
    - log: Real-time log entries (type: info/ok/warn/critical)
    - progress: Scan progress updates (current, total, percentage, phase)
    - finding: New vulnerability discoveries
    - status: Scan status changes (running, completed, failed)
    """
    await manager.connect(websocket, scan_id)
    
    try:
        # Send initial connection confirmation
        await websocket.send_json({
            "type": "connected",
            "data": {"scan_id": scan_id, "message": "Connected to scan updates"},
        })
        
        # Keep connection alive and handle incoming messages
        while True:
            try:
                # Wait for any client messages (ping/pong, commands)
                data = await asyncio.wait_for(
                    websocket.receive_json(),
                    timeout=30.0  # 30 second timeout for keepalive
                )
                
                # Handle client commands
                if data.get("type") == "ping":
                    await websocket.send_json({"type": "pong"})
                
            except asyncio.TimeoutError:
                # Send keepalive ping
                try:
                    await websocket.send_json({"type": "ping"})
                except Exception:
                    break
                    
    except WebSocketDisconnect:
        pass
    finally:
        manager.disconnect(websocket, scan_id)


def get_connection_manager() -> ConnectionManager:
    """Get the global connection manager for use in other modules."""
    return manager
