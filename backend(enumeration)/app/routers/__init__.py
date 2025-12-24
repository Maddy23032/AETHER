"""Router package initialization."""

from app.routers import health, scans, websocket

__all__ = ["health", "scans", "websocket"]
