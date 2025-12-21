/**
 * WebSocket service for real-time scan updates
 */

import { WS_BASE_URL } from "./api";
import type { WSMessage } from "@/types/scan";

export type WSMessageHandler = (message: WSMessage) => void;

export class ScanWebSocket {
  private ws: WebSocket | null = null;
  private scanId: string;
  private onMessage: WSMessageHandler;
  private onError?: (error: Event) => void;
  private onClose?: () => void;
  private reconnectAttempts = 0;
  private maxReconnects = 3;

  constructor(
    scanId: string,
    onMessage: WSMessageHandler,
    onError?: (error: Event) => void,
    onClose?: () => void
  ) {
    this.scanId = scanId;
    this.onMessage = onMessage;
    this.onError = onError;
    this.onClose = onClose;
  }

  connect(): void {
    const url = `${WS_BASE_URL}/ws/scans/${this.scanId}`;
    this.ws = new WebSocket(url);

    this.ws.onopen = () => {
      this.reconnectAttempts = 0;
    };

    this.ws.onmessage = (event) => {
      try {
        const message: WSMessage = JSON.parse(event.data);
        
        // Handle ping/pong internally
        if (message.type === "ping") {
          this.ws?.send(JSON.stringify({ type: "pong" }));
          return;
        }
        
        this.onMessage(message);
      } catch (e) {
        console.error("Failed to parse WebSocket message:", e);
      }
    };

    this.ws.onerror = (error) => {
      this.onError?.(error);
    };

    this.ws.onclose = () => {
      if (this.reconnectAttempts < this.maxReconnects) {
        this.reconnectAttempts++;
        setTimeout(() => this.connect(), 1000 * this.reconnectAttempts);
      } else {
        this.onClose?.();
      }
    };
  }

  disconnect(): void {
    this.maxReconnects = 0; // Prevent reconnection
    this.ws?.close();
    this.ws = null;
  }

  isConnected(): boolean {
    return this.ws?.readyState === WebSocket.OPEN;
  }
}
