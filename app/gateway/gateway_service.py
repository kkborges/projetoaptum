"""
AptumNet Gateway — Intelligent proxy for agents.

The gateway acts as an intermediary between agents and the central server:
  - Receives agent reports and log data locally
  - Buffers data when the server is unreachable (local queue)
  - Compresses and forwards to the main server with retry
  - Provides high availability for data collection

Run: python -m app.gateway.gateway_service --server http://server:8000 --port 9200
"""
import argparse
import gzip
import json
import logging
import os
import threading
import time
from collections import deque
from datetime import datetime
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

# Buffer configuration
MAX_BUFFER_SIZE = 10000
RETRY_INTERVALS = [2, 4, 8, 16, 30, 60]  # seconds
FLUSH_INTERVAL = 5  # seconds
COMPRESS_THRESHOLD = 1024  # bytes — compress payloads larger than this


class DataBuffer:
    """Thread-safe local buffer for high availability."""

    def __init__(self, max_size: int = MAX_BUFFER_SIZE, persist_path: Optional[str] = None):
        self._queue = deque(maxlen=max_size)
        self._lock = threading.Lock()
        self._persist_path = persist_path
        if persist_path:
            self._load_persisted()

    def push(self, endpoint: str, payload: dict):
        with self._lock:
            self._queue.append({
                "endpoint": endpoint,
                "payload": payload,
                "queued_at": datetime.utcnow().isoformat(),
                "retries": 0,
            })

    def pop_batch(self, batch_size: int = 50) -> list[dict]:
        with self._lock:
            batch = []
            for _ in range(min(batch_size, len(self._queue))):
                batch.append(self._queue.popleft())
            return batch

    def requeue(self, items: list[dict]):
        with self._lock:
            for item in items:
                item["retries"] = item.get("retries", 0) + 1
                self._queue.appendleft(item)

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._queue)

    def persist(self):
        if not self._persist_path:
            return
        with self._lock:
            data = list(self._queue)
        try:
            with open(self._persist_path, "w") as f:
                json.dump(data, f)
        except Exception as e:
            logger.error(f"Failed to persist buffer: {e}")

    def _load_persisted(self):
        if not self._persist_path or not os.path.exists(self._persist_path):
            return
        try:
            with open(self._persist_path, "r") as f:
                data = json.load(f)
            for item in data:
                self._queue.append(item)
            logger.info(f"Loaded {len(data)} buffered items from disk")
        except Exception as e:
            logger.error(f"Failed to load persisted buffer: {e}")


class GatewayService:
    """Proxy service that buffers and forwards agent data to the server."""

    def __init__(self, server_url: str, listen_port: int = 9200,
                 buffer_path: Optional[str] = None):
        self.server_url = server_url.rstrip("/")
        self.listen_port = listen_port
        self.buffer = DataBuffer(persist_path=buffer_path)
        self._running = False
        self._stats = {
            "received": 0,
            "forwarded": 0,
            "failed": 0,
            "buffered": 0,
            "compressed_bytes_saved": 0,
        }

    def receive_agent_report(self, payload: dict) -> dict:
        """Receive an agent report and queue for forwarding."""
        self._stats["received"] += 1
        self.buffer.push("/api/agent/report", payload)
        return {"status": "queued", "buffer_size": self.buffer.size}

    def receive_logs(self, payload: dict) -> dict:
        """Receive log data and queue for forwarding."""
        self._stats["received"] += 1
        self.buffer.push("/api/logs/ingest", payload)
        return {"status": "queued", "buffer_size": self.buffer.size}

    def receive_generic(self, endpoint: str, payload: dict) -> dict:
        """Receive any payload for forwarding to a specific endpoint."""
        self._stats["received"] += 1
        self.buffer.push(endpoint, payload)
        return {"status": "queued", "buffer_size": self.buffer.size}

    def _forward_batch(self):
        """Forward a batch of buffered data to the server."""
        batch = self.buffer.pop_batch()
        if not batch:
            return

        failed = []
        with httpx.Client(timeout=15) as client:
            for item in batch:
                url = self.server_url + item["endpoint"]
                payload_json = json.dumps(item["payload"])

                headers = {"Content-Type": "application/json"}
                body = payload_json.encode("utf-8")

                # Compress large payloads
                if len(body) > COMPRESS_THRESHOLD:
                    compressed = gzip.compress(body)
                    saved = len(body) - len(compressed)
                    if saved > 0:
                        self._stats["compressed_bytes_saved"] += saved
                        body = compressed
                        headers["Content-Encoding"] = "gzip"

                try:
                    resp = client.post(url, content=body, headers=headers)
                    if resp.status_code < 400:
                        self._stats["forwarded"] += 1
                    else:
                        logger.warning(f"Server returned {resp.status_code} for {item['endpoint']}")
                        if item.get("retries", 0) < len(RETRY_INTERVALS):
                            failed.append(item)
                        else:
                            self._stats["failed"] += 1
                except Exception as e:
                    logger.error(f"Forward failed: {e}")
                    if item.get("retries", 0) < len(RETRY_INTERVALS):
                        failed.append(item)
                    else:
                        self._stats["failed"] += 1

        if failed:
            self.buffer.requeue(failed)
            self._stats["buffered"] = self.buffer.size

    def _flush_loop(self):
        """Background loop that flushes the buffer periodically."""
        while self._running:
            try:
                self._forward_batch()
            except Exception as e:
                logger.error(f"Flush error: {e}")
            time.sleep(FLUSH_INTERVAL)
        # Final flush and persist on shutdown
        self._forward_batch()
        self.buffer.persist()

    def get_stats(self) -> dict:
        return {
            **self._stats,
            "buffer_size": self.buffer.size,
            "server_url": self.server_url,
        }

    def start(self):
        """Start the gateway service (FastAPI app + flush thread)."""
        self._running = True
        flush_thread = threading.Thread(target=self._flush_loop, daemon=True)
        flush_thread.start()
        logger.info(f"Gateway flush thread started (server={self.server_url})")
        return flush_thread

    def stop(self):
        self._running = False


def create_gateway_app(server_url: str, buffer_path: Optional[str] = None):
    """Create a FastAPI app for the gateway service."""
    from fastapi import FastAPI

    gateway = GatewayService(server_url, buffer_path=buffer_path)
    app = FastAPI(title="AptumNet Gateway", version="1.0.0")

    @app.on_event("startup")
    def on_startup():
        gateway.start()

    @app.on_event("shutdown")
    def on_shutdown():
        gateway.stop()

    @app.post("/api/agent/report")
    def proxy_agent_report(payload: dict):
        """Receive agent report and forward to server."""
        return gateway.receive_agent_report(payload)

    @app.post("/api/logs/ingest")
    def proxy_logs(payload: dict):
        """Receive logs and forward to server."""
        return gateway.receive_logs(payload)

    @app.post("/api/gateway/forward")
    def proxy_generic(endpoint: str, payload: dict):
        """Forward any payload to a specific server endpoint."""
        return gateway.receive_generic(endpoint, payload)

    @app.get("/api/gateway/stats")
    def gateway_stats():
        """Get gateway statistics."""
        return gateway.get_stats()

    @app.get("/health")
    def health():
        return {"status": "healthy", "service": "AptumNet Gateway",
                "buffer_size": gateway.buffer.size}

    return app, gateway


if __name__ == "__main__":
    import uvicorn

    parser = argparse.ArgumentParser(description="AptumNet Gateway Service")
    parser.add_argument("--server", required=True, help="Central server URL")
    parser.add_argument("--port", type=int, default=9200, help="Gateway listen port")
    parser.add_argument("--buffer-file", default=None, help="Path to persist buffer on disk")
    args = parser.parse_args()

    app, gw = create_gateway_app(args.server, args.buffer_file)
    uvicorn.run(app, host="0.0.0.0", port=args.port)
