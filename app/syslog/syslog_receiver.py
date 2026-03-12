"""
AptumNet Syslog Receiver — Collects logs via UDP/TCP syslog protocol.

Features:
  - UDP and TCP syslog listeners (RFC 3164 / RFC 5424)
  - Configurable parsers (syslog, JSON, CSV, regex)
  - Sensitive data filtering
  - Local buffer with queue for high availability
  - Forward to main server or gateway

Run: python -m app.syslog.syslog_receiver --server http://server:8000 --udp-port 514 --tcp-port 514
"""
import argparse
import json
import logging
import re
import socket
import socketserver
import threading
import time
from collections import deque
from datetime import datetime
from typing import Optional, Callable

import httpx

logger = logging.getLogger(__name__)

# Buffer
MAX_QUEUE_SIZE = 50000
FLUSH_BATCH_SIZE = 200
FLUSH_INTERVAL = 3  # seconds

# Default sensitive data patterns to filter
DEFAULT_SENSITIVE_PATTERNS = [
    (re.compile(r'\b\d{3}[-.]?\d{2}[-.]?\d{4}\b'), '[SSN_REDACTED]'),  # SSN
    (re.compile(r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b'), '[CC_REDACTED]'),  # Credit card
    (re.compile(r'(?i)(password|passwd|pwd|secret|token|api_key)\s*[=:]\s*\S+'), r'\1=[REDACTED]'),
]


# --- Parsers ---

def parse_syslog_rfc3164(raw: str) -> dict:
    """Parse RFC 3164 syslog format: <PRI>TIMESTAMP HOSTNAME MSG"""
    m = re.match(
        r'^<(\d{1,3})>(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.*)',
        raw
    )
    if m:
        pri = int(m.group(1))
        facility = pri >> 3
        severity = pri & 0x07
        severity_names = ["emergency", "alert", "critical", "error", "warning", "notice", "info", "debug"]
        return {
            "facility": facility,
            "severity": severity,
            "severity_name": severity_names[severity] if severity < len(severity_names) else "unknown",
            "timestamp_raw": m.group(2),
            "hostname": m.group(3),
            "message": m.group(4),
            "parser": "rfc3164",
        }
    return {"message": raw, "parser": "raw"}


def parse_syslog_rfc5424(raw: str) -> dict:
    """Parse RFC 5424 syslog format."""
    m = re.match(
        r'^<(\d{1,3})>(\d)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*(?:\[(.*?)\])?\s*(.*)',
        raw
    )
    if m:
        pri = int(m.group(1))
        return {
            "facility": pri >> 3,
            "severity": pri & 0x07,
            "version": m.group(2),
            "timestamp_raw": m.group(3),
            "hostname": m.group(4),
            "app_name": m.group(5),
            "proc_id": m.group(6),
            "msg_id": m.group(7),
            "structured_data": m.group(8),
            "message": m.group(9),
            "parser": "rfc5424",
        }
    return parse_syslog_rfc3164(raw)


def parse_json_log(raw: str) -> dict:
    """Parse JSON-formatted log line."""
    try:
        data = json.loads(raw)
        data["parser"] = "json"
        return data
    except (json.JSONDecodeError, ValueError):
        return {"message": raw, "parser": "raw"}


PARSERS = {
    "auto": None,  # auto-detect
    "rfc3164": parse_syslog_rfc3164,
    "rfc5424": parse_syslog_rfc5424,
    "json": parse_json_log,
    "raw": lambda raw: {"message": raw, "parser": "raw"},
}


def auto_parse(raw: str) -> dict:
    """Auto-detect log format and parse."""
    raw = raw.strip()
    if not raw:
        return {"message": "", "parser": "empty"}
    if raw.startswith("{"):
        return parse_json_log(raw)
    if re.match(r'^<\d{1,3}>\d\s', raw):
        return parse_syslog_rfc5424(raw)
    if re.match(r'^<\d{1,3}>', raw):
        return parse_syslog_rfc3164(raw)
    return {"message": raw, "parser": "raw"}


# --- Sensitive Data Filter ---

class SensitiveDataFilter:
    def __init__(self, patterns=None):
        self.patterns = patterns or DEFAULT_SENSITIVE_PATTERNS

    def filter(self, text: str) -> str:
        for pattern, replacement in self.patterns:
            text = pattern.sub(replacement, text)
        return text


# --- Log Buffer Queue ---

class LogQueue:
    """Thread-safe queue with batch flush support."""

    def __init__(self, max_size: int = MAX_QUEUE_SIZE):
        self._queue = deque(maxlen=max_size)
        self._lock = threading.Lock()
        self._dropped = 0

    def push(self, item: dict):
        with self._lock:
            if len(self._queue) >= self._queue.maxlen:
                self._dropped += 1
            self._queue.append(item)

    def pop_batch(self, size: int = FLUSH_BATCH_SIZE) -> list[dict]:
        with self._lock:
            batch = []
            for _ in range(min(size, len(self._queue))):
                batch.append(self._queue.popleft())
            return batch

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._queue)

    @property
    def dropped(self) -> int:
        return self._dropped


# --- UDP Handler ---

class SyslogUDPHandler(socketserver.BaseRequestHandler):
    """Handle incoming UDP syslog messages."""

    def handle(self):
        data = self.request[0].strip()
        try:
            raw = data.decode("utf-8", errors="replace")
        except Exception:
            raw = str(data)

        sender_ip = self.client_address[0]
        receiver = self.server.receiver  # type: SyslogReceiver

        parsed = receiver.parse_and_filter(raw)
        parsed["source_ip"] = sender_ip
        parsed["protocol"] = "udp"
        parsed["received_at"] = datetime.utcnow().isoformat()

        receiver.queue.push(parsed)


# --- TCP Handler ---

class SyslogTCPHandler(socketserver.StreamRequestHandler):
    """Handle incoming TCP syslog messages (one message per line)."""

    def handle(self):
        sender_ip = self.client_address[0]
        receiver = self.server.receiver  # type: SyslogReceiver

        while True:
            try:
                line = self.rfile.readline()
                if not line:
                    break
                raw = line.decode("utf-8", errors="replace").strip()
                if not raw:
                    continue

                parsed = receiver.parse_and_filter(raw)
                parsed["source_ip"] = sender_ip
                parsed["protocol"] = "tcp"
                parsed["received_at"] = datetime.utcnow().isoformat()

                receiver.queue.push(parsed)
            except Exception:
                break


class ThreadedUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    allow_reuse_address = True


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True


# --- Main Receiver ---

class SyslogReceiver:
    """Complete syslog receiver with parsing, filtering, buffering, and forwarding."""

    def __init__(
        self,
        server_url: str,
        udp_port: int = 5514,
        tcp_port: int = 5514,
        parser: str = "auto",
        filter_sensitive: bool = True,
    ):
        self.server_url = server_url.rstrip("/")
        self.udp_port = udp_port
        self.tcp_port = tcp_port
        self.queue = LogQueue()
        self.sensitive_filter = SensitiveDataFilter() if filter_sensitive else None

        self._parser_name = parser
        if parser == "auto":
            self._parse_fn = auto_parse
        else:
            self._parse_fn = PARSERS.get(parser, auto_parse)

        self._running = False
        self._stats = {
            "received_udp": 0,
            "received_tcp": 0,
            "forwarded": 0,
            "failed": 0,
        }

    def parse_and_filter(self, raw: str) -> dict:
        """Parse a raw log line and apply sensitive data filter."""
        if self.sensitive_filter:
            raw = self.sensitive_filter.filter(raw)
        parsed = self._parse_fn(raw)
        parsed["raw"] = raw
        return parsed

    def _flush_loop(self):
        """Background thread: flush queued logs to server/gateway."""
        while self._running:
            try:
                batch = self.queue.pop_batch()
                if batch:
                    self._forward_batch(batch)
            except Exception as e:
                logger.error(f"Flush error: {e}")
            time.sleep(FLUSH_INTERVAL)

    def _forward_batch(self, batch: list[dict]):
        """Send a batch of parsed logs to the server."""
        # Group by source_ip for efficient ingestion
        by_source = {}
        for item in batch:
            src = item.get("source_ip", "unknown")
            by_source.setdefault(src, []).append(item.get("raw", item.get("message", "")))

        with httpx.Client(timeout=10) as client:
            for source_ip, lines in by_source.items():
                try:
                    resp = client.post(
                        f"{self.server_url}/api/logs/ingest",
                        json={
                            "source": f"syslog:{source_ip}",
                            "host_ip": source_ip,
                            "lines": lines,
                        },
                    )
                    if resp.status_code < 400:
                        self._stats["forwarded"] += len(lines)
                    else:
                        self._stats["failed"] += len(lines)
                except Exception as e:
                    logger.error(f"Forward to server failed: {e}")
                    self._stats["failed"] += len(lines)

    def get_stats(self) -> dict:
        return {
            **self._stats,
            "queue_size": self.queue.size,
            "dropped": self.queue.dropped,
            "parser": self._parser_name,
        }

    def start(self):
        """Start UDP and TCP listeners plus flush thread."""
        self._running = True

        # UDP server
        udp_server = ThreadedUDPServer(("0.0.0.0", self.udp_port), SyslogUDPHandler)
        udp_server.receiver = self
        udp_thread = threading.Thread(target=udp_server.serve_forever, daemon=True)
        udp_thread.start()
        logger.info(f"Syslog UDP listener started on port {self.udp_port}")

        # TCP server
        tcp_server = ThreadedTCPServer(("0.0.0.0", self.tcp_port), SyslogTCPHandler)
        tcp_server.receiver = self
        tcp_thread = threading.Thread(target=tcp_server.serve_forever, daemon=True)
        tcp_thread.start()
        logger.info(f"Syslog TCP listener started on port {self.tcp_port}")

        # Flush thread
        flush_thread = threading.Thread(target=self._flush_loop, daemon=True)
        flush_thread.start()

        return udp_server, tcp_server

    def stop(self):
        self._running = False


def create_syslog_app(server_url: str, udp_port: int = 5514,
                       tcp_port: int = 5514, parser: str = "auto"):
    """Create a FastAPI app wrapping the syslog receiver for management API."""
    from fastapi import FastAPI

    receiver = SyslogReceiver(server_url, udp_port, tcp_port, parser)
    app = FastAPI(title="AptumNet Syslog Receiver", version="1.0.0")

    @app.on_event("startup")
    def on_startup():
        receiver.start()

    @app.on_event("shutdown")
    def on_shutdown():
        receiver.stop()

    @app.get("/api/syslog/stats")
    def syslog_stats():
        return receiver.get_stats()

    @app.get("/health")
    def health():
        return {"status": "healthy", "service": "AptumNet Syslog",
                "queue_size": receiver.queue.size}

    return app, receiver


if __name__ == "__main__":
    import uvicorn

    parser = argparse.ArgumentParser(description="AptumNet Syslog Receiver")
    parser.add_argument("--server", required=True, help="Central server or gateway URL")
    parser.add_argument("--udp-port", type=int, default=5514, help="UDP listen port")
    parser.add_argument("--tcp-port", type=int, default=5514, help="TCP listen port")
    parser.add_argument("--mgmt-port", type=int, default=9300, help="Management API port")
    parser.add_argument("--parser", default="auto", choices=list(PARSERS.keys()), help="Log parser")
    args = parser.parse_args()

    app, recv = create_syslog_app(args.server, args.udp_port, args.tcp_port, args.parser)
    uvicorn.run(app, host="0.0.0.0", port=args.mgmt_port)
