"""Intrusion Detection System (IDS) engine - rule-based detection."""
import re
from datetime import datetime
from typing import Optional


class IDSRule:
    """A single IDS detection rule."""

    def __init__(self, rule_id: str, name: str, severity: str,
                 pattern: Optional[str] = None, condition: Optional[callable] = None,
                 description: str = ""):
        self.rule_id = rule_id
        self.name = name
        self.severity = severity
        self.pattern = re.compile(pattern) if pattern else None
        self.condition = condition
        self.description = description


# Built-in IDS rules
DEFAULT_RULES = [
    IDSRule(
        "IDS-001", "SSH Brute Force Attempt", "high",
        pattern=r"Failed password.*ssh|authentication failure.*sshd",
        description="Multiple failed SSH login attempts detected"
    ),
    IDSRule(
        "IDS-002", "Port Scan Detected", "medium",
        description="Rapid connection attempts to multiple ports from single source"
    ),
    IDSRule(
        "IDS-003", "SQL Injection Attempt", "critical",
        pattern=r"(?i)(union\s+select|or\s+1\s*=\s*1|drop\s+table|;\s*delete|'\s*or\s*')",
        description="SQL injection pattern detected in request"
    ),
    IDSRule(
        "IDS-004", "XSS Attempt", "high",
        pattern=r"(?i)(<script|javascript:|on(load|error|click)\s*=|alert\s*\()",
        description="Cross-site scripting pattern detected"
    ),
    IDSRule(
        "IDS-005", "Directory Traversal", "high",
        pattern=r"\.\./|\.\.\\|%2e%2e|%252e%252e",
        description="Directory traversal attempt detected"
    ),
    IDSRule(
        "IDS-006", "Suspicious Outbound Connection", "medium",
        description="Connection to known malicious IP or unusual port"
    ),
    IDSRule(
        "IDS-007", "Privilege Escalation Attempt", "critical",
        pattern=r"sudo.*FAILED|su:.*authentication failure|unauthorized.*root",
        description="Privilege escalation attempt detected"
    ),
    IDSRule(
        "IDS-008", "Unusual Network Traffic Volume", "medium",
        description="Network traffic significantly exceeds baseline"
    ),
    IDSRule(
        "IDS-009", "New Listening Port", "low",
        description="New port opened on monitored host"
    ),
    IDSRule(
        "IDS-010", "Service Down", "high",
        description="Previously running service is no longer responding"
    ),
]

SUSPICIOUS_PORTS = {4444, 5555, 6666, 6667, 31337, 12345, 65535}
RATE_LIMIT_WINDOW = 60  # seconds
MAX_CONN_PER_WINDOW = 50


class IDSEngine:
    """Main IDS engine for analyzing events and connections."""

    def __init__(self):
        self.rules = {r.rule_id: r for r in DEFAULT_RULES}
        self.connection_tracker: dict[str, list[float]] = {}
        self.alerts: list[dict] = []

    def analyze_log(self, log_line: str, source_ip: str = None) -> list[dict]:
        """Analyze a log line against IDS rules."""
        triggered = []
        for rule in self.rules.values():
            if rule.pattern and rule.pattern.search(log_line):
                alert = {
                    "rule_id": rule.rule_id,
                    "rule_name": rule.name,
                    "severity": rule.severity,
                    "description": rule.description,
                    "matched_text": log_line[:500],
                    "source_ip": source_ip,
                    "detected_at": datetime.utcnow().isoformat(),
                }
                triggered.append(alert)
                self.alerts.append(alert)
        return triggered

    def analyze_connection(self, source_ip: str, dest_port: int,
                           timestamp: float = None) -> list[dict]:
        """Analyze network connection for suspicious activity."""
        if timestamp is None:
            timestamp = datetime.utcnow().timestamp()

        triggered = []

        # Check for suspicious ports
        if dest_port in SUSPICIOUS_PORTS:
            alert = {
                "rule_id": "IDS-006",
                "rule_name": "Suspicious Outbound Connection",
                "severity": "medium",
                "description": f"Connection to suspicious port {dest_port}",
                "source_ip": source_ip,
                "dest_port": dest_port,
                "detected_at": datetime.utcnow().isoformat(),
            }
            triggered.append(alert)

        # Track connection rate for port scan detection
        if source_ip not in self.connection_tracker:
            self.connection_tracker[source_ip] = []

        self.connection_tracker[source_ip].append(timestamp)

        # Clean old entries
        cutoff = timestamp - RATE_LIMIT_WINDOW
        self.connection_tracker[source_ip] = [
            t for t in self.connection_tracker[source_ip] if t > cutoff
        ]

        if len(self.connection_tracker[source_ip]) > MAX_CONN_PER_WINDOW:
            alert = {
                "rule_id": "IDS-002",
                "rule_name": "Port Scan Detected",
                "severity": "medium",
                "description": f"Rapid connections from {source_ip}: "
                               f"{len(self.connection_tracker[source_ip])} in {RATE_LIMIT_WINDOW}s",
                "source_ip": source_ip,
                "detected_at": datetime.utcnow().isoformat(),
            }
            triggered.append(alert)

        self.alerts.extend(triggered)
        return triggered

    def analyze_port_changes(self, host_ip: str,
                             previous_ports: list[int],
                             current_ports: list[int]) -> list[dict]:
        """Detect new or closed ports on a host."""
        triggered = []
        new_ports = set(current_ports) - set(previous_ports)
        closed_ports = set(previous_ports) - set(current_ports)

        for port in new_ports:
            alert = {
                "rule_id": "IDS-009",
                "rule_name": "New Listening Port",
                "severity": "low" if port > 1024 else "medium",
                "description": f"New port {port} detected on {host_ip}",
                "source_ip": host_ip,
                "detected_at": datetime.utcnow().isoformat(),
            }
            triggered.append(alert)

        for port in closed_ports:
            if port in {22, 80, 443, 3306, 5432}:
                alert = {
                    "rule_id": "IDS-010",
                    "rule_name": "Service Down",
                    "severity": "high",
                    "description": f"Port {port} closed on {host_ip} - service may be down",
                    "source_ip": host_ip,
                    "detected_at": datetime.utcnow().isoformat(),
                }
                triggered.append(alert)

        self.alerts.extend(triggered)
        return triggered

    def get_recent_alerts(self, limit: int = 100) -> list[dict]:
        """Get most recent alerts."""
        return sorted(
            self.alerts, key=lambda a: a["detected_at"], reverse=True
        )[:limit]

    def get_stats(self) -> dict:
        """Get IDS statistics."""
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for alert in self.alerts:
            sev = alert.get("severity", "low")
            if sev in severity_counts:
                severity_counts[sev] += 1
        return {
            "total_alerts": len(self.alerts),
            "by_severity": severity_counts,
            "rules_count": len(self.rules),
        }
