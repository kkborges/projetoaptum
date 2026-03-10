"""Log analyzer module - centralized log collection and analysis."""
import re
from datetime import datetime
from collections import Counter


# Log parsing patterns
LOG_PATTERNS = {
    "syslog": re.compile(
        r"(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
        r"(?P<hostname>\S+)\s+(?P<service>\S+?)(?:\[(?P<pid>\d+)\])?\s*:\s+"
        r"(?P<message>.*)"
    ),
    "apache_access": re.compile(
        r"(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+"
        r'"(?P<method>\S+)\s+(?P<url>\S+)\s+\S+"\s+(?P<status>\d+)\s+(?P<size>\d+)'
    ),
    "apache_error": re.compile(
        r"\[(?P<timestamp>[^\]]+)\]\s+\[(?P<module>\S+):(?P<level>\S+)\]\s+"
        r"(?:\[pid\s+(?P<pid>\d+)\]\s+)?(?P<message>.*)"
    ),
    "auth_log": re.compile(
        r"(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
        r"(?P<hostname>\S+)\s+(?P<service>\S+?)(?:\[(?P<pid>\d+)\])?\s*:\s+"
        r"(?P<message>.*)"
    ),
    "nginx_access": re.compile(
        r"(?P<ip>\S+)\s+-\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+"
        r'"(?P<method>\S+)\s+(?P<url>\S+)\s+\S+"\s+(?P<status>\d+)\s+(?P<size>\d+)\s+'
        r'"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)"'
    ),
}

# Threat detection patterns
THREAT_PATTERNS = [
    {
        "name": "Failed Login",
        "pattern": re.compile(r"(?i)(failed\s+password|authentication\s+failure|login\s+failed|invalid\s+user)"),
        "severity": "medium",
        "category": "authentication",
    },
    {
        "name": "Successful Root Login",
        "pattern": re.compile(r"(?i)(accepted.*root|session\s+opened.*root|root\s+logged\s+in)"),
        "severity": "high",
        "category": "authentication",
    },
    {
        "name": "Privilege Escalation",
        "pattern": re.compile(r"(?i)(sudo.*command|su\s*:\s*\+|gained\s+root)"),
        "severity": "medium",
        "category": "privilege",
    },
    {
        "name": "Service Error",
        "pattern": re.compile(r"(?i)(segfault|out\s+of\s+memory|killed\s+process|oom-killer)"),
        "severity": "high",
        "category": "system",
    },
    {
        "name": "Firewall Block",
        "pattern": re.compile(r"(?i)(iptables.*drop|blocked|denied|firewall.*reject)"),
        "severity": "low",
        "category": "network",
    },
    {
        "name": "Suspicious Command",
        "pattern": re.compile(r"(?i)(wget\s+http|curl.*\|.*sh|base64.*decode|/etc/shadow|/etc/passwd)"),
        "severity": "critical",
        "category": "security",
    },
    {
        "name": "Web Attack",
        "pattern": re.compile(r"(?i)(\.\.\/|union\s+select|<script|eval\(|exec\()"),
        "severity": "high",
        "category": "web",
    },
    {
        "name": "Brute Force",
        "pattern": re.compile(r"(?i)(maximum.*authentication|too\s+many.*failures|repeated.*login)"),
        "severity": "high",
        "category": "authentication",
    },
]


def parse_log_line(line: str) -> dict:
    """Parse a log line and extract structured data."""
    for log_type, pattern in LOG_PATTERNS.items():
        match = pattern.match(line.strip())
        if match:
            parsed = match.groupdict()
            parsed["log_type"] = log_type
            parsed["raw"] = line.strip()
            return parsed

    return {"log_type": "unknown", "message": line.strip(), "raw": line.strip()}


def detect_threats(log_line: str) -> list[dict]:
    """Detect threats in a log line."""
    threats = []
    for tp in THREAT_PATTERNS:
        if tp["pattern"].search(log_line):
            threats.append({
                "threat_name": tp["name"],
                "severity": tp["severity"],
                "category": tp["category"],
                "matched_line": log_line[:500],
                "detected_at": datetime.utcnow().isoformat(),
            })
    return threats


class LogAnalyzer:
    """Centralized log analysis engine."""

    def __init__(self):
        self.entries: list[dict] = []
        self.threats: list[dict] = []
        self.stats = Counter()

    def ingest(self, log_lines: list[str], source: str = "unknown",
               host_ip: str = None) -> dict:
        """Ingest and analyze log lines."""
        new_threats = []

        for line in log_lines:
            if not line.strip():
                continue

            parsed = parse_log_line(line)
            parsed["source"] = source
            parsed["host_ip"] = host_ip
            parsed["ingested_at"] = datetime.utcnow().isoformat()
            self.entries.append(parsed)

            self.stats[parsed.get("log_type", "unknown")] += 1

            threats = detect_threats(line)
            for t in threats:
                t["source"] = source
                t["host_ip"] = host_ip
                new_threats.append(t)

        self.threats.extend(new_threats)

        return {
            "lines_processed": len(log_lines),
            "threats_found": len(new_threats),
            "threats": new_threats,
        }

    def get_summary(self) -> dict:
        """Get analysis summary."""
        severity_counts = Counter()
        category_counts = Counter()
        for t in self.threats:
            severity_counts[t["severity"]] += 1
            category_counts[t["category"]] += 1

        return {
            "total_entries": len(self.entries),
            "total_threats": len(self.threats),
            "by_severity": dict(severity_counts),
            "by_category": dict(category_counts),
            "by_log_type": dict(self.stats),
        }

    def search(self, query: str, limit: int = 100) -> list[dict]:
        """Search through ingested logs."""
        pattern = re.compile(re.escape(query), re.IGNORECASE)
        results = []
        for entry in reversed(self.entries):
            if pattern.search(entry.get("raw", "") or entry.get("message", "")):
                results.append(entry)
                if len(results) >= limit:
                    break
        return results

    def get_failed_logins(self) -> dict:
        """Analyze failed login attempts for brute force detection."""
        ip_counter = Counter()
        user_counter = Counter()

        for entry in self.entries:
            raw = entry.get("raw", "") or entry.get("message", "")
            if re.search(r"(?i)failed\s+password|authentication\s+failure", raw):
                ip_match = re.search(r"from\s+(\d+\.\d+\.\d+\.\d+)", raw)
                user_match = re.search(r"(?:user|for)\s+(\S+)", raw)
                if ip_match:
                    ip_counter[ip_match.group(1)] += 1
                if user_match:
                    user_counter[user_match.group(1)] += 1

        return {
            "top_source_ips": ip_counter.most_common(20),
            "top_usernames": user_counter.most_common(20),
            "total_failed": sum(ip_counter.values()),
        }
