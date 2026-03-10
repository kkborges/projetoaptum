"""Anomaly detection engine - identifies unusual patterns and behaviors."""
import math
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Optional


class MetricBaseline:
    """Tracks metric baseline using exponential moving average."""

    def __init__(self, window_size: int = 30):
        self.values: list[float] = []
        self.window_size = window_size
        self._mean: Optional[float] = None
        self._std: Optional[float] = None

    def add(self, value: float):
        self.values.append(value)
        if len(self.values) > self.window_size * 10:
            self.values = self.values[-self.window_size * 5:]
        self._update_stats()

    def _update_stats(self):
        if len(self.values) < 2:
            self._mean = self.values[0] if self.values else 0
            self._std = 0
            return
        recent = self.values[-self.window_size:]
        self._mean = sum(recent) / len(recent)
        variance = sum((x - self._mean) ** 2 for x in recent) / len(recent)
        self._std = math.sqrt(variance)

    @property
    def mean(self) -> float:
        return self._mean if self._mean is not None else 0

    @property
    def std(self) -> float:
        return self._std if self._std is not None else 0

    def is_anomalous(self, value: float, threshold: float = 2.5) -> bool:
        """Check if value deviates significantly from baseline."""
        if len(self.values) < 5:
            return False
        if self._std == 0:
            return value != self._mean
        z_score = abs(value - self._mean) / self._std
        return z_score > threshold

    def get_z_score(self, value: float) -> float:
        if self._std == 0:
            return 0.0
        return abs(value - self._mean) / self._std


class AnomalyDetector:
    """Main anomaly detection engine."""

    def __init__(self):
        self.baselines: dict[str, MetricBaseline] = defaultdict(MetricBaseline)
        self.anomalies: list[dict] = []
        self.host_port_history: dict[str, set[int]] = {}

    def _key(self, host: str, metric: str) -> str:
        return f"{host}:{metric}"

    def record_metric(self, host: str, metric_type: str, value: float) -> Optional[dict]:
        """Record a metric value and check for anomalies."""
        key = self._key(host, metric_type)
        baseline = self.baselines[key]

        anomaly = None
        if baseline.is_anomalous(value):
            z_score = baseline.get_z_score(value)
            severity = "low"
            if z_score > 4:
                severity = "critical"
            elif z_score > 3.5:
                severity = "high"
            elif z_score > 3:
                severity = "medium"

            anomaly = {
                "host": host,
                "metric_type": metric_type,
                "current_value": value,
                "baseline_mean": round(baseline.mean, 2),
                "baseline_std": round(baseline.std, 2),
                "z_score": round(z_score, 2),
                "severity": severity,
                "description": (
                    f"{metric_type} anomaly on {host}: value {value} "
                    f"(baseline: {baseline.mean:.1f} ± {baseline.std:.1f})"
                ),
                "detected_at": datetime.utcnow().isoformat(),
            }
            self.anomalies.append(anomaly)

        baseline.add(value)
        return anomaly

    def check_host_availability(self, host: str, is_up: bool,
                                 previous_status: str) -> Optional[dict]:
        """Detect host availability changes."""
        if previous_status == "up" and not is_up:
            anomaly = {
                "host": host,
                "metric_type": "availability",
                "severity": "critical",
                "description": f"Host {host} went DOWN",
                "detected_at": datetime.utcnow().isoformat(),
            }
            self.anomalies.append(anomaly)
            return anomaly
        return None

    def check_port_changes(self, host: str, current_ports: list[int]) -> list[dict]:
        """Detect changes in open ports."""
        current_set = set(current_ports)
        results = []

        if host in self.host_port_history:
            previous = self.host_port_history[host]
            new_ports = current_set - previous
            closed_ports = previous - current_set

            for port in new_ports:
                anomaly = {
                    "host": host,
                    "metric_type": "port_change",
                    "severity": "medium",
                    "description": f"New port opened on {host}: {port}",
                    "details": {"port": port, "change": "opened"},
                    "detected_at": datetime.utcnow().isoformat(),
                }
                results.append(anomaly)
                self.anomalies.append(anomaly)

            for port in closed_ports:
                anomaly = {
                    "host": host,
                    "metric_type": "port_change",
                    "severity": "high" if port < 1024 else "low",
                    "description": f"Port closed on {host}: {port}",
                    "details": {"port": port, "change": "closed"},
                    "detected_at": datetime.utcnow().isoformat(),
                }
                results.append(anomaly)
                self.anomalies.append(anomaly)

        self.host_port_history[host] = current_set
        return results

    def check_thresholds(self, host: str, metrics: dict) -> list[dict]:
        """Check metrics against static thresholds."""
        results = []
        thresholds = {
            "cpu_percent": {"warning": 80, "critical": 95},
            "memory_percent": {"warning": 85, "critical": 95},
            "disk_percent": {"warning": 85, "critical": 95},
            "network_errors": {"warning": 10, "critical": 100},
        }

        for metric_name, limits in thresholds.items():
            value = metrics.get(metric_name)
            if value is None:
                continue

            if value >= limits["critical"]:
                anomaly = {
                    "host": host,
                    "metric_type": metric_name,
                    "severity": "critical",
                    "current_value": value,
                    "threshold": limits["critical"],
                    "description": f"CRITICAL: {metric_name} at {value}% on {host}",
                    "detected_at": datetime.utcnow().isoformat(),
                }
                results.append(anomaly)
                self.anomalies.append(anomaly)
            elif value >= limits["warning"]:
                anomaly = {
                    "host": host,
                    "metric_type": metric_name,
                    "severity": "medium",
                    "current_value": value,
                    "threshold": limits["warning"],
                    "description": f"WARNING: {metric_name} at {value}% on {host}",
                    "detected_at": datetime.utcnow().isoformat(),
                }
                results.append(anomaly)
                self.anomalies.append(anomaly)

        return results

    def get_anomalies(self, hours: int = 24, severity: str = None,
                      host: str = None) -> list[dict]:
        """Get recent anomalies with optional filters."""
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        cutoff_str = cutoff.isoformat()

        filtered = [
            a for a in self.anomalies
            if a["detected_at"] >= cutoff_str
        ]
        if severity:
            filtered = [a for a in filtered if a.get("severity") == severity]
        if host:
            filtered = [a for a in filtered if a.get("host") == host]

        return sorted(filtered, key=lambda a: a["detected_at"], reverse=True)

    def get_summary(self) -> dict:
        """Get anomaly detection summary."""
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        type_counts = defaultdict(int)

        for a in self.anomalies:
            sev = a.get("severity", "low")
            if sev in severity_counts:
                severity_counts[sev] += 1
            type_counts[a.get("metric_type", "unknown")] += 1

        return {
            "total_anomalies": len(self.anomalies),
            "by_severity": severity_counts,
            "by_type": dict(type_counts),
            "monitored_metrics": len(self.baselines),
            "monitored_hosts": len(self.host_port_history),
        }
