"""API routes for AptumNet."""
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.database import (
    get_db, Host, Port, HostMetric, Alert, NetworkLink,
    ScanJob, LogEntry
)
from app.scanner.network_scanner import (
    discover_hosts, scan_ports, full_scan, COMMON_PORTS
)
from app.snmp.snmp_collector import collect_host_info, collect_metrics
from app.security.ids_engine import IDSEngine
from app.security.pentest_scanner import run_pentest
from app.security.log_analyzer import LogAnalyzer
from app.monitoring.anomaly_detector import AnomalyDetector

router = APIRouter(prefix="/api")

# Singleton engines
ids_engine = IDSEngine()
log_analyzer = LogAnalyzer()
anomaly_detector = AnomalyDetector()


# --- Pydantic Models ---

class ScanRequest(BaseModel):
    target: str
    ports: Optional[list[int]] = None
    scan_type: str = "discovery"  # discovery, port_scan, full, pentest


class AgentReport(BaseModel):
    system_info: dict
    metrics: dict


class LogIngest(BaseModel):
    source: str
    host_ip: Optional[str] = None
    lines: list[str]


class HostUpdate(BaseModel):
    hostname: Optional[str] = None
    host_type: Optional[str] = None
    location: Optional[str] = None
    notes: Optional[str] = None
    topology_x: Optional[float] = None
    topology_y: Optional[float] = None


class AlertUpdate(BaseModel):
    status: str  # acknowledged, resolved, false_positive


# --- Dashboard ---

@router.get("/dashboard")
def get_dashboard(db: Session = Depends(get_db)):
    """Get dashboard overview data."""
    total_hosts = db.query(Host).count()
    hosts_up = db.query(Host).filter(Host.status == "up").count()
    hosts_down = db.query(Host).filter(Host.status == "down").count()
    total_alerts = db.query(Alert).filter(Alert.status == "open").count()
    critical_alerts = db.query(Alert).filter(
        Alert.status == "open", Alert.severity == "critical"
    ).count()

    recent_alerts = db.query(Alert).order_by(
        Alert.created_at.desc()
    ).limit(10).all()

    return {
        "hosts": {
            "total": total_hosts,
            "up": hosts_up,
            "down": hosts_down,
            "unknown": total_hosts - hosts_up - hosts_down,
        },
        "alerts": {
            "total_open": total_alerts,
            "critical": critical_alerts,
        },
        "ids_stats": ids_engine.get_stats(),
        "anomaly_summary": anomaly_detector.get_summary(),
        "log_summary": log_analyzer.get_summary(),
        "recent_alerts": [
            {
                "id": a.id, "title": a.title, "severity": a.severity,
                "source": a.source, "created_at": a.created_at.isoformat(),
                "host_ip": a.host.ip_address if a.host else None,
            }
            for a in recent_alerts
        ],
    }


# --- Hosts ---

@router.get("/hosts")
def list_hosts(status: Optional[str] = None, db: Session = Depends(get_db)):
    """List all monitored hosts."""
    query = db.query(Host)
    if status:
        query = query.filter(Host.status == status)
    hosts = query.order_by(Host.ip_address).all()
    return [
        {
            "id": h.id, "ip_address": h.ip_address, "hostname": h.hostname,
            "mac_address": h.mac_address, "vendor": h.vendor,
            "os_detected": h.os_detected, "status": h.status,
            "host_type": h.host_type, "snmp_enabled": h.snmp_enabled,
            "agent_installed": h.agent_installed,
            "last_seen": h.last_seen.isoformat() if h.last_seen else None,
            "open_ports": len([p for p in h.ports if p.state == "open"]),
            "topology_x": h.topology_x, "topology_y": h.topology_y,
        }
        for h in hosts
    ]


@router.get("/hosts/{host_id}")
def get_host(host_id: int, db: Session = Depends(get_db)):
    """Get host details."""
    host = db.query(Host).filter(Host.id == host_id).first()
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    return {
        "id": host.id, "ip_address": host.ip_address,
        "hostname": host.hostname, "mac_address": host.mac_address,
        "vendor": host.vendor, "os_detected": host.os_detected,
        "status": host.status, "host_type": host.host_type,
        "snmp_enabled": host.snmp_enabled,
        "agent_installed": host.agent_installed,
        "first_seen": host.first_seen.isoformat(),
        "last_seen": host.last_seen.isoformat() if host.last_seen else None,
        "location": host.location, "notes": host.notes,
        "topology_x": host.topology_x, "topology_y": host.topology_y,
        "ports": [
            {
                "port": p.port_number, "protocol": p.protocol,
                "state": p.state, "service": p.service_name,
                "version": p.service_version, "banner": p.banner,
            }
            for p in host.ports
        ],
        "recent_metrics": [
            {
                "type": m.metric_type, "value": m.metric_value,
                "unit": m.metric_unit, "details": m.details,
                "collected_at": m.collected_at.isoformat(),
            }
            for m in sorted(host.metrics, key=lambda x: x.collected_at, reverse=True)[:50]
        ],
        "alerts": [
            {
                "id": a.id, "type": a.alert_type, "severity": a.severity,
                "title": a.title, "status": a.status,
                "created_at": a.created_at.isoformat(),
            }
            for a in host.alerts
        ],
    }


@router.put("/hosts/{host_id}")
def update_host(host_id: int, data: HostUpdate, db: Session = Depends(get_db)):
    """Update host information."""
    host = db.query(Host).filter(Host.id == host_id).first()
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    for field, value in data.model_dump(exclude_none=True).items():
        setattr(host, field, value)
    db.commit()
    return {"status": "updated"}


# --- Scanning ---

@router.post("/scan")
async def start_scan(req: ScanRequest, background_tasks: BackgroundTasks,
                     db: Session = Depends(get_db)):
    """Start a network scan."""
    job = ScanJob(
        scan_type=req.scan_type, target=req.target,
        status="running", started_at=datetime.utcnow()
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    background_tasks.add_task(_run_scan, job.id, req)
    return {"job_id": job.id, "status": "started"}


async def _run_scan(job_id: int, req: ScanRequest):
    """Execute scan in background."""
    from app.core.database import SessionLocal
    db = SessionLocal()

    try:
        job = db.query(ScanJob).filter(ScanJob.id == job_id).first()

        if req.scan_type == "discovery":
            results = await discover_hosts(req.target)
        elif req.scan_type == "port_scan":
            results = await scan_ports(req.target, req.ports)
        elif req.scan_type == "full":
            results = await full_scan(req.target)
        elif req.scan_type == "pentest":
            results = await run_pentest(req.target, req.ports)
        else:
            results = {"error": f"Unknown scan type: {req.scan_type}"}

        # Save discovered hosts
        if req.scan_type in ("discovery", "full"):
            hosts_data = results if isinstance(results, list) else results.get("hosts", [])
            for hdata in hosts_data:
                existing = db.query(Host).filter(
                    Host.ip_address == hdata["ip_address"]
                ).first()
                if existing:
                    existing.status = "up"
                    existing.last_seen = datetime.utcnow()
                    if hdata.get("hostname"):
                        existing.hostname = hdata["hostname"]
                    if hdata.get("host_type"):
                        existing.host_type = hdata["host_type"]
                else:
                    host = Host(
                        ip_address=hdata["ip_address"],
                        hostname=hdata.get("hostname"),
                        status="up",
                        host_type=hdata.get("host_type", "unknown"),
                    )
                    db.add(host)
                    db.flush()

                # Save ports
                if "ports" in hdata:
                    host_obj = db.query(Host).filter(
                        Host.ip_address == hdata["ip_address"]
                    ).first()
                    if host_obj:
                        for pdata in hdata["ports"]:
                            if pdata["state"] == "open":
                                existing_port = db.query(Port).filter(
                                    Port.host_id == host_obj.id,
                                    Port.port_number == pdata["port"]
                                ).first()
                                if existing_port:
                                    existing_port.state = pdata["state"]
                                    existing_port.service_name = pdata.get("service")
                                    existing_port.banner = pdata.get("banner")
                                    existing_port.last_scanned = datetime.utcnow()
                                else:
                                    port = Port(
                                        host_id=host_obj.id,
                                        port_number=pdata["port"],
                                        state=pdata["state"],
                                        service_name=pdata.get("service"),
                                        banner=pdata.get("banner"),
                                    )
                                    db.add(port)

        # Save pentest results as alerts
        if req.scan_type == "pentest" and isinstance(results, dict):
            host_obj = db.query(Host).filter(Host.ip_address == req.target).first()
            all_findings = (
                results.get("banner_findings", []) +
                results.get("credential_findings", []) +
                [{"severity": f.get("severity", "info"),
                  "description": f.get("detail", "SSL issue"),
                  "type": f.get("type", "ssl")}
                 for f in results.get("ssl_findings", [])]
            )
            for finding in all_findings:
                alert = Alert(
                    host_id=host_obj.id if host_obj else None,
                    alert_type="vulnerability",
                    severity=finding.get("severity", "info"),
                    title=finding.get("vulnerability", finding.get("type", "Security Finding")),
                    description=finding.get("description", ""),
                    source="pentest",
                    details=finding,
                )
                db.add(alert)

        job.status = "completed"
        job.results = results if isinstance(results, (dict, list)) else {"data": str(results)}
        job.completed_at = datetime.utcnow()
        job.progress = 100
        db.commit()

    except Exception as e:
        job = db.query(ScanJob).filter(ScanJob.id == job_id).first()
        if job:
            job.status = "failed"
            job.results = {"error": str(e)}
            job.completed_at = datetime.utcnow()
            db.commit()
    finally:
        db.close()


@router.get("/scan/{job_id}")
def get_scan_status(job_id: int, db: Session = Depends(get_db)):
    """Get scan job status and results."""
    job = db.query(ScanJob).filter(ScanJob.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")
    return {
        "id": job.id, "scan_type": job.scan_type, "target": job.target,
        "status": job.status, "progress": job.progress,
        "results": job.results,
        "started_at": job.started_at.isoformat() if job.started_at else None,
        "completed_at": job.completed_at.isoformat() if job.completed_at else None,
    }


@router.get("/scans")
def list_scans(db: Session = Depends(get_db)):
    """List all scan jobs."""
    jobs = db.query(ScanJob).order_by(ScanJob.created_at.desc()).limit(50).all()
    return [
        {
            "id": j.id, "scan_type": j.scan_type, "target": j.target,
            "status": j.status, "progress": j.progress,
            "created_at": j.created_at.isoformat(),
        }
        for j in jobs
    ]


# --- Agent ---

@router.post("/agent/report")
def agent_report(report: AgentReport, db: Session = Depends(get_db)):
    """Receive metrics from monitoring agent."""
    sys_info = report.system_info
    ip = sys_info.get("ip_address", "unknown")

    host = db.query(Host).filter(Host.ip_address == ip).first()
    if not host:
        host = Host(
            ip_address=ip,
            hostname=sys_info.get("hostname"),
            os_detected=sys_info.get("os"),
            status="up",
            agent_installed=True,
        )
        db.add(host)
        db.flush()
    else:
        host.status = "up"
        host.last_seen = datetime.utcnow()
        host.agent_installed = True
        if sys_info.get("hostname"):
            host.hostname = sys_info["hostname"]
        if sys_info.get("os"):
            host.os_detected = sys_info["os"]

    metrics = report.metrics
    now = datetime.utcnow()

    # CPU
    cpu = metrics.get("cpu", {})
    if cpu.get("percent") is not None:
        db.add(HostMetric(
            host_id=host.id, metric_type="cpu",
            metric_value=cpu["percent"], metric_unit="%",
            details=cpu, collected_at=now, source="agent"
        ))
        anomaly = anomaly_detector.record_metric(ip, "cpu_percent", cpu["percent"])
        if anomaly:
            db.add(Alert(
                host_id=host.id, alert_type="performance",
                severity=anomaly["severity"], title="CPU Anomaly Detected",
                description=anomaly["description"], source="anomaly",
            ))

    # Memory
    mem = metrics.get("memory", {})
    if mem.get("percent") is not None:
        db.add(HostMetric(
            host_id=host.id, metric_type="memory",
            metric_value=mem["percent"], metric_unit="%",
            details=mem, collected_at=now, source="agent"
        ))
        anomaly = anomaly_detector.record_metric(ip, "memory_percent", mem["percent"])
        if anomaly:
            db.add(Alert(
                host_id=host.id, alert_type="performance",
                severity=anomaly["severity"], title="Memory Anomaly Detected",
                description=anomaly["description"], source="anomaly",
            ))

    # Disk
    for disk in metrics.get("disks", []):
        if disk.get("usage_percent") is not None:
            db.add(HostMetric(
                host_id=host.id, metric_type="disk",
                metric_value=disk["usage_percent"], metric_unit="%",
                details=disk, collected_at=now, source="agent"
            ))

    # Threshold checks
    threshold_alerts = anomaly_detector.check_thresholds(ip, {
        "cpu_percent": cpu.get("percent", 0),
        "memory_percent": mem.get("percent", 0),
    })
    for ta in threshold_alerts:
        db.add(Alert(
            host_id=host.id, alert_type="performance",
            severity=ta["severity"], title=ta["description"],
            description=ta["description"], source="anomaly",
        ))

    db.commit()
    return {"status": "ok", "host_id": host.id}


# --- SNMP ---

@router.post("/snmp/collect/{host_id}")
async def snmp_collect(host_id: int, db: Session = Depends(get_db)):
    """Trigger SNMP collection for a host."""
    host = db.query(Host).filter(Host.id == host_id).first()
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")

    info = await collect_host_info(host.ip_address)
    if info.get("snmp_available"):
        host.snmp_enabled = True
        if info.get("sys_name"):
            host.hostname = info["sys_name"]
        if info.get("sys_location"):
            host.location = info["sys_location"]

        metrics_data = await collect_metrics(host.ip_address)
        for cpu in metrics_data.get("cpu", []):
            db.add(HostMetric(
                host_id=host.id, metric_type="cpu",
                metric_value=cpu["load_percent"], metric_unit="%",
                source="snmp"
            ))
        db.commit()

    return {"snmp_available": info.get("snmp_available", False), "info": info}


# --- Alerts ---

@router.get("/alerts")
def list_alerts(severity: Optional[str] = None, status: Optional[str] = None,
                limit: int = 100, db: Session = Depends(get_db)):
    """List alerts."""
    query = db.query(Alert)
    if severity:
        query = query.filter(Alert.severity == severity)
    if status:
        query = query.filter(Alert.status == status)
    alerts = query.order_by(Alert.created_at.desc()).limit(limit).all()
    return [
        {
            "id": a.id, "host_ip": a.host.ip_address if a.host else None,
            "type": a.alert_type, "severity": a.severity,
            "title": a.title, "description": a.description,
            "source": a.source, "status": a.status,
            "details": a.details,
            "created_at": a.created_at.isoformat(),
        }
        for a in alerts
    ]


@router.put("/alerts/{alert_id}")
def update_alert(alert_id: int, data: AlertUpdate,
                 db: Session = Depends(get_db)):
    """Update alert status."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.status = data.status
    if data.status == "resolved":
        alert.resolved_at = datetime.utcnow()
    db.commit()
    return {"status": "updated"}


# --- IDS ---

@router.get("/ids/stats")
def get_ids_stats():
    """Get IDS statistics."""
    return ids_engine.get_stats()


@router.get("/ids/alerts")
def get_ids_alerts(limit: int = 100):
    """Get IDS alerts."""
    return ids_engine.get_recent_alerts(limit)


@router.post("/ids/analyze")
def ids_analyze_log(data: LogIngest):
    """Send log lines through IDS analysis."""
    all_alerts = []
    for line in data.lines:
        alerts = ids_engine.analyze_log(line, data.host_ip)
        all_alerts.extend(alerts)
    return {"alerts": all_alerts, "total": len(all_alerts)}


# --- Logs ---

@router.post("/logs/ingest")
def ingest_logs(data: LogIngest, db: Session = Depends(get_db)):
    """Ingest and analyze log data."""
    result = log_analyzer.ingest(data.lines, data.source, data.host_ip)

    # Also run through IDS
    for line in data.lines:
        ids_engine.analyze_log(line, data.host_ip)

    # Save threats as alerts
    host = None
    if data.host_ip:
        host = db.query(Host).filter(Host.ip_address == data.host_ip).first()

    for threat in result.get("threats", []):
        db.add(Alert(
            host_id=host.id if host else None,
            alert_type="security",
            severity=threat["severity"],
            title=threat["threat_name"],
            description=threat.get("matched_line", ""),
            source="log_analysis",
            details=threat,
        ))

    # Save log entries
    for line in data.lines[:1000]:
        if line.strip():
            db.add(LogEntry(
                host_id=host.id if host else None,
                source=data.source,
                level="info",
                message=line[:1000],
                raw_log=line,
            ))

    db.commit()
    return result


@router.get("/logs/summary")
def get_log_summary():
    """Get log analysis summary."""
    return log_analyzer.get_summary()


@router.get("/logs/search")
def search_logs(q: str, limit: int = 100):
    """Search through ingested logs."""
    return log_analyzer.search(q, limit)


@router.get("/logs/failed-logins")
def get_failed_logins():
    """Get failed login analysis."""
    return log_analyzer.get_failed_logins()


# --- Anomalies ---

@router.get("/anomalies")
def get_anomalies(hours: int = 24, severity: Optional[str] = None,
                  host: Optional[str] = None):
    """Get detected anomalies."""
    return anomaly_detector.get_anomalies(hours, severity, host)


@router.get("/anomalies/summary")
def get_anomaly_summary():
    """Get anomaly detection summary."""
    return anomaly_detector.get_summary()


# --- Topology ---

@router.get("/topology")
def get_topology(db: Session = Depends(get_db)):
    """Get network topology data for visualization."""
    hosts = db.query(Host).all()
    links = db.query(NetworkLink).all()

    nodes = []
    for h in hosts:
        open_ports = len([p for p in h.ports if p.state == "open"])
        open_alerts = len([a for a in h.alerts if a.status == "open"])
        nodes.append({
            "id": h.id,
            "ip": h.ip_address,
            "hostname": h.hostname or h.ip_address,
            "type": h.host_type or "unknown",
            "status": h.status,
            "x": h.topology_x,
            "y": h.topology_y,
            "open_ports": open_ports,
            "alerts": open_alerts,
            "snmp": h.snmp_enabled,
            "agent": h.agent_installed,
        })

    edges = []
    for link in links:
        edges.append({
            "id": link.id,
            "source": link.source_host_id,
            "target": link.target_host_id,
            "type": link.link_type,
            "status": link.status,
        })

    return {"nodes": nodes, "edges": edges}


@router.post("/topology/link")
def add_topology_link(source_id: int, target_id: int,
                      link_type: str = "ethernet",
                      db: Session = Depends(get_db)):
    """Add a network link between two hosts."""
    link = NetworkLink(
        source_host_id=source_id,
        target_host_id=target_id,
        link_type=link_type,
    )
    db.add(link)
    db.commit()
    return {"status": "created", "link_id": link.id}
