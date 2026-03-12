"""
AptumNet Windows Agent — Monitoring agent for Windows hosts.

Collects system metrics, running services, and Windows-specific data.
Sends to the central server via HTTP.

Requirements: pip install psutil httpx wmi pywin32
Run: python agent_windows.py --server http://server:8000
"""
import argparse
import json
import platform
import socket
import time
import sys
import os

import psutil

# Optional Windows-specific imports
WMI_AVAILABLE = False
try:
    import wmi
    WMI_AVAILABLE = True
except ImportError:
    pass

WIN32_AVAILABLE = False
try:
    import win32service
    import win32serviceutil
    WIN32_AVAILABLE = True
except ImportError:
    pass


def collect_system_info() -> dict:
    """Collect comprehensive system information."""
    uname = platform.uname()
    boot_time = psutil.boot_time()

    info = {
        "hostname": socket.gethostname(),
        "ip_address": _get_primary_ip(),
        "os": f"{uname.system} {uname.release}",
        "os_version": uname.version,
        "architecture": uname.machine,
        "processor": uname.processor or platform.processor(),
        "boot_time": boot_time,
        "uptime_seconds": time.time() - boot_time,
        "platform": "windows",
    }

    # WMI extras
    if WMI_AVAILABLE:
        try:
            c = wmi.WMI()
            for os_info in c.Win32_OperatingSystem():
                info["os_version_full"] = os_info.Caption
                info["os_build"] = os_info.BuildNumber
                info["total_memory_gb"] = round(
                    int(os_info.TotalVisibleMemorySize) / (1024 * 1024), 2
                )
                break
            for cs in c.Win32_ComputerSystem():
                info["manufacturer"] = cs.Manufacturer
                info["model"] = cs.Model
                info["domain"] = cs.Domain
                break
        except Exception:
            pass

    return info


def collect_metrics() -> dict:
    """Collect current system metrics."""
    cpu_freq = psutil.cpu_freq()
    mem = psutil.virtual_memory()
    disk_partitions = psutil.disk_partitions()
    net_io = psutil.net_io_counters()
    net_per_nic = psutil.net_io_counters(pernic=True)

    disks = []
    for part in disk_partitions:
        try:
            usage = psutil.disk_usage(part.mountpoint)
            disks.append({
                "device": part.device,
                "mountpoint": part.mountpoint,
                "fstype": part.fstype,
                "total_gb": round(usage.total / (1024 ** 3), 2),
                "used_gb": round(usage.used / (1024 ** 3), 2),
                "free_gb": round(usage.free / (1024 ** 3), 2),
                "usage_percent": usage.percent,
            })
        except (PermissionError, OSError):
            continue

    interfaces = []
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    for iface, addr_list in addrs.items():
        iface_info = {"name": iface, "addresses": []}
        for addr in addr_list:
            if addr.family == socket.AF_INET:
                iface_info["addresses"].append({
                    "type": "ipv4", "address": addr.address,
                    "netmask": addr.netmask
                })
        if iface in stats:
            iface_info["is_up"] = stats[iface].isup
            iface_info["speed_mbps"] = stats[iface].speed
        if iface in net_per_nic:
            nic = net_per_nic[iface]
            iface_info["bytes_sent"] = nic.bytes_sent
            iface_info["bytes_recv"] = nic.bytes_recv
            iface_info["packets_sent"] = nic.packets_sent
            iface_info["packets_recv"] = nic.packets_recv
            iface_info["errors_in"] = nic.errin
            iface_info["errors_out"] = nic.errout
        interfaces.append(iface_info)

    # Top processes by CPU
    processes = []
    for proc in psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent", "status"]):
        try:
            info = proc.info
            if info["cpu_percent"] and info["cpu_percent"] > 0:
                processes.append(info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    processes.sort(key=lambda p: p.get("cpu_percent", 0), reverse=True)

    # Network connections
    connections = []
    try:
        for conn in psutil.net_connections(kind="inet"):
            connections.append({
                "fd": conn.fd,
                "family": str(conn.family),
                "type": str(conn.type),
                "laddr": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                "raddr": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                "status": conn.status,
                "pid": conn.pid,
            })
    except (psutil.AccessDenied, PermissionError):
        pass

    # Collect running services (listening ports)
    services = []
    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.status == "LISTEN" and conn.laddr:
                svc_info = {
                    "port": conn.laddr.port,
                    "address": conn.laddr.ip,
                    "protocol": "tcp",
                    "pid": conn.pid,
                    "name": None,
                }
                if conn.pid:
                    try:
                        proc = psutil.Process(conn.pid)
                        svc_info["name"] = proc.name()
                        svc_info["cmdline"] = " ".join(proc.cmdline()[:3])
                        try:
                            svc_info["username"] = proc.username()
                        except psutil.AccessDenied:
                            pass
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                services.append(svc_info)
        seen_ports = set()
        unique_services = []
        for svc in services:
            if svc["port"] not in seen_ports:
                seen_ports.add(svc["port"])
                unique_services.append(svc)
        services = sorted(unique_services, key=lambda s: s["port"])
    except (psutil.AccessDenied, PermissionError):
        pass

    # Windows services via WMI
    windows_services = []
    if WMI_AVAILABLE:
        try:
            c = wmi.WMI()
            for svc in c.Win32_Service():
                if svc.State == "Running":
                    windows_services.append({
                        "name": svc.Name,
                        "display_name": svc.DisplayName,
                        "state": svc.State,
                        "start_mode": svc.StartMode,
                        "pid": svc.ProcessId,
                        "path": svc.PathName,
                    })
        except Exception:
            pass

    return {
        "timestamp": time.time(),
        "cpu": {
            "percent": psutil.cpu_percent(interval=1),
            "per_cpu": psutil.cpu_percent(interval=0, percpu=True),
            "count_logical": psutil.cpu_count(),
            "count_physical": psutil.cpu_count(logical=False),
            "freq_mhz": cpu_freq.current if cpu_freq else None,
        },
        "memory": {
            "total_gb": round(mem.total / (1024 ** 3), 2),
            "used_gb": round(mem.used / (1024 ** 3), 2),
            "available_gb": round(mem.available / (1024 ** 3), 2),
            "percent": mem.percent,
        },
        "disks": disks,
        "network": {
            "bytes_sent": net_io.bytes_sent,
            "bytes_recv": net_io.bytes_recv,
            "packets_sent": net_io.packets_sent,
            "packets_recv": net_io.packets_recv,
            "errors_in": net_io.errin,
            "errors_out": net_io.errout,
            "interfaces": interfaces,
        },
        "services": services,
        "windows_services": windows_services[:50],
        "processes_top10": processes[:10],
        "connections_count": len(connections),
        "connections": connections[:50],
    }


def _get_primary_ip() -> str:
    """Get the primary IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def collect_windows_event_logs(max_entries: int = 50) -> list[dict]:
    """Collect recent Windows Event Log entries (System + Security)."""
    entries = []
    if not WIN32_AVAILABLE:
        return entries

    try:
        import win32evtlog
        import win32evtlogutil

        for log_type in ["System", "Security"]:
            try:
                hand = win32evtlog.OpenEventLog(None, log_type)
                flags = (
                    win32evtlog.EVENTLOG_BACKWARDS_READ
                    | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                )
                count = 0
                while count < max_entries:
                    events = win32evtlog.ReadEventLog(hand, flags, 0)
                    if not events:
                        break
                    for event in events:
                        if count >= max_entries:
                            break
                        entries.append({
                            "source": event.SourceName,
                            "event_id": event.EventID & 0xFFFF,
                            "event_type": event.EventType,
                            "log_type": log_type,
                            "time": event.TimeGenerated.Format(),
                            "message": win32evtlogutil.SafeFormatMessage(
                                event, log_type
                            )[:500] if hasattr(win32evtlogutil, 'SafeFormatMessage') else "",
                        })
                        count += 1
                win32evtlog.CloseEventLog(hand)
            except Exception:
                continue
    except ImportError:
        pass

    return entries


def run_agent(server_url: str, interval: int = 30):
    """Run the Windows agent loop."""
    import httpx

    server_url = server_url.rstrip("/")
    print(f"[AptumNet Windows Agent] Starting - Server: {server_url}, Interval: {interval}s")
    print(f"[Agent] Platform: {platform.platform()}")
    print(f"[Agent] WMI available: {WMI_AVAILABLE}")
    print(f"[Agent] Win32 available: {WIN32_AVAILABLE}")

    while True:
        try:
            payload = {
                "system_info": collect_system_info(),
                "metrics": collect_metrics(),
            }

            with httpx.Client(timeout=10) as client:
                resp = client.post(
                    f"{server_url}/api/agent/report",
                    json=payload
                )
                if resp.status_code == 200:
                    print(f"[Agent] Metrics sent successfully")
                else:
                    print(f"[Agent] Server responded with {resp.status_code}: {resp.text[:200]}")

            # Optionally send Windows event logs
            if WIN32_AVAILABLE:
                try:
                    events = collect_windows_event_logs(30)
                    if events:
                        lines = [
                            f"[{e['log_type']}] [{e['source']}] EventID={e['event_id']} {e.get('message', '')[:200]}"
                            for e in events
                        ]
                        sys_info = payload["system_info"]
                        with httpx.Client(timeout=10) as client:
                            client.post(
                                f"{server_url}/api/logs/ingest",
                                json={
                                    "source": "windows_event",
                                    "host_ip": sys_info["ip_address"],
                                    "lines": lines,
                                },
                            )
                except Exception as e:
                    print(f"[Agent] Event log forwarding error: {e}")

        except Exception as e:
            print(f"[Agent] Error: {e}")

        time.sleep(interval)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AptumNet Windows Monitoring Agent")
    parser.add_argument("--server", required=True, help="Server URL (e.g., http://server:8000)")
    parser.add_argument("--interval", type=int, default=30, help="Collection interval in seconds")
    args = parser.parse_args()

    run_agent(args.server, args.interval)
