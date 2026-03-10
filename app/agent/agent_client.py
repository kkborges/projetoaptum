"""
AptumNet Agent - Lightweight monitoring agent to install on hosts.
Collects system metrics and sends to the central server.
Run: python -m app.agent.agent_client --server http://server:8000
"""
import argparse
import json
import platform
import socket
import time
import sys

import psutil


def collect_system_info() -> dict:
    """Collect comprehensive system information."""
    uname = platform.uname()
    boot_time = psutil.boot_time()

    return {
        "hostname": socket.gethostname(),
        "ip_address": _get_primary_ip(),
        "os": f"{uname.system} {uname.release}",
        "os_version": uname.version,
        "architecture": uname.machine,
        "processor": uname.processor or platform.processor(),
        "boot_time": boot_time,
        "uptime_seconds": time.time() - boot_time,
    }


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
        except PermissionError:
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

    # Top processes
    processes = []
    for proc in psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent", "status"]):
        try:
            info = proc.info
            if info["cpu_percent"] and info["cpu_percent"] > 0:
                processes.append(info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    processes.sort(key=lambda p: p.get("cpu_percent", 0), reverse=True)

    # Connections for security monitoring
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


def run_agent(server_url: str, interval: int = 30):
    """Run the agent loop, sending metrics to the server."""
    import httpx

    print(f"[AptumNet Agent] Starting - Server: {server_url}, Interval: {interval}s")

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
                    print(f"[Agent] Server responded with {resp.status_code}")
        except Exception as e:
            print(f"[Agent] Error sending metrics: {e}")

        time.sleep(interval)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AptumNet Monitoring Agent")
    parser.add_argument("--server", required=True, help="Server URL (e.g., http://server:8000)")
    parser.add_argument("--interval", type=int, default=30, help="Collection interval in seconds")
    args = parser.parse_args()

    run_agent(args.server, args.interval)
