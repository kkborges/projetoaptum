"""Network scanner module - host discovery and port scanning."""
import socket
import struct
import asyncio
import ipaddress
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

from app.core.config import SCAN_TIMEOUT, SCAN_THREADS


def _tcp_connect_scan(ip: str, port: int, timeout: float) -> dict:
    """Attempt TCP connection to determine port state."""
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        # Use connect() instead of connect_ex() for reliable timeout handling
        try:
            sock.connect((ip, port))
        except socket.timeout:
            return {"port": port, "state": "filtered", "banner": ""}
        except ConnectionRefusedError:
            return {"port": port, "state": "closed", "banner": ""}
        except OSError as e:
            # ENETUNREACH, EHOSTUNREACH, etc.
            if e.errno in (111, 113, 101):  # ECONNREFUSED, EHOSTUNREACH, ENETUNREACH
                return {"port": port, "state": "closed", "banner": ""}
            return {"port": port, "state": "filtered", "banner": ""}

        # Port is open — try to grab banner
        banner = ""
        try:
            # For non-HTTP services, just try receiving first
            sock.settimeout(2)
            sock.send(b"\r\n")
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        except Exception:
            pass

        if not banner:
            try:
                sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock2.settimeout(3)
                sock2.connect((ip, port))
                sock2.send(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = sock2.recv(1024).decode("utf-8", errors="ignore").strip()
                sock2.close()
            except Exception:
                pass

        return {"port": port, "state": "open", "banner": banner}

    except socket.timeout:
        return {"port": port, "state": "filtered", "banner": ""}
    except Exception:
        return {"port": port, "state": "closed", "banner": ""}
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888, 9090, 27017
]

SERVICE_MAP = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
    139: "netbios-ssn", 143: "imap", 443: "https", 445: "microsoft-ds",
    993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle",
    3306: "mysql", 3389: "rdp", 5432: "postgresql", 5900: "vnc",
    6379: "redis", 8080: "http-proxy", 8443: "https-alt",
    8888: "http-alt", 9090: "web-console", 27017: "mongodb"
}


def identify_host_type(open_ports: list[int]) -> str:
    """Guess host type based on open ports."""
    port_set = set(open_ports)
    if port_set & {80, 443, 8080, 8443}:
        if port_set & {22}:
            return "server"
        return "server"
    if port_set & {161, 162}:
        return "network_device"
    if port_set & {3389}:
        return "workstation"
    if port_set & {515, 631, 9100}:
        return "printer"
    if port_set & {23} and len(open_ports) < 5:
        return "switch"
    return "unknown"


async def ping_host(ip: str, timeout: float = 2.0) -> bool:
    """Check if host is reachable using TCP SYN to common ports."""
    loop = asyncio.get_event_loop()
    quick_ports = [80, 443, 22, 445, 139]
    for port in quick_ports:
        try:
            result = await asyncio.wait_for(
                loop.run_in_executor(None, lambda p=port: _tcp_connect_scan(ip, p, timeout)),
                timeout=timeout + 1
            )
            if result["state"] == "open":
                return True
        except (asyncio.TimeoutError, Exception):
            continue
    # Try fallback — connect to echo port
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, 7))
        sock.close()
        return result == 0
    except Exception:
        return False


async def discover_hosts(network: str, progress_callback=None) -> list[dict]:
    """Discover live hosts on a network (CIDR notation)."""
    try:
        net = ipaddress.ip_network(network, strict=False)
    except ValueError:
        return []

    hosts = list(net.hosts())
    total = len(hosts)
    discovered = []
    loop = asyncio.get_event_loop()

    async def check_host(ip_str, idx):
        is_up = await ping_host(ip_str, timeout=SCAN_TIMEOUT)
        if progress_callback:
            progress_callback(int((idx / total) * 100))
        if is_up:
            hostname = None
            try:
                # Try reverse DNS first (more reliable for internal hosts)
                result = await loop.run_in_executor(
                    None, lambda: socket.gethostbyaddr(ip_str)
                )
                hostname = result[0] if result[0] != ip_str else None
            except (socket.herror, socket.gaierror, OSError):
                pass
            if not hostname:
                try:
                    hostname = await loop.run_in_executor(
                        None, lambda: socket.getfqdn(ip_str)
                    )
                    if hostname == ip_str:
                        hostname = None
                except Exception:
                    pass
            return {
                "ip_address": ip_str,
                "hostname": hostname,
                "status": "up",
                "first_seen": datetime.utcnow().isoformat(),
                "last_seen": datetime.utcnow().isoformat(),
            }
        return None

    semaphore = asyncio.Semaphore(SCAN_THREADS)

    async def bounded_check(ip_str, idx):
        async with semaphore:
            return await check_host(ip_str, idx)

    tasks = [bounded_check(str(ip), i) for i, ip in enumerate(hosts)]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for r in results:
        if r and not isinstance(r, Exception):
            discovered.append(r)

    return discovered


async def scan_ports(ip: str, ports: Optional[list[int]] = None, progress_callback=None) -> list[dict]:
    """Scan ports on a specific host."""
    if ports is None:
        ports = COMMON_PORTS

    loop = asyncio.get_event_loop()
    total = len(ports)
    results = []

    with ThreadPoolExecutor(max_workers=SCAN_THREADS) as executor:
        futures = []
        for port in ports:
            future = loop.run_in_executor(
                executor, _tcp_connect_scan, ip, port, SCAN_TIMEOUT
            )
            futures.append(future)

        for i, future in enumerate(asyncio.as_completed(futures)):
            result = await future
            result["service"] = SERVICE_MAP.get(result["port"], "unknown")
            results.append(result)
            if progress_callback:
                progress_callback(int(((i + 1) / total) * 100))

    results.sort(key=lambda x: x["port"])
    return results


async def full_scan(network: str, progress_callback=None) -> dict:
    """Full network scan: discover hosts then scan ports on each."""
    hosts = await discover_hosts(network, progress_callback)

    for host in hosts:
        port_results = await scan_ports(host["ip_address"])
        open_ports = [p for p in port_results if p["state"] == "open"]
        host["ports"] = port_results
        host["open_ports_count"] = len(open_ports)
        host["host_type"] = identify_host_type([p["port"] for p in open_ports])

    return {
        "network": network,
        "total_hosts": len(hosts),
        "hosts": hosts,
        "scanned_at": datetime.utcnow().isoformat()
    }
