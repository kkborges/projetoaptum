"""SNMP collector module for network device monitoring."""
import asyncio
from datetime import datetime
from typing import Optional


# Standard SNMP OIDs
OIDS = {
    "sysDescr": "1.3.6.1.2.1.1.1.0",
    "sysUpTime": "1.3.6.1.2.1.1.3.0",
    "sysName": "1.3.6.1.2.1.1.5.0",
    "sysLocation": "1.3.6.1.2.1.1.6.0",
    "ifNumber": "1.3.6.1.2.1.2.1.0",
    "ifDescr": "1.3.6.1.2.1.2.2.1.2",
    "ifOperStatus": "1.3.6.1.2.1.2.2.1.8",
    "ifInOctets": "1.3.6.1.2.1.2.2.1.10",
    "ifOutOctets": "1.3.6.1.2.1.2.2.1.16",
    "hrProcessorLoad": "1.3.6.1.2.1.25.3.3.1.2",
    "hrStorageDescr": "1.3.6.1.2.1.25.2.3.1.3",
    "hrStorageSize": "1.3.6.1.2.1.25.2.3.1.5",
    "hrStorageUsed": "1.3.6.1.2.1.25.2.3.1.6",
    "hrMemorySize": "1.3.6.1.2.1.25.2.2.0",
}


async def snmp_get(ip: str, oid: str, community: str = "public",
                   port: int = 161, timeout: float = 5.0) -> Optional[str]:
    """Perform SNMP GET request."""
    try:
        from pysnmp.hlapi import (
            getCmd, SnmpEngine, CommunityData, UdpTransportTarget,
            ContextData, ObjectType, ObjectIdentity
        )

        loop = asyncio.get_event_loop()

        def _do_get():
            error_indication, error_status, _, var_binds = next(
                getCmd(
                    SnmpEngine(),
                    CommunityData(community),
                    UdpTransportTarget((ip, port), timeout=timeout),
                    ContextData(),
                    ObjectType(ObjectIdentity(oid))
                )
            )
            if error_indication or error_status:
                return None
            for _, val in var_binds:
                return str(val)
            return None

        return await loop.run_in_executor(None, _do_get)
    except ImportError:
        return None
    except Exception:
        return None


async def snmp_walk(ip: str, oid: str, community: str = "public",
                    port: int = 161) -> list[tuple[str, str]]:
    """Perform SNMP WALK."""
    try:
        from pysnmp.hlapi import (
            nextCmd, SnmpEngine, CommunityData, UdpTransportTarget,
            ContextData, ObjectType, ObjectIdentity
        )

        loop = asyncio.get_event_loop()

        def _do_walk():
            results = []
            for error_indication, error_status, _, var_binds in nextCmd(
                SnmpEngine(),
                CommunityData(community),
                UdpTransportTarget((ip, port), timeout=5),
                ContextData(),
                ObjectType(ObjectIdentity(oid)),
                lexicographicMode=False
            ):
                if error_indication or error_status:
                    break
                for var_bind in var_binds:
                    results.append((str(var_bind[0]), str(var_bind[1])))
            return results

        return await loop.run_in_executor(None, _do_walk)
    except ImportError:
        return []
    except Exception:
        return []


async def collect_host_info(ip: str, community: str = "public") -> dict:
    """Collect system information via SNMP."""
    info = {
        "ip": ip,
        "snmp_available": False,
        "collected_at": datetime.utcnow().isoformat()
    }

    sys_descr = await snmp_get(ip, OIDS["sysDescr"], community)
    if sys_descr is None:
        return info

    info["snmp_available"] = True
    info["sys_description"] = sys_descr
    info["sys_name"] = await snmp_get(ip, OIDS["sysName"], community)
    info["sys_location"] = await snmp_get(ip, OIDS["sysLocation"], community)

    uptime = await snmp_get(ip, OIDS["sysUpTime"], community)
    if uptime:
        info["uptime_ticks"] = uptime

    return info


async def collect_metrics(ip: str, community: str = "public") -> dict:
    """Collect performance metrics via SNMP."""
    metrics = {
        "ip": ip,
        "collected_at": datetime.utcnow().isoformat(),
        "cpu": [],
        "interfaces": [],
        "storage": [],
    }

    # CPU load
    cpu_data = await snmp_walk(ip, OIDS["hrProcessorLoad"], community)
    for oid_str, val in cpu_data:
        try:
            metrics["cpu"].append({"load_percent": int(val)})
        except (ValueError, TypeError):
            pass

    # Network interfaces
    if_descrs = await snmp_walk(ip, OIDS["ifDescr"], community)
    if_statuses = await snmp_walk(ip, OIDS["ifOperStatus"], community)
    if_in = await snmp_walk(ip, OIDS["ifInOctets"], community)
    if_out = await snmp_walk(ip, OIDS["ifOutOctets"], community)

    for i, (oid_str, name) in enumerate(if_descrs):
        iface = {"name": name}
        if i < len(if_statuses):
            iface["status"] = "up" if if_statuses[i][1] == "1" else "down"
        if i < len(if_in):
            try:
                iface["in_octets"] = int(if_in[i][1])
            except (ValueError, TypeError):
                pass
        if i < len(if_out):
            try:
                iface["out_octets"] = int(if_out[i][1])
            except (ValueError, TypeError):
                pass
        metrics["interfaces"].append(iface)

    # Storage
    storage_descrs = await snmp_walk(ip, OIDS["hrStorageDescr"], community)
    storage_sizes = await snmp_walk(ip, OIDS["hrStorageSize"], community)
    storage_used = await snmp_walk(ip, OIDS["hrStorageUsed"], community)

    for i, (oid_str, name) in enumerate(storage_descrs):
        storage = {"name": name}
        if i < len(storage_sizes):
            try:
                storage["size"] = int(storage_sizes[i][1])
            except (ValueError, TypeError):
                pass
        if i < len(storage_used):
            try:
                storage["used"] = int(storage_used[i][1])
            except (ValueError, TypeError):
                pass
        if "size" in storage and "used" in storage and storage["size"] > 0:
            storage["usage_percent"] = round(
                (storage["used"] / storage["size"]) * 100, 1
            )
        metrics["storage"].append(storage)

    return metrics
