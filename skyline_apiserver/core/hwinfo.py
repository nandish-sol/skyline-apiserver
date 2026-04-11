# Copyright 2025-2026 Xloud Technologies Pvt Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

"""Pure-stdlib hardware + OS readers for single-node Monitor pages.

Every function is defensive: missing files, permission errors and malformed
content return safe defaults so the endpoint never raises.
"""

from __future__ import annotations

import os
import re
import socket
import time
from typing import Any, Dict, List, Optional

_DMI_DIR = "/sys/class/dmi/id"
_DMI_FIELDS = {
    "sys_vendor": "manufacturer",
    "product_name": "model",
    "product_serial": "serial_number",
    "product_uuid": "uuid",
    "chassis_asset_tag": "asset_tag",
    "bios_vendor": "bios_vendor",
    "bios_version": "bios_version",
    "bios_date": "bios_date",
    "board_vendor": "board_vendor",
    "board_name": "board_name",
}


def _read_first_line(path: str) -> Optional[str]:
    try:
        with open(path, "r") as fh:
            return fh.readline().strip() or None
    except (OSError, PermissionError):
        return None


def _read_all(path: str) -> Optional[str]:
    try:
        with open(path, "r") as fh:
            return fh.read()
    except (OSError, PermissionError):
        return None


def read_dmi() -> Dict[str, Optional[str]]:
    """Read DMI/SMBIOS hardware identifiers.

    Returns a dict with keys: manufacturer, model, serial_number, uuid,
    asset_tag, bios_vendor, bios_version, bios_date, board_vendor, board_name.
    Missing fields are None.
    """
    out: Dict[str, Optional[str]] = {v: None for v in _DMI_FIELDS.values()}
    for fname, key in _DMI_FIELDS.items():
        val = _read_first_line(os.path.join(_DMI_DIR, fname))
        if val and val not in ("", "None", "To be filled by O.E.M.", "Default string"):
            out[key] = val
    return out


def read_cpuinfo() -> Dict[str, Any]:
    """Parse /proc/cpuinfo into a summary.

    Returns: model_name, vendor_id, cores (logical), sockets, mhz, cache_kb.
    """
    raw = _read_all("/proc/cpuinfo") or ""
    processors: List[Dict[str, str]] = []
    current: Dict[str, str] = {}
    for line in raw.splitlines():
        if not line.strip():
            if current:
                processors.append(current)
                current = {}
            continue
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        current[key.strip()] = val.strip()
    if current:
        processors.append(current)

    model_name = None
    vendor_id = None
    mhz = None
    cache_kb = None
    physical_ids = set()
    cores_per_socket = 0
    if processors:
        first = processors[0]
        model_name = first.get("model name") or first.get("Hardware")
        vendor_id = first.get("vendor_id")
        try:
            mhz = float(first.get("cpu MHz", "0")) or None
        except ValueError:
            mhz = None
        cache = first.get("cache size", "")
        m = re.match(r"(\d+)\s*KB", cache)
        if m:
            cache_kb = int(m.group(1))
        for p in processors:
            pid = p.get("physical id")
            if pid is not None:
                physical_ids.add(pid)
        cps = processors[0].get("cpu cores")
        if cps and cps.isdigit():
            cores_per_socket = int(cps)

    return {
        "model_name": model_name,
        "vendor_id": vendor_id,
        "logical_cores": len(processors) or os.cpu_count() or 0,
        "sockets": len(physical_ids) or 1,
        "cores_per_socket": cores_per_socket,
        "mhz": mhz,
        "cache_kb": cache_kb,
    }


def read_meminfo() -> Dict[str, int]:
    """Parse /proc/meminfo. All values in bytes."""
    raw = _read_all("/proc/meminfo") or ""
    out: Dict[str, int] = {}
    for line in raw.splitlines():
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        parts = val.strip().split()
        if not parts or not parts[0].isdigit():
            continue
        kb = int(parts[0])
        out[key.strip()] = kb * 1024
    return out


def read_loadavg() -> Dict[str, float]:
    raw = _read_first_line("/proc/loadavg") or ""
    parts = raw.split()
    out = {"load1": 0.0, "load5": 0.0, "load15": 0.0}
    try:
        if len(parts) >= 3:
            out["load1"] = float(parts[0])
            out["load5"] = float(parts[1])
            out["load15"] = float(parts[2])
    except ValueError:
        pass
    return out


def read_uptime() -> Dict[str, float]:
    raw = _read_first_line("/proc/uptime") or ""
    parts = raw.split()
    try:
        up = float(parts[0]) if parts else 0.0
    except ValueError:
        up = 0.0
    return {
        "uptime_seconds": up,
        "boot_time": time.time() - up,
    }


def read_os_release() -> Dict[str, str]:
    """Read /etc/os-release.

    Prefer the HOST's os-release so reports show XOS instead of the Ubuntu
    base image the apiserver container runs on. Tries (in order):
      /host/etc/os-release   — expected bind-mount from xavs-ansible
      /etc/host-os-release   — docker cp fallback for hot-patched clusters
      /etc/os-release        — container's own file (last resort)
    """
    raw = None
    for path in ("/host/etc/os-release", "/etc/host-os-release", "/etc/os-release"):
        raw = _read_all(path)
        if raw:
            break
    raw = raw or ""
    out: Dict[str, str] = {}
    for line in raw.splitlines():
        if "=" not in line:
            continue
        key, _, val = line.partition("=")
        out[key.strip()] = val.strip().strip('"')
    return out


def read_hostname() -> str:
    h = _read_first_line("/proc/sys/kernel/hostname")
    if h:
        return h
    try:
        return socket.gethostname()
    except OSError:
        return "unknown"


def read_nics() -> List[Dict[str, Any]]:
    """Return a list of NIC dicts: name, mac, ipv4, ipv6, state, mtu."""
    base = "/sys/class/net"
    out: List[Dict[str, Any]] = []
    try:
        names = sorted(os.listdir(base))
    except OSError:
        return out
    for name in names:
        if name == "lo":
            continue
        info: Dict[str, Any] = {"name": name}
        info["mac"] = _read_first_line(os.path.join(base, name, "address"))
        info["state"] = _read_first_line(os.path.join(base, name, "operstate"))
        mtu = _read_first_line(os.path.join(base, name, "mtu"))
        try:
            info["mtu"] = int(mtu) if mtu else None
        except ValueError:
            info["mtu"] = None
        info["ipv4"] = []
        info["ipv6"] = []
        try:
            addrs = socket.getaddrinfo(socket.gethostname(), None)
            for family, _, _, _, sockaddr in addrs:
                if family == socket.AF_INET:
                    info["ipv4"].append(sockaddr[0])
                elif family == socket.AF_INET6:
                    info["ipv6"].append(sockaddr[0])
        except OSError:
            pass
        out.append(info)
    return out


def read_primary_ipv4() -> Optional[str]:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        finally:
            s.close()
    except OSError:
        return None


def read_default_gateway() -> Optional[str]:
    raw = _read_all("/proc/net/route") or ""
    for line in raw.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 3:
            continue
        if parts[1] == "00000000":
            hex_gw = parts[2]
            try:
                b = bytes.fromhex(hex_gw)
                return ".".join(str(x) for x in reversed(b))
            except ValueError:
                return None
    return None


def read_dns_servers() -> List[str]:
    raw = _read_all("/etc/resolv.conf") or ""
    out: List[str] = []
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("nameserver"):
            parts = line.split()
            if len(parts) >= 2:
                out.append(parts[1])
    return out


def collect_hardware_blob() -> Dict[str, Any]:
    """Single entry-point for /xavs-hardware endpoint.

    Returns the complete hardware/configuration/system_info/networking blob
    used by the VMware-style card on Physical Nodes.
    """
    dmi = read_dmi()
    cpu = read_cpuinfo()
    mem = read_meminfo()
    up = read_uptime()
    osr = read_os_release()
    nics = read_nics()
    mem_total_bytes = int(mem.get("MemTotal", 0))

    hostname = read_hostname()
    primary_ip = read_primary_ipv4()
    gateway = read_default_gateway()
    dns = read_dns_servers()

    cpu_summary = None
    if cpu.get("model_name"):
        ghz = (cpu.get("mhz") or 0) / 1000.0
        cpu_summary = (
            f"{cpu.get('logical_cores', 0)} CPUs x {cpu['model_name']}"
            f"{' @ %.2fGHz' % ghz if ghz else ''}"
        )

    return {
        "hardware": {
            "manufacturer": dmi.get("manufacturer") or "Unknown",
            "model": dmi.get("model") or "Unknown",
            "cpu": cpu_summary or "Unknown",
            "cpu_detail": cpu,
            "memory_bytes": mem_total_bytes,
            "memory_display": _format_bytes(mem_total_bytes),
            "virtual_flash": None,
        },
        "configuration": {
            "os_image": osr.get("PRETTY_NAME") or osr.get("NAME") or "Linux",
            "os_version": osr.get("VERSION_ID"),
            "ha_state": "Not configured",
            "live_migration": "Supported",
        },
        "system_information": {
            "host_time": time.strftime("%A, %B %d, %Y, %H:%M:%S UTC", time.gmtime()),
            "install_date": None,
            "asset_tag": dmi.get("asset_tag"),
            "serial_number": dmi.get("serial_number"),
            "bios_vendor": dmi.get("bios_vendor"),
            "bios_version": dmi.get("bios_version"),
            "bios_date": dmi.get("bios_date"),
            "board_vendor": dmi.get("board_vendor"),
            "board_name": dmi.get("board_name"),
            "uuid": dmi.get("uuid"),
        },
        "networking": {
            "hostname": hostname,
            "primary_ipv4": primary_ip,
            "default_gateway": gateway,
            "dns_servers": dns,
            "nics": nics,
        },
        "uptime": up,
        "meminfo_bytes": mem,
    }


def _format_bytes(b: int) -> str:
    if b <= 0:
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    f = float(b)
    for u in units:
        if f < 1024 or u == units[-1]:
            return f"{f:.2f} {u}"
        f /= 1024
    return f"{f:.2f} PB"
