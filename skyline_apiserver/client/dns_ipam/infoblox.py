"""Infoblox WAPI client for DNS & IPAM panel.

Async httpx calls to Infoblox Grid Manager WAPI.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from skyline_apiserver.client.dns_ipam import decrypt_password

LOG = logging.getLogger(__name__)

TIMEOUT = httpx.Timeout(30.0, connect=10.0)


def _build_client(conn: dict) -> tuple[httpx.AsyncClient, str]:
    password = decrypt_password(conn["password_encrypted"])
    base_url = conn["api_url"].rstrip("/")
    client = httpx.AsyncClient(
        auth=(conn["username"], password),
        verify=conn.get("ssl_verify", False),
        timeout=TIMEOUT,
        headers={"Content-Type": "application/json"},
    )
    return client, base_url


async def _wapi_get(
    conn: dict, object_type: str, params: dict | None = None,
    return_fields: list[str] | None = None,
) -> list[dict]:
    client, base_url = _build_client(conn)
    url = f"{base_url}/{object_type}"
    p = dict(params or {})
    if return_fields:
        p["_return_fields"] = ",".join(return_fields)
    async with client:
        resp = await client.get(url, params=p)
        resp.raise_for_status()
        return resp.json()


async def _wapi_post(conn: dict, object_type: str, payload: dict) -> Any:
    client, base_url = _build_client(conn)
    url = f"{base_url}/{object_type}"
    async with client:
        resp = await client.post(url, json=payload)
        resp.raise_for_status()
        return resp.json()


async def _wapi_delete(conn: dict, ref: str) -> Any:
    client, base_url = _build_client(conn)
    url = f"{base_url.rsplit('/wapi/', 1)[0]}/wapi/{ref}"
    async with client:
        resp = await client.delete(url)
        resp.raise_for_status()
        return resp.json()


async def _wapi_function(
    conn: dict, ref: str, func_name: str, payload: dict,
) -> Any:
    client, base_url = _build_client(conn)
    url = f"{base_url.rsplit('/wapi/', 1)[0]}/wapi/{ref}"
    async with client:
        resp = await client.post(url, params={"_function": func_name}, json=payload)
        resp.raise_for_status()
        return resp.json()


async def test_connection(conn: dict) -> dict:
    try:
        result = await _wapi_get(conn, "grid", return_fields=["_ref"])
        grid_ref = result[0].get("_ref", "") if result else ""
        return {
            "ok": True,
            "message": "Connected",
            "grid_ref": grid_ref,
            "status": "active",
        }
    except Exception as e:
        return {
            "ok": False,
            "message": str(e)[:500],
            "grid_ref": "",
            "status": "error",
        }


async def list_zones(conn: dict) -> list[dict]:
    zones = await _wapi_get(
        conn, "zone_auth",
        return_fields=["fqdn", "view", "soa_serial_number", "ns_group"],
    )
    return [
        {
            "id": z.get("_ref", ""),
            "fqdn": z.get("fqdn", ""),
            "view": z.get("view", ""),
            "soa_serial": str(z.get("soa_serial_number", "")),
            "ns_group": z.get("ns_group", ""),
        }
        for z in zones
    ]


async def list_records(conn: dict, zone: str) -> list[dict]:
    records = await _wapi_get(
        conn, "record:a",
        params={"zone": zone},
        return_fields=["name", "ipv4addr", "view", "ttl", "comment"],
    )
    result = []
    for r in records:
        result.append({
            "id": r.get("_ref", ""),
            "name": r.get("name", ""),
            "type": "A",
            "value": r.get("ipv4addr", ""),
            "view": r.get("view", ""),
            "ttl": str(r.get("ttl", "")),
            "comment": r.get("comment", ""),
        })
    return result


async def list_networks(conn: dict, network_view: str | None = None) -> list[dict]:
    params = {}
    if network_view:
        params["network_view"] = network_view
    networks = await _wapi_get(
        conn, "network",
        params=params,
        return_fields=["network", "network_view", "comment", "utilization"],
    )
    return [
        {
            "id": n.get("_ref", ""),
            "network": n.get("network", ""),
            "network_view": n.get("network_view", ""),
            "comment": n.get("comment", ""),
            "utilization": n.get("utilization", 0),
        }
        for n in networks
    ]


async def list_addresses(
    conn: dict, network: str | None = None,
) -> list[dict]:
    params: dict[str, str] = {"_max_results": "500"}
    if network:
        params["network"] = network
    addresses = await _wapi_get(
        conn, "ipv4address",
        params=params,
        return_fields=[
            "ip_address", "status", "mac_address",
            "is_conflict", "names", "types", "network",
        ],
    )
    return [
        {
            "id": a.get("_ref", ""),
            "ip_address": a.get("ip_address", ""),
            "status": a.get("status", ""),
            "mac_address": a.get("mac_address", ""),
            "is_conflict": a.get("is_conflict", False),
            "names": ", ".join(a.get("names", [])),
            "types": ", ".join(a.get("types", [])),
            "network": a.get("network", ""),
        }
        for a in addresses
    ]


async def list_conflicts(conn: dict) -> list[dict]:
    try:
        addresses = await _wapi_get(
            conn, "ipv4address",
            params={"is_conflict": "true", "_max_results": "500"},
            return_fields=[
                "ip_address", "status", "mac_address",
                "is_conflict", "names", "network",
            ],
        )
    except Exception:
        return []
    return [
        {
            "id": c.get("_ref", ""),
            "ip_address": c.get("ip_address", ""),
            "status": c.get("status", ""),
            "mac_address": c.get("mac_address", ""),
            "names": ", ".join(c.get("names", [])),
            "network": c.get("network", ""),
        }
        for c in addresses
    ]


async def reserve_ip(
    conn: dict, ipv4addr: str, mac: str = "", hostname: str = "",
    comment: str = "",
) -> Any:
    payload: dict[str, str] = {
        "ipv4addr": ipv4addr,
        "mac": mac or "00:00:00:00:00:00",
        "name": hostname,
    }
    if comment:
        payload["comment"] = comment
    return await _wapi_post(conn, "fixedaddress", payload)


async def release_ip(conn: dict, ref: str) -> Any:
    return await _wapi_delete(conn, ref)


async def grid_members(conn: dict) -> list[dict]:
    try:
        members = await _wapi_get(
            conn, "member:dns",
            return_fields=["host_name", "ipv4addr", "status"],
        )
    except Exception:
        return []
    return [
        {
            "id": m.get("_ref", ""),
            "host_name": m.get("host_name", ""),
            "ipv4addr": m.get("ipv4addr", ""),
            "platform": "Infoblox DDI",
            "status": m.get("status", "UNKNOWN"),
        }
        for m in members
    ]


async def next_available_ip(
    conn: dict, network: str, count: int = 1,
) -> list[str]:
    networks = await _wapi_get(
        conn, "network",
        params={"network": network},
        return_fields=["network"],
    )
    if not networks:
        return []
    net_ref = networks[0]["_ref"]
    result = await _wapi_function(
        conn, net_ref, "next_available_ip", {"num": count},
    )
    return result.get("ips", [])


def generate_pool_snippet(
    conn: dict, pool_name: str, ns_hostname: str,
    nameserver_host: str, mdns_host: str,
) -> str:
    import uuid

    password = decrypt_password(conn["password_encrypted"])
    pool_uuid = str(uuid.uuid4())
    return (
        f"- name: {pool_name}\n"
        f"  id: {pool_uuid}\n"
        f"  attributes:\n"
        f"    backend: infoblox\n"
        f"  ns_records:\n"
        f"    - hostname: {ns_hostname}\n"
        f"      priority: 1\n"
        f"  nameservers:\n"
        f"    - host: {nameserver_host}\n"
        f"      port: 53\n"
        f"  targets:\n"
        f"    - type: infoblox\n"
        f"      description: {pool_name}\n"
        f"      masters:\n"
        f"        - host: {mdns_host}\n"
        f"          port: 53\n"
        f"      options:\n"
        f"        wapi_url: {conn['api_url']}\n"
        f"        username: {conn['username']}\n"
        f"        password: {password}\n"
        f"        ns_group: {conn.get('ns_group', 'designate')}\n"
        f"        dns_view: {conn.get('dns_view', 'default')}\n"
        f'        multi_tenant: "0"\n'
    ), pool_uuid
