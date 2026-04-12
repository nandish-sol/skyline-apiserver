"""PowerDNS API client for DNS & IPAM panel."""

from __future__ import annotations

import logging

import httpx

from skyline_apiserver.client.dns_ipam import decrypt_password

LOG = logging.getLogger(__name__)

TIMEOUT = httpx.Timeout(30.0, connect=10.0)


def _build_client(conn: dict) -> tuple[httpx.AsyncClient, str]:
    api_key = decrypt_password(conn["password_encrypted"])
    base = conn["api_url"].rstrip("/")
    if "/api/v1/servers/localhost" not in base:
        base += "/api/v1/servers/localhost"
    client = httpx.AsyncClient(
        verify=conn.get("ssl_verify", False),
        timeout=TIMEOUT,
        headers={
            "X-API-Key": api_key,
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
    )
    return client, base


async def test_connection(conn: dict) -> dict:
    try:
        client, base = _build_client(conn)
        async with client:
            resp = await client.get(base)
            resp.raise_for_status()
            data = resp.json()
            version = data.get("version", "")
        return {
            "ok": True,
            "message": f"Connected (v{version})",
            "grid_ref": f"PowerDNS {version}",
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
    client, base = _build_client(conn)
    async with client:
        resp = await client.get(f"{base}/zones")
        resp.raise_for_status()
        return [
            {
                "id": z.get("id", ""),
                "fqdn": z.get("name", "").rstrip("."),
                "view": z.get("kind", ""),
                "soa_serial": str(z.get("serial", "")),
                "ns_group": "",
            }
            for z in resp.json()
        ]


async def list_records(conn: dict, zone: str) -> list[dict]:
    client, base = _build_client(conn)
    zone_id = zone.rstrip(".") + "."
    records: list[dict] = []
    async with client:
        resp = await client.get(f"{base}/zones/{zone_id}")
        resp.raise_for_status()
        data = resp.json()
        for rrset in data.get("rrsets", []):
            rtype = rrset.get("type", "")
            if rtype in ("A", "AAAA", "CNAME", "MX", "TXT", "PTR", "SRV"):
                for rec in rrset.get("records", []):
                    records.append({
                        "id": f"{rrset['name']}_{rtype}",
                        "name": rrset.get("name", "").rstrip("."),
                        "type": rtype,
                        "value": rec.get("content", ""),
                        "view": zone,
                        "ttl": str(rrset.get("ttl", "")),
                        "comment": "",
                    })
    return records


async def grid_members(conn: dict) -> list[dict]:
    try:
        client, base = _build_client(conn)
        async with client:
            resp = await client.get(base)
            resp.raise_for_status()
            data = resp.json()
            host = conn["api_url"].split("//")[1].split(":")[0] if "//" in conn["api_url"] else conn["api_url"]
            return [{
                "id": data.get("id", "localhost"),
                "host_name": host,
                "ipv4addr": host,
                "platform": f"PowerDNS {data.get('version', '')}",
                "status": "WORKING",
            }]
    except Exception:
        return []
