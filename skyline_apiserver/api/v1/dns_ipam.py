"""DNS & IPAM multi-provider management endpoints.

Admin-only. Manages connections to external DNS/IPAM providers
(Infoblox, PowerDNS, Microsoft DNS) and provides unified zone/record
browsing, IPAM network management, and Designate pool configuration.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from starlette.concurrency import run_in_threadpool

from skyline_apiserver.api import deps
from skyline_apiserver.client.dns_ipam import (
    decrypt_password,
    encrypt_password,
    get_provider_client,
)
from skyline_apiserver.db import api as db_api
from skyline_apiserver import schemas
from skyline_apiserver.utils.roles import assert_system_admin

LOG = logging.getLogger(__name__)
router = APIRouter()


# =========================================================================
# Pydantic schemas
# =========================================================================


class ConnectionCreate(BaseModel):
    name: str
    provider_type: str = "infoblox"
    api_url: str
    username: str = ""
    password: str = ""
    dns_view: str = "default"
    network_view: str = "default"
    ns_group: str = ""
    site_name: str = ""
    ssl_verify: bool = True


class ConnectionUpdate(BaseModel):
    name: Optional[str] = None
    api_url: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    dns_view: Optional[str] = None
    network_view: Optional[str] = None
    ns_group: Optional[str] = None
    site_name: Optional[str] = None
    ssl_verify: Optional[bool] = None


class PoolCreate(BaseModel):
    connection_id: str
    pool_name: str = "infoblox-pool"
    ns_hostname: str
    nameserver_host: str
    mdns_host: str = "10.0.1.70"


class IPReserve(BaseModel):
    ipv4addr: str
    mac: str = ""
    hostname: str = ""
    comment: str = ""


class IPRelease(BaseModel):
    ref: str


# =========================================================================
# Helpers
# =========================================================================


def _conn_response(row: Any) -> dict:
    """Convert DB row to response dict, masking password."""
    d = dict(row._mapping) if hasattr(row, "_mapping") else dict(row)
    d.pop("password_encrypted", None)
    d["password"] = "********"
    for k in ("created_at", "updated_at", "last_check"):
        if d.get(k) and hasattr(d[k], "isoformat"):
            d[k] = d[k].isoformat()
    return d


def _pool_response(row: Any) -> dict:
    d = dict(row._mapping) if hasattr(row, "_mapping") else dict(row)
    for k in ("created_at",):
        if d.get(k) and hasattr(d[k], "isoformat"):
            d[k] = d[k].isoformat()
    return d


async def _get_conn_with_password(connection_id: str) -> dict:
    row = await db_api.get_dns_ipam_connection(connection_id)
    if not row:
        raise HTTPException(status_code=404, detail="Connection not found")
    return dict(row._mapping) if hasattr(row, "_mapping") else dict(row)


# =========================================================================
# Connection CRUD
# =========================================================================


@router.get("/dns-ipam/connections")
async def list_connections(
    profile: schemas.Profile = Depends(deps.get_profile),
):
    assert_system_admin(profile=profile, exception="Not allowed")
    rows = await db_api.list_dns_ipam_connections()
    return [_conn_response(r) for r in rows]


@router.post("/dns-ipam/connections")
async def create_connection(
    body: ConnectionCreate,
    profile: schemas.Profile = Depends(deps.get_profile),
):
    assert_system_admin(profile=profile, exception="Not allowed")
    now = datetime.now(timezone.utc)
    values = {
        "id": str(uuid.uuid4()),
        "name": body.name,
        "provider_type": body.provider_type,
        "api_url": body.api_url.rstrip("/") + "/",
        "username": body.username,
        "password_encrypted": encrypt_password(body.password),
        "dns_view": body.dns_view,
        "network_view": body.network_view,
        "ns_group": body.ns_group,
        "site_name": body.site_name,
        "ssl_verify": body.ssl_verify,
        "status": "unknown",
        "created_by": profile.user.id if profile.user else "",
        "created_at": now,
        "updated_at": now,
    }
    row = await db_api.create_dns_ipam_connection(values)
    return _conn_response(row)


@router.get("/dns-ipam/connections/{connection_id}")
async def get_connection(
    connection_id: str,
    profile: schemas.Profile = Depends(deps.get_profile),
):
    assert_system_admin(profile=profile, exception="Not allowed")
    row = await db_api.get_dns_ipam_connection(connection_id)
    if not row:
        raise HTTPException(status_code=404, detail="Connection not found")
    return _conn_response(row)


@router.put("/dns-ipam/connections/{connection_id}")
async def update_connection(
    connection_id: str,
    body: ConnectionUpdate,
    profile: schemas.Profile = Depends(deps.get_profile),
):
    assert_system_admin(profile=profile, exception="Not allowed")
    existing = await db_api.get_dns_ipam_connection(connection_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Connection not found")
    values: dict[str, Any] = {"updated_at": datetime.now(timezone.utc)}
    for field in ("name", "api_url", "username", "dns_view", "network_view",
                  "ns_group", "site_name", "ssl_verify"):
        val = getattr(body, field, None)
        if val is not None:
            if field == "api_url":
                val = val.rstrip("/") + "/"
            values[field] = val
    if body.password:
        values["password_encrypted"] = encrypt_password(body.password)
    row = await db_api.update_dns_ipam_connection(connection_id, values)
    return _conn_response(row)


@router.delete("/dns-ipam/connections/{connection_id}")
async def delete_connection(
    connection_id: str,
    profile: schemas.Profile = Depends(deps.get_profile),
):
    assert_system_admin(profile=profile, exception="Not allowed")
    await db_api.delete_dns_ipam_connection(connection_id)
    return {"ok": True}


# =========================================================================
# Connection test
# =========================================================================


@router.post("/dns-ipam/connections/{connection_id}/test")
async def test_connection(
    connection_id: str,
    profile: schemas.Profile = Depends(deps.get_profile),
):
    assert_system_admin(profile=profile, exception="Not allowed")
    conn = await _get_conn_with_password(connection_id)
    client = get_provider_client(conn["provider_type"])
    result = await client.test_connection(conn)
    update_values: dict[str, Any] = {
        "status": result.get("status", "unknown"),
        "last_check": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    if result.get("grid_ref"):
        update_values["grid_ref"] = result["grid_ref"]
    if result.get("ok"):
        update_values["last_error"] = None
    else:
        update_values["last_error"] = result.get("message", "")
    await db_api.update_dns_ipam_connection(connection_id, update_values)
    return result


# =========================================================================
# Provider data (live queries)
# =========================================================================


@router.get("/dns-ipam/connections/{connection_id}/zones")
async def list_provider_zones(
    connection_id: str,
    profile: schemas.Profile = Depends(deps.get_profile),
):
    assert_system_admin(profile=profile, exception="Not allowed")
    conn = await _get_conn_with_password(connection_id)
    client = get_provider_client(conn["provider_type"])
    return await client.list_zones(conn)


@router.get("/dns-ipam/connections/{connection_id}/zones/{zone}/records")
async def list_provider_records(
    connection_id: str,
    zone: str,
    profile: schemas.Profile = Depends(deps.get_profile),
):
    assert_system_admin(profile=profile, exception="Not allowed")
    conn = await _get_conn_with_password(connection_id)
    client = get_provider_client(conn["provider_type"])
    return await client.list_records(conn, zone)


@router.get("/dns-ipam/connections/{connection_id}/networks")
async def list_provider_networks(
    connection_id: str,
    network_view: Optional[str] = Query(None),
    profile: schemas.Profile = Depends(deps.get_profile),
):
    assert_system_admin(profile=profile, exception="Not allowed")
    conn = await _get_conn_with_password(connection_id)
    if conn["provider_type"] != "infoblox":
        raise HTTPException(status_code=400, detail="IPAM only available for Infoblox")
    from skyline_apiserver.client.dns_ipam import infoblox
    return await infoblox.list_networks(conn, network_view)


@router.get("/dns-ipam/connections/{connection_id}/networks/{network_ref:path}/addresses")
async def list_provider_addresses(
    connection_id: str,
    network_ref: str,
    profile: schemas.Profile = Depends(deps.get_profile),
):
    assert_system_admin(profile=profile, exception="Not allowed")
    conn = await _get_conn_with_password(connection_id)
    if conn["provider_type"] != "infoblox":
        raise HTTPException(status_code=400, detail="IPAM only available for Infoblox")
    from skyline_apiserver.client.dns_ipam import infoblox
    return await infoblox.list_addresses(conn, network_ref)


@router.get("/dns-ipam/connections/{connection_id}/conflicts")
async def list_provider_conflicts(
    connection_id: str,
    profile: schemas.Profile = Depends(deps.get_profile),
):
    assert_system_admin(profile=profile, exception="Not allowed")
    conn = await _get_conn_with_password(connection_id)
    if conn["provider_type"] != "infoblox":
        raise HTTPException(status_code=400, detail="Conflicts only available for Infoblox")
    from skyline_apiserver.client.dns_ipam import infoblox
    return await infoblox.list_conflicts(conn)


@router.get("/dns-ipam/connections/{connection_id}/members")
async def list_provider_members(
    connection_id: str,
    profile: schemas.Profile = Depends(deps.get_profile),
):
    assert_system_admin(profile=profile, exception="Not allowed")
    conn = await _get_conn_with_password(connection_id)
    client = get_provider_client(conn["provider_type"])
    return await client.grid_members(conn)


# =========================================================================
# IP management (Infoblox only)
# =========================================================================


@router.post("/dns-ipam/connections/{connection_id}/ip/reserve")
async def reserve_ip(
    connection_id: str,
    body: IPReserve,
    profile: schemas.Profile = Depends(deps.get_profile),
):
    assert_system_admin(profile=profile, exception="Not allowed")
    conn = await _get_conn_with_password(connection_id)
    if conn["provider_type"] != "infoblox":
        raise HTTPException(status_code=400, detail="IP reserve only for Infoblox")
    from skyline_apiserver.client.dns_ipam import infoblox
    return await infoblox.reserve_ip(
        conn, body.ipv4addr, body.mac, body.hostname, body.comment,
    )


@router.post("/dns-ipam/connections/{connection_id}/ip/release")
async def release_ip(
    connection_id: str,
    body: IPRelease,
    profile: schemas.Profile = Depends(deps.get_profile),
):
    assert_system_admin(profile=profile, exception="Not allowed")
    conn = await _get_conn_with_password(connection_id)
    if conn["provider_type"] != "infoblox":
        raise HTTPException(status_code=400, detail="IP release only for Infoblox")
    from skyline_apiserver.client.dns_ipam import infoblox
    return await infoblox.release_ip(conn, body.ref)


# =========================================================================
# Designate zone comparison
# =========================================================================


@router.get("/dns-ipam/designate-zones")
async def list_designate_zones(
    profile: schemas.Profile = Depends(deps.get_profile),
):
    assert_system_admin(profile=profile, exception="Not allowed")
    try:
        import httpx
        from skyline_apiserver.client.utils import generate_session, get_system_session

        session = await generate_session(profile)
        token = session.get_token()
        endpoint = session.get_endpoint(service_type="dns", interface="internal")
        if not endpoint:
            endpoint = session.get_endpoint(service_type="dns", interface="public")
        if not endpoint:
            return []
        async with httpx.AsyncClient(verify=False, timeout=30) as client:
            resp = await client.get(
                f"{endpoint}/v2/zones",
                headers={"X-Auth-Token": token},
                params={"limit": "1000"},
            )
            resp.raise_for_status()
            data = resp.json()
        return [
            {
                "id": z.get("id", ""),
                "name": z.get("name", ""),
                "type": z.get("type", "PRIMARY"),
                "status": z.get("status", ""),
                "serial": z.get("serial", ""),
            }
            for z in data.get("zones", [])
        ]
    except Exception as e:
        LOG.debug("Designate zones unavailable: %s", e)
        return []


# =========================================================================
# Pool snippets
# =========================================================================


@router.get("/dns-ipam/pools")
async def list_pools(
    profile: schemas.Profile = Depends(deps.get_profile),
):
    assert_system_admin(profile=profile, exception="Not allowed")
    rows = await db_api.list_dns_ipam_pools()
    return [_pool_response(r) for r in rows]


@router.post("/dns-ipam/pools")
async def create_pool(
    body: PoolCreate,
    profile: schemas.Profile = Depends(deps.get_profile),
):
    assert_system_admin(profile=profile, exception="Not allowed")
    conn = await _get_conn_with_password(body.connection_id)
    from skyline_apiserver.client.dns_ipam.infoblox import generate_pool_snippet

    snippet, pool_uuid = generate_pool_snippet(
        conn,
        pool_name=body.pool_name,
        ns_hostname=body.ns_hostname,
        nameserver_host=body.nameserver_host,
        mdns_host=body.mdns_host,
    )
    values = {
        "id": str(uuid.uuid4()),
        "connection_id": body.connection_id,
        "designate_pool_id": pool_uuid,
        "pool_name": body.pool_name,
        "ns_hostname": body.ns_hostname,
        "nameserver_host": body.nameserver_host,
        "mdns_host": body.mdns_host,
        "status": "draft",
        "pools_yaml_snippet": snippet,
        "created_by": profile.user.id if profile.user else "",
        "created_at": datetime.now(timezone.utc),
    }
    row = await db_api.create_dns_ipam_pool(values)
    result = _pool_response(row)
    result["pools_yaml_snippet"] = snippet
    return result


@router.delete("/dns-ipam/pools/{pool_id}")
async def delete_pool(
    pool_id: str,
    profile: schemas.Profile = Depends(deps.get_profile),
):
    assert_system_admin(profile=profile, exception="Not allowed")
    await db_api.delete_dns_ipam_pool(pool_id)
    return {"ok": True}
