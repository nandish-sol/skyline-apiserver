# Copyright 2021 99cloud
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import annotations

import time
from functools import wraps
from typing import Any, Union

from sqlalchemy import Insert, Update, delete, func, insert, select, update

from skyline_apiserver.types import Fn

from .base import DB, inject_db
from .models import (
    DnsIpamConnections,
    DnsIpamPools,
    RbacRolePermissions,
    RevokedToken,
    Settings,
    SkylineLicenseEvents,
    SkylineLicenses,
    SkylineSystemState,
    UserProfiles,
    UserSessions,
)


def check_db_connected(fn: Fn) -> Any:
    @wraps(fn)
    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        await inject_db()
        db = DB.get()
        assert db is not None, "Database is not connected."
        return await fn(*args, **kwargs)

    return wrapper


@check_db_connected
async def check_token(token_id: str) -> bool:
    count_label = "revoked_count"
    query = (
        select(func.count(RevokedToken.c.uuid).label(count_label))
        .select_from(RevokedToken)
        .where(RevokedToken.c.uuid == token_id)
    )
    db = DB.get()
    async with db.transaction():
        result = await db.fetch_one(query)

    count = getattr(result, count_label, 0)
    return count > 0


@check_db_connected
async def revoke_token(token_id: str, expire: int) -> Any:
    query = insert(RevokedToken)
    db = DB.get()
    async with db.transaction():
        result = await db.execute(query, {"uuid": token_id, "expire": expire})

    return result


@check_db_connected
async def purge_revoked_token() -> Any:
    now = int(time.time()) - 1
    query = delete(RevokedToken).where(RevokedToken.c.expire < now)
    db = DB.get()
    async with db.transaction():
        result = await db.execute(query)

    return result


@check_db_connected
async def list_settings() -> Any:
    query = select(Settings)
    db = DB.get()
    async with db.transaction():
        result = await db.fetch_all(query)

    return result


@check_db_connected
async def get_setting(key: str) -> Any:
    query = select(Settings).where(Settings.c.key == key)
    db = DB.get()
    async with db.transaction():
        result = await db.fetch_one(query)

    return result


@check_db_connected
async def update_setting(key: str, value: Any) -> Any:
    get_query = (
        select(Settings.c.key, Settings.c.value).where(Settings.c.key == key).with_for_update()
    )
    db = DB.get()
    async with db.transaction():
        is_exist = await db.fetch_one(get_query)
        stmt: Union[Insert, Update]
        if is_exist is None:
            stmt = insert(Settings).values(key=key, value=value)
        else:
            stmt = update(Settings).where(Settings.c.key == key).values(value=value)
        await db.execute(stmt)
        result = await db.fetch_one(get_query)

    return result


@check_db_connected
async def delete_setting(key: str) -> Any:
    query = delete(Settings).where(Settings.c.key == key)
    db = DB.get()
    async with db.transaction():
        result = await db.execute(query)

    return result


@check_db_connected
async def get_permissions_for_role(role_name: str) -> Any:
    query = select(RbacRolePermissions).where(
        RbacRolePermissions.c.role_name == role_name
    )
    db = DB.get()
    async with db.transaction():
        result = await db.fetch_all(query)

    return result


@check_db_connected
async def get_all_custom_permissions() -> Any:
    query = select(RbacRolePermissions)
    db = DB.get()
    async with db.transaction():
        result = await db.fetch_all(query)

    return result


@check_db_connected
async def get_custom_role_names() -> Any:
    query = select(RbacRolePermissions.c.role_name).distinct()
    db = DB.get()
    async with db.transaction():
        result = await db.fetch_all(query)

    return result


@check_db_connected
async def set_role_permission(
    role_name: str,
    service: str,
    action: str,
    allowed: bool,
) -> Any:
    db = DB.get()
    check = select(RbacRolePermissions).where(
        (RbacRolePermissions.c.role_name == role_name)
        & (RbacRolePermissions.c.service == service)
        & (RbacRolePermissions.c.action == action)
    )
    async with db.transaction():
        existing = await db.fetch_one(check)
        stmt: Union[Insert, Update]
        if existing:
            stmt = (
                update(RbacRolePermissions)
                .where(
                    (RbacRolePermissions.c.role_name == role_name)
                    & (RbacRolePermissions.c.service == service)
                    & (RbacRolePermissions.c.action == action)
                )
                .values(allowed=int(allowed))
            )
        else:
            stmt = insert(RbacRolePermissions).values(
                role_name=role_name,
                service=service,
                action=action,
                allowed=int(allowed),
            )
        await db.execute(stmt)


@check_db_connected
async def delete_role_permissions(role_name: str) -> Any:
    query = delete(RbacRolePermissions).where(
        RbacRolePermissions.c.role_name == role_name
    )
    db = DB.get()
    async with db.transaction():
        await db.execute(query)


@check_db_connected
async def batch_set_role_permissions(
    role_name: str,
    permissions: list,
) -> Any:
    db = DB.get()
    async with db.transaction():
        del_query = delete(RbacRolePermissions).where(
            RbacRolePermissions.c.role_name == role_name
        )
        await db.execute(del_query)
        for perm in permissions:
            ins_query = insert(RbacRolePermissions).values(
                role_name=role_name,
                service=perm["service"],
                action=perm["action"],
                allowed=int(perm["allowed"]),
            )
            await db.execute(ins_query)


# ---------------------------------------------------------------------------
# License management DB functions
# ---------------------------------------------------------------------------


@check_db_connected
async def get_active_license(cluster_id: str) -> Any:
    query = (
        select(SkylineLicenses)
        .where(SkylineLicenses.c.cluster_id == cluster_id)
        .where(SkylineLicenses.c.is_active == 1)
    )
    db = DB.get()
    async with db.transaction():
        result = await db.fetch_one(query)
    return result


@check_db_connected
async def insert_license(
    serial: str,
    cluster_id: str,
    license_type: str,
    valid_from: Any,
    valid_until: Any,
    max_sockets: int = 0,
    max_nodes: int = 0,
    vendor: str = "Xloud Technologies",
    applied_by: str = "system",
    applied_from: str = "0.0.0.0",
    token_payload: str = None,
    token_signature: str = None,
    token_full_json: str = None,
) -> Any:
    from datetime import datetime

    now = datetime.utcnow()
    query = insert(SkylineLicenses).values(
        serial=serial,
        cluster_id=cluster_id,
        license_type=license_type,
        valid_from=valid_from,
        valid_until=valid_until,
        max_sockets=max_sockets,
        max_nodes=max_nodes,
        vendor=vendor,
        is_active=1,
        applied_at=now,
        applied_by=applied_by,
        applied_from=applied_from,
        token_payload=token_payload,
        token_signature=token_signature,
        token_full_json=token_full_json,
        created_at=now,
        updated_at=now,
    )
    db = DB.get()
    async with db.transaction():
        result = await db.execute(query)
    return result


@check_db_connected
async def update_license_status(serial: str, is_active: int) -> Any:
    from datetime import datetime

    query = (
        update(SkylineLicenses)
        .where(SkylineLicenses.c.serial == serial)
        .values(is_active=is_active, updated_at=datetime.utcnow())
    )
    db = DB.get()
    async with db.transaction():
        await db.execute(query)


@check_db_connected
async def insert_license_event(
    event_type: str,
    event_message: str,
    event_details: Any = None,
    license_id: int = None,
    user: str = None,
    ip_address: str = None,
    hostname: str = None,
) -> Any:
    import json as _json
    from datetime import datetime

    details = event_details
    if details and not isinstance(details, str):
        details = _json.dumps(details)

    query = insert(SkylineLicenseEvents).values(
        license_id=license_id,
        event_type=event_type,
        event_message=event_message,
        event_details=details,
        user=user,
        ip_address=ip_address,
        hostname=hostname,
        created_at=datetime.utcnow(),
    )
    db = DB.get()
    async with db.transaction():
        result = await db.execute(query)
    return result


@check_db_connected
async def get_system_state(cluster_id: str) -> Any:
    query = select(SkylineSystemState).where(
        SkylineSystemState.c.cluster_id == cluster_id
    )
    db = DB.get()
    async with db.transaction():
        result = await db.fetch_one(query)
    return result


@check_db_connected
async def upsert_system_state(
    cluster_id: str,
    grace_period_start: Any = None,
    grace_period_days: int = 15,
    grace_period_reason: str = None,
    hardware_fingerprint: str = None,
    status: str = "grace_period",
    status_message: str = None,
) -> Any:
    from datetime import datetime

    now = datetime.utcnow()
    db = DB.get()
    async with db.transaction():
        # Check if row exists (with lock)
        existing = await db.fetch_one(
            select(SkylineSystemState)
            .where(SkylineSystemState.c.cluster_id == cluster_id)
            .with_for_update()
        )
        if existing is None:
            # Insert new record with grace period locked
            stmt = insert(SkylineSystemState).values(
                cluster_id=cluster_id,
                grace_period_start=grace_period_start,
                grace_period_locked=1,
                grace_period_days=grace_period_days,
                grace_period_reason=grace_period_reason,
                hardware_fingerprint=hardware_fingerprint,
                status=status,
                status_message=status_message,
                last_checked=now,
                created_at=now,
                updated_at=now,
            )
            await db.execute(stmt)
        else:
            # Only update grace period fields if NOT locked
            is_locked = getattr(existing, "grace_period_locked", 0)
            values = {
                "last_checked": now,
                "updated_at": now,
                "status": status,
                "status_message": status_message,
            }
            if not is_locked:
                values["grace_period_start"] = grace_period_start
                values["grace_period_locked"] = 1
                values["grace_period_days"] = grace_period_days
                values["grace_period_reason"] = grace_period_reason
            if hardware_fingerprint:
                values["hardware_fingerprint"] = hardware_fingerprint

            stmt = (
                update(SkylineSystemState)
                .where(SkylineSystemState.c.cluster_id == cluster_id)
                .values(**values)
            )
            await db.execute(stmt)


@check_db_connected
async def update_system_state_checked(cluster_id: str) -> Any:
    from datetime import datetime

    query = (
        update(SkylineSystemState)
        .where(SkylineSystemState.c.cluster_id == cluster_id)
        .values(last_checked=datetime.utcnow(), updated_at=datetime.utcnow())
    )
    db = DB.get()
    async with db.transaction():
        await db.execute(query)


# ---------------------------------------------------------------------------
# User profile image DB functions
# ---------------------------------------------------------------------------


@check_db_connected
async def get_user_profile_image(user_id: str) -> Any:
    query = select(UserProfiles).where(UserProfiles.c.user_id == user_id)
    db = DB.get()
    async with db.transaction():
        result = await db.fetch_one(query)
    return result


@check_db_connected
async def upsert_user_profile_image(
    user_id: str,
    username: str,
    profile_image_base64: str,
    image_format: str = "png",
    image_size_bytes: int = 0,
) -> Any:
    from datetime import datetime

    now = datetime.utcnow()
    db = DB.get()
    async with db.transaction():
        existing = await db.fetch_one(
            select(UserProfiles)
            .where(UserProfiles.c.user_id == user_id)
            .with_for_update()
        )
        stmt: Union[Insert, Update]
        if existing is None:
            stmt = insert(UserProfiles).values(
                user_id=user_id,
                username=username,
                profile_image_base64=profile_image_base64,
                image_format=image_format,
                image_size_bytes=image_size_bytes,
                created_at=now,
                updated_at=now,
            )
        else:
            stmt = (
                update(UserProfiles)
                .where(UserProfiles.c.user_id == user_id)
                .values(
                    profile_image_base64=profile_image_base64,
                    image_format=image_format,
                    image_size_bytes=image_size_bytes,
                    updated_at=now,
                )
            )
        await db.execute(stmt)


@check_db_connected
async def delete_user_profile_image(user_id: str) -> int:
    db = DB.get()
    async with db.transaction():
        stmt = delete(UserProfiles).where(UserProfiles.c.user_id == user_id)
        result = await db.execute(stmt)
    return result if isinstance(result, int) else 0


# Columns that can be patched via PATCH /profile/me
PROFILE_PATCHABLE_COLUMNS = frozenset({
    "first_name",
    "last_name",
    "phone",
    "job_title",
    "department",
    "theme_color",
    "default_project_id",
})


@check_db_connected
async def create_user_session(
    user_id: str,
    username: str,
    ip_address: str,
    user_agent: str,
    jti: str,
    expires_at: Any = None,
) -> Any:
    from datetime import datetime

    now = datetime.utcnow()
    db = DB.get()
    async with db.transaction():
        stmt = insert(UserSessions).values(
            user_id=user_id,
            username=username,
            ip_address=ip_address,
            user_agent=(user_agent or "")[:512],
            jti=jti,
            created_at=now,
            last_seen_at=now,
            expires_at=expires_at,
            revoked=0,
        )
        await db.execute(stmt)


@check_db_connected
async def list_user_sessions(user_id: str, limit: int = 50) -> Any:
    query = (
        select(UserSessions)
        .where(UserSessions.c.user_id == user_id)
        .order_by(UserSessions.c.last_seen_at.desc())
        .limit(limit)
    )
    db = DB.get()
    async with db.transaction():
        return await db.fetch_all(query)


@check_db_connected
async def touch_user_session(jti: str) -> None:
    from datetime import datetime

    now = datetime.utcnow()
    db = DB.get()
    async with db.transaction():
        stmt = (
            update(UserSessions)
            .where(UserSessions.c.jti == jti)
            .values(last_seen_at=now)
        )
        await db.execute(stmt)


@check_db_connected
async def revoke_user_session(user_id: str, session_id: int) -> int:
    db = DB.get()
    async with db.transaction():
        stmt = (
            update(UserSessions)
            .where(UserSessions.c.id == session_id)
            .where(UserSessions.c.user_id == user_id)
            .values(revoked=1)
        )
        result = await db.execute(stmt)
    return result if isinstance(result, int) else 0


@check_db_connected
async def upsert_user_profile_fields(
    user_id: str,
    username: str,
    fields: dict,
) -> Any:
    from datetime import datetime

    clean = {k: v for k, v in fields.items() if k in PROFILE_PATCHABLE_COLUMNS}
    now = datetime.utcnow()
    db = DB.get()
    async with db.transaction():
        existing = await db.fetch_one(
            select(UserProfiles)
            .where(UserProfiles.c.user_id == user_id)
            .with_for_update()
        )
        stmt: Union[Insert, Update]
        if existing is None:
            stmt = insert(UserProfiles).values(
                user_id=user_id,
                username=username,
                created_at=now,
                updated_at=now,
                **clean,
            )
        else:
            stmt = (
                update(UserProfiles)
                .where(UserProfiles.c.user_id == user_id)
                .values(updated_at=now, **clean)
            )
        await db.execute(stmt)


# =========================================================================
# DNS IPAM Connections
# =========================================================================


@check_db_connected
async def list_dns_ipam_connections() -> Any:
    query = select(DnsIpamConnections).order_by(DnsIpamConnections.c.created_at.desc())
    db = DB.get()
    async with db.transaction():
        return await db.fetch_all(query)


@check_db_connected
async def get_dns_ipam_connection(connection_id: str) -> Any:
    query = select(DnsIpamConnections).where(DnsIpamConnections.c.id == connection_id)
    db = DB.get()
    async with db.transaction():
        return await db.fetch_one(query)


@check_db_connected
async def create_dns_ipam_connection(values: dict) -> Any:
    db = DB.get()
    async with db.transaction():
        await db.execute(insert(DnsIpamConnections), values)
        return await db.fetch_one(
            select(DnsIpamConnections).where(DnsIpamConnections.c.id == values["id"])
        )


@check_db_connected
async def update_dns_ipam_connection(connection_id: str, values: dict) -> Any:
    stmt = (
        update(DnsIpamConnections)
        .where(DnsIpamConnections.c.id == connection_id)
        .values(**values)
    )
    db = DB.get()
    async with db.transaction():
        await db.execute(stmt)
        return await db.fetch_one(
            select(DnsIpamConnections).where(DnsIpamConnections.c.id == connection_id)
        )


@check_db_connected
async def delete_dns_ipam_connection(connection_id: str) -> Any:
    query = delete(DnsIpamConnections).where(DnsIpamConnections.c.id == connection_id)
    db = DB.get()
    async with db.transaction():
        return await db.execute(query)


# =========================================================================
# DNS IPAM Pools
# =========================================================================


@check_db_connected
async def list_dns_ipam_pools(connection_id: str = None) -> Any:
    query = select(DnsIpamPools)
    if connection_id:
        query = query.where(DnsIpamPools.c.connection_id == connection_id)
    query = query.order_by(DnsIpamPools.c.created_at.desc())
    db = DB.get()
    async with db.transaction():
        return await db.fetch_all(query)


@check_db_connected
async def create_dns_ipam_pool(values: dict) -> Any:
    db = DB.get()
    async with db.transaction():
        await db.execute(insert(DnsIpamPools), values)
        return await db.fetch_one(
            select(DnsIpamPools).where(DnsIpamPools.c.id == values["id"])
        )


@check_db_connected
async def delete_dns_ipam_pool(pool_id: str) -> Any:
    query = delete(DnsIpamPools).where(DnsIpamPools.c.id == pool_id)
    db = DB.get()
    async with db.transaction():
        return await db.execute(query)
