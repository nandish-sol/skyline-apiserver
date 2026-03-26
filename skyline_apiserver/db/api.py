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
from .models import RbacRolePermissions, RevokedToken, Settings


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
