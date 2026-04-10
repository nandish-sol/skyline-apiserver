from __future__ import annotations

import base64
import binascii
import re
from typing import Optional

from fastapi import APIRouter, Body, Depends, HTTPException, status
from pydantic import BaseModel, Field

from skyline_apiserver import schemas
from skyline_apiserver.api import deps
from skyline_apiserver.db import api as db_api


router = APIRouter()

ALLOWED_FORMATS = {"png", "jpg", "jpeg", "webp"}
MAX_IMAGE_BYTES = 200 * 1024  # 200KB decoded

THEME_COLOR_RE = re.compile(r"^#[0-9a-fA-F]{6}$")


class ProfileImageResponse(BaseModel):
    user_id: str
    username: str
    profile_image_base64: Optional[str] = None
    image_format: str = "png"


class ProfileImageUpload(BaseModel):
    profile_image_base64: str = Field(..., description="Base64-encoded image (data URI prefix allowed)")
    image_format: str = Field("png", description="Image format: png, jpg, jpeg, or webp")


class ProfileMeResponse(BaseModel):
    user_id: str
    username: str
    has_profile_image: bool = False
    image_format: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    phone: Optional[str] = None
    job_title: Optional[str] = None
    department: Optional[str] = None
    theme_color: Optional[str] = None
    default_project_id: Optional[str] = None


class ProfileMePatch(BaseModel):
    first_name: Optional[str] = Field(None, max_length=64)
    last_name: Optional[str] = Field(None, max_length=64)
    phone: Optional[str] = Field(None, max_length=32)
    job_title: Optional[str] = Field(None, max_length=128)
    department: Optional[str] = Field(None, max_length=128)
    theme_color: Optional[str] = Field(None, max_length=16)
    default_project_id: Optional[str] = Field(None, max_length=64)


def _strip_data_uri_prefix(b64: str) -> str:
    if b64.startswith("data:"):
        comma = b64.find(",")
        if comma != -1:
            return b64[comma + 1:]
    return b64


def _validate_image(b64: str, fmt: str) -> int:
    fmt_lower = (fmt or "").lower().strip()
    if fmt_lower not in ALLOWED_FORMATS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid image format. Allowed: {sorted(ALLOWED_FORMATS)}",
        )
    try:
        raw = base64.b64decode(b64, validate=True)
    except (binascii.Error, ValueError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid base64 payload.",
        )
    size = len(raw)
    if size == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Empty image payload.",
        )
    if size > MAX_IMAGE_BYTES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Image too large ({size} bytes). Max {MAX_IMAGE_BYTES} bytes.",
        )
    if fmt_lower == "png" and not raw.startswith(b"\x89PNG\r\n\x1a\n"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Payload does not look like a PNG image.",
        )
    if fmt_lower in {"jpg", "jpeg"} and not raw.startswith(b"\xff\xd8\xff"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Payload does not look like a JPEG image.",
        )
    if fmt_lower == "webp" and not (raw[:4] == b"RIFF" and raw[8:12] == b"WEBP"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Payload does not look like a WebP image.",
        )
    return size


@router.get(
    "/profile/image",
    description="Get the current user's profile image.",
    responses={
        200: {"model": ProfileImageResponse},
        401: {"model": schemas.UnauthorizedMessage},
    },
    response_model=ProfileImageResponse,
    status_code=status.HTTP_200_OK,
)
async def get_profile_image(
    profile: schemas.Profile = Depends(deps.get_profile_update_jwt),
) -> ProfileImageResponse:
    user_id = profile.user.id
    username = profile.user.name
    # Try lookup by Keystone user ID first, then fall back to username
    row = await db_api.get_user_profile_image(user_id)
    if row is None:
        row = await db_api.get_user_profile_image(username)
    if row is None:
        return ProfileImageResponse(user_id=user_id, username=username)
    return ProfileImageResponse(
        user_id=user_id,
        username=username,
        profile_image_base64=row.profile_image_base64,
        image_format=row.image_format or "png",
    )


@router.put(
    "/profile/image",
    description="Upload or update the current user's profile image.",
    responses={
        200: {"model": ProfileImageResponse},
        401: {"model": schemas.UnauthorizedMessage},
    },
    response_model=ProfileImageResponse,
    status_code=status.HTTP_200_OK,
)
async def upload_profile_image(
    payload: ProfileImageUpload = Body(...),
    profile: schemas.Profile = Depends(deps.get_profile_update_jwt),
) -> ProfileImageResponse:
    user_id = profile.user.id
    username = profile.user.name

    b64 = _strip_data_uri_prefix(payload.profile_image_base64 or "")
    fmt = (payload.image_format or "png").lower().strip()
    if fmt == "jpg":
        fmt = "jpeg"
    size_bytes = _validate_image(b64, fmt)

    await db_api.upsert_user_profile_image(
        user_id=user_id,
        username=username,
        profile_image_base64=b64,
        image_format=fmt,
        image_size_bytes=size_bytes,
    )

    return ProfileImageResponse(
        user_id=user_id,
        username=username,
        profile_image_base64=b64,
        image_format=fmt,
    )


@router.delete(
    "/profile/image",
    description="Remove the current user's profile image.",
    responses={
        200: {"model": ProfileImageResponse},
        401: {"model": schemas.UnauthorizedMessage},
    },
    response_model=ProfileImageResponse,
    status_code=status.HTTP_200_OK,
)
async def delete_profile_image(
    profile: schemas.Profile = Depends(deps.get_profile_update_jwt),
) -> ProfileImageResponse:
    user_id = profile.user.id
    username = profile.user.name
    await db_api.delete_user_profile_image(user_id)
    # Also drop any legacy row keyed by username (migration from pre-UUID seeds)
    if username and username != user_id:
        await db_api.delete_user_profile_image(username)
    return ProfileImageResponse(user_id=user_id, username=username)


def _row_to_profile_me(row, user_id: str, username: str) -> ProfileMeResponse:
    if row is None:
        return ProfileMeResponse(user_id=user_id, username=username, has_profile_image=False)
    return ProfileMeResponse(
        user_id=user_id,
        username=username,
        has_profile_image=bool(row["profile_image_base64"]),
        image_format=row["image_format"],
        first_name=row["first_name"],
        last_name=row["last_name"],
        phone=row["phone"],
        job_title=row["job_title"],
        department=row["department"],
        theme_color=row["theme_color"],
        default_project_id=row["default_project_id"],
    )


@router.get(
    "/profile/me",
    description="Get the current user's Xloud-managed profile fields.",
    responses={
        200: {"model": ProfileMeResponse},
        401: {"model": schemas.UnauthorizedMessage},
    },
    response_model=ProfileMeResponse,
    status_code=status.HTTP_200_OK,
)
async def get_profile_me(
    profile: schemas.Profile = Depends(deps.get_profile_update_jwt),
) -> ProfileMeResponse:
    user_id = profile.user.id
    username = profile.user.name
    row = await db_api.get_user_profile_image(user_id)
    if row is None:
        row = await db_api.get_user_profile_image(username)
    return _row_to_profile_me(row, user_id, username)


@router.patch(
    "/profile/me",
    description="Update one or more Xloud-managed profile fields for the current user.",
    responses={
        200: {"model": ProfileMeResponse},
        400: {"description": "Validation error"},
        401: {"model": schemas.UnauthorizedMessage},
    },
    response_model=ProfileMeResponse,
    status_code=status.HTTP_200_OK,
)
async def patch_profile_me(
    payload: ProfileMePatch = Body(...),
    profile: schemas.Profile = Depends(deps.get_profile_update_jwt),
) -> ProfileMeResponse:
    user_id = profile.user.id
    username = profile.user.name

    data = payload.dict(exclude_unset=True)
    if "theme_color" in data and data["theme_color"] is not None:
        if not THEME_COLOR_RE.match(data["theme_color"]):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="theme_color must be a 6-digit hex like '#197560'.",
            )

    # Normalize empty strings to None so clients can clear fields explicitly.
    for k, v in list(data.items()):
        if isinstance(v, str) and v.strip() == "":
            data[k] = None

    await db_api.upsert_user_profile_fields(user_id, username, data)
    row = await db_api.get_user_profile_image(user_id)
    return _row_to_profile_me(row, user_id, username)
