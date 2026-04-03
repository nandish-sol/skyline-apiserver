# Copyright 2025-2026 Xloud Technologies Pvt Ltd
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

"""
Skyline License Compliance Module — Encrypted License Management

Ported from Horizon's compliance_new.py for async FastAPI context.

Architecture:
- License: /var/lib/kolla/config_files/cluster-license.xlic (encrypted binary)
- Private Key: /var/lib/kolla/config_files/customer-private.key
- Public Key: /var/lib/kolla/config_files/xloud-public.key
- Cache: In-memory (asyncio.Lock, configurable TTL)

Validation Flow:
1. Decrypt license file with customer private key (RSA-4096 + AES-256-GCM)
2. Verify RSA signature with Xloud public key
3. Match product_uuid (SMBIOS) against license hardware binding
4. Check expiry date and calculate days remaining
5. Cache result
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import socket
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

LOG = logging.getLogger(__name__)


class ComplianceValidator:
    """Async file-based license validation with RSA signature verification."""

    # In-memory cache
    _cache_lock = asyncio.Lock()
    _cached_state: dict | None = None
    _cache_timestamp: float = 0

    # Grace period tracking file
    LICENSE_INFO_FILE = "/etc/xavs/skyline/license-info.json"

    # Grace period constants
    GRACE_PERIOD_DAYS_NO_FILE = 15
    GRACE_PERIOD_DAYS_INVALID = 7
    MAX_TOTAL_GRACE_DAYS = 30

    # -----------------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------------

    @classmethod
    async def get_compliance_state(cls) -> dict:
        """Main entry point — returns cached or freshly validated state."""
        cache_ttl = cls._get_cache_ttl()
        now = time.time()

        async with cls._cache_lock:
            if cls._cached_state and (now - cls._cache_timestamp) < cache_ttl:
                return cls._cached_state

        LOG.info("License cache miss — checking status...")

        # Try encrypted license file
        license_path = cls._get_license_path()
        try:
            file_exists = license_path.exists()
        except (OSError, PermissionError) as exc:
            LOG.warning("Cannot check license file: %s", exc)
            file_exists = False

        if file_exists:
            LOG.info("Encrypted license found, decrypting...")
            license_data = await cls._decrypt_license()
            if license_data:
                state = cls._validate_encrypted_license(license_data)
            else:
                LOG.error("Decryption FAILED — entering grace period")
                state = await cls._grace_period_state(
                    cls.GRACE_PERIOD_DAYS_NO_FILE, "no_file"
                )
        else:
            LOG.error("No license file at %s — entering grace period", license_path)
            state = await cls._grace_period_state(
                cls.GRACE_PERIOD_DAYS_NO_FILE, "no_file"
            )

        # Cache result
        async with cls._cache_lock:
            cls._cached_state = state
            cls._cache_timestamp = time.time()

        return state

    @classmethod
    async def invalidate_cache(cls) -> None:
        """Force cache invalidation (e.g. after license file change)."""
        async with cls._cache_lock:
            cls._cached_state = None
            cls._cache_timestamp = 0

    # -----------------------------------------------------------------------
    # Config helpers (lazy import to avoid circular imports at module load)
    # -----------------------------------------------------------------------

    @classmethod
    def _get_license_path(cls) -> Path:
        try:
            from skyline_apiserver.config import CONF

            return Path(CONF.default.license_file_path)
        except Exception:
            return Path("/var/lib/kolla/config_files/cluster-license.xlic")

    @classmethod
    def _get_private_key_path(cls) -> Path:
        try:
            from skyline_apiserver.config import CONF

            return Path(CONF.default.license_private_key_path)
        except Exception:
            return Path("/var/lib/kolla/config_files/customer-private.key")

    @classmethod
    def _get_public_key_path(cls) -> Path:
        try:
            from skyline_apiserver.config import CONF

            return Path(CONF.default.license_public_key_path)
        except Exception:
            return Path("/var/lib/kolla/config_files/xloud-public.key")

    @classmethod
    def _get_cache_ttl(cls) -> int:
        try:
            from skyline_apiserver.config import CONF

            return CONF.default.license_cache_ttl
        except Exception:
            return 180

    # -----------------------------------------------------------------------
    # Hardware / container helpers
    # -----------------------------------------------------------------------

    @classmethod
    def _get_container_identifier(cls) -> str:
        try:
            return socket.gethostname()
        except Exception:
            return "UNKNOWN"

    @classmethod
    def _get_hardware_fingerprint(cls) -> dict:
        fingerprint: dict = {"product_uuid": None, "hostname": None}

        uuid_path = "/sys/class/dmi/id/product_uuid"
        uuid_cache = "/tmp/.hardware_uuid"

        # Method 1: Direct read (works if running as root or permissions allow)
        try:
            if os.path.exists(uuid_path):
                with open(uuid_path) as fh:
                    fingerprint["product_uuid"] = fh.read().strip().upper()
        except PermissionError:
            pass
        except Exception as exc:
            LOG.warning("Could not read product_uuid directly: %s", exc)

        # Method 2: Read from cached UUID files (written by Ansible/Kolla)
        if not fingerprint["product_uuid"]:
            for cache_path in [
                "/tmp/.hardware_uuid",
                "/etc/xavs/skyline/hardware_uuid",
                "/etc/xavs/horizon/hardware_uuid",
            ]:
                try:
                    if os.path.exists(cache_path):
                        with open(cache_path) as fh:
                            val = fh.read().strip().upper()
                            if val and len(val) >= 32:
                                fingerprint["product_uuid"] = val
                                break
                except Exception:
                    continue

        # Method 3: Use subprocess to read with elevated privileges
        if not fingerprint["product_uuid"]:
            import subprocess
            for cmd in [
                ["cat", uuid_path],
                ["dmidecode", "-s", "system-uuid"],
            ]:
                try:
                    result = subprocess.run(
                        cmd, capture_output=True, text=True, timeout=5
                    )
                    if result.returncode == 0 and result.stdout.strip():
                        fingerprint["product_uuid"] = (
                            result.stdout.strip().upper()
                        )
                        # Cache for future reads
                        try:
                            with open(uuid_cache, "w") as fh:
                                fh.write(fingerprint["product_uuid"])
                        except Exception:
                            pass
                        break
                except Exception:
                    continue

        if not fingerprint["product_uuid"]:
            LOG.error(
                "Cannot read hardware UUID from any source. "
                "Ensure /sys/class/dmi/id/product_uuid is readable "
                "or run: cat /sys/class/dmi/id/product_uuid > /tmp/.hardware_uuid"
            )

        try:
            fingerprint["hostname"] = socket.gethostname()
        except Exception:
            fingerprint["hostname"] = "unknown"
        return fingerprint

    @classmethod
    def _get_container_creation_time(cls) -> datetime | None:
        try:
            if os.path.exists("/proc/1/stat"):
                with open("/proc/1/stat") as fh:
                    stat = fh.read().split(")")[-1].split()
                    start_ticks = int(stat[19])
                with open("/proc/stat") as fs:
                    for line in fs:
                        if line.startswith("btime"):
                            boot_time = int(line.split()[1])
                            ticks = os.sysconf(os.sysconf_names["SC_CLK_TCK"])
                            return datetime.fromtimestamp(
                                boot_time + (start_ticks / ticks)
                            )
        except Exception as exc:
            LOG.warning("Could not read container creation time: %s", exc)
        return None

    # -----------------------------------------------------------------------
    # Integrity helpers
    # -----------------------------------------------------------------------

    @classmethod
    def _calculate_integrity_hash(
        cls, grace_start: datetime, container_id: str, days: int
    ) -> str:
        data = f"{grace_start.isoformat()}:{container_id}:{days}:xloud-skyline"
        return hashlib.sha256(data.encode()).hexdigest()

    @classmethod
    def _verify_file_integrity(cls, info: dict, container_id: str) -> bool:
        if "integrity_hash" not in info:
            return True  # old format
        try:
            grace_start = datetime.fromisoformat(info["grace_period_start"])
            days = info.get("grace_period_days", cls.GRACE_PERIOD_DAYS_NO_FILE)
            expected = cls._calculate_integrity_hash(grace_start, container_id, days)
            if info["integrity_hash"] != expected:
                LOG.error("TAMPERING DETECTED: integrity hash mismatch")
                return False
            return True
        except Exception as exc:
            LOG.error("Integrity verification error: %s", exc)
            return False

    # -----------------------------------------------------------------------
    # DB helpers (async)
    # -----------------------------------------------------------------------

    @classmethod
    async def _log_license_event(
        cls, event_type: str, message: str, details: dict | None = None
    ) -> None:
        try:
            from skyline_apiserver.db import api as db_api

            await db_api.insert_license_event(
                event_type=event_type,
                event_message=message,
                event_details=details,
                hostname=socket.gethostname(),
            )
        except Exception as exc:
            LOG.warning("Could not log license event: %s", exc)

    @classmethod
    async def _get_grace_period_from_db(cls) -> tuple:
        """Returns (grace_start, is_locked, days) or (None, False, None)."""
        try:
            from skyline_apiserver.db import api as db_api

            cluster_id = socket.gethostname()
            row = await db_api.get_system_state(cluster_id)
            if row:
                gs = getattr(row, "grace_period_start", None)
                if gs:
                    if isinstance(gs, str):
                        gs = datetime.fromisoformat(gs)
                    locked = bool(getattr(row, "grace_period_locked", 0))
                    days = getattr(row, "grace_period_days", None) or cls.GRACE_PERIOD_DAYS_NO_FILE
                    last_checked = getattr(row, "last_checked", None)
                    if last_checked:
                        if isinstance(last_checked, str):
                            last_checked = datetime.fromisoformat(last_checked)
                        if datetime.utcnow() < last_checked - timedelta(hours=1):
                            LOG.error("TIME MANIPULATION DETECTED")
                            await cls._log_license_event(
                                "time_jump_detected",
                                "Clock moved backwards",
                                {"last_check": str(last_checked), "current": str(datetime.utcnow())},
                            )
                    return (gs, locked, days)
        except Exception as exc:
            LOG.warning("Could not read grace period from DB: %s", exc)
        return (None, False, None)

    @classmethod
    async def _get_first_deployment_time(cls) -> datetime | None:
        try:
            from skyline_apiserver.db import api as db_api

            cluster_id = socket.gethostname()
            row = await db_api.get_system_state(cluster_id)
            if row:
                created = getattr(row, "created_at", None)
                if created:
                    return datetime.fromisoformat(created) if isinstance(created, str) else created
            # First deployment — insert record
            container_time = cls._get_container_creation_time()
            first_deploy = container_time or datetime.utcnow()
            await db_api.upsert_system_state(
                cluster_id=cluster_id,
                hardware_fingerprint=cls._get_container_identifier(),
                status="grace_period",
            )
            await cls._log_license_event(
                "first_deployment_recorded",
                "System first deployment recorded",
                {"first_deployment": str(first_deploy)},
            )
            return first_deploy
        except Exception as exc:
            LOG.warning("Could not get first deployment time: %s", exc)
            return cls._get_container_creation_time()

    @classmethod
    async def _save_grace_period_to_db(
        cls, grace_start: datetime, days: int, reason: str
    ) -> bool:
        try:
            from skyline_apiserver.db import api as db_api

            cluster_id = socket.gethostname()
            await db_api.upsert_system_state(
                cluster_id=cluster_id,
                grace_period_start=grace_start,
                grace_period_days=days,
                grace_period_reason=reason,
                hardware_fingerprint=cls._get_container_identifier(),
                status="grace_period",
            )
            return True
        except Exception as exc:
            LOG.error("Could not save grace period to DB: %s", exc)
            return False

    # -----------------------------------------------------------------------
    # Grace period logic
    # -----------------------------------------------------------------------

    @classmethod
    async def _grace_period_state(cls, days: int = 7, reason: str = "invalid") -> dict:
        now = datetime.utcnow()
        container_id = cls._get_container_identifier()
        grace_start: datetime | None = None
        is_locked = False
        file_deleted = False
        file_tampered = False

        # LAYER 1: Database (primary)
        db_start, db_locked, db_days = await cls._get_grace_period_from_db()
        if db_start:
            grace_start = db_start
            is_locked = db_locked
            if db_days:
                days = db_days

        # LAYER 2: File with integrity check
        file_start: datetime | None = None
        if os.path.exists(cls.LICENSE_INFO_FILE):
            try:
                with open(cls.LICENSE_INFO_FILE) as fh:
                    info = json.load(fh)
                if cls._verify_file_integrity(info, container_id):
                    file_start = datetime.fromisoformat(info.get("grace_period_start"))
                else:
                    file_tampered = True
                    await cls._log_license_event(
                        "tampering_detected",
                        "License info file failed integrity check",
                    )
            except Exception:
                pass
        elif db_start:
            file_deleted = True
            await cls._log_license_event(
                "file_deleted_detected", "License info file was deleted"
            )

        # Cross-validate
        if db_start and file_start:
            diff = abs((db_start - file_start).total_seconds())
            if diff > 60:
                LOG.error("DB/file timestamps differ by %ss — using DB", diff)
                grace_start = db_start

        # LAYER 3: Container creation time validation
        # Skip if DB record is locked — DB is trusted, container restarts are normal
        container_start = cls._get_container_creation_time()
        if container_start and grace_start and not is_locked:
            if grace_start < container_start - timedelta(hours=1):
                LOG.error("Grace period predates container creation")
                await cls._log_license_event(
                    "tampering_detected",
                    "Grace period predates container creation",
                )
                grace_start = container_start

        # No grace period found — create new
        if not grace_start:
            first_deployment = await cls._get_first_deployment_time()
            if first_deployment:
                max_end = first_deployment + timedelta(days=cls.MAX_TOTAL_GRACE_DAYS)
                if now > max_end:
                    LOG.error("MAX_TOTAL_GRACE_DAYS exceeded")
                    await cls._log_license_event(
                        "max_grace_exceeded",
                        "Maximum grace period from first deployment exceeded",
                        {"first_deployment": str(first_deployment), "days_since": (now - first_deployment).days},
                    )
                    return {
                        "enabled": False,
                        "serial": "TRIAL-PERIOD",
                        "cluster_id": container_id,
                        "license_type": "grace_period",
                        "days_remaining": 0,
                        "days_elapsed": (now - first_deployment).days,
                        "start_date": first_deployment.strftime("%Y-%m-%d"),
                        "end_date": max_end.strftime("%Y-%m-%d"),
                        "expired": True,
                        "warning": True,
                        "status": "expired",
                        "message": f"Maximum grace period ({cls.MAX_TOTAL_GRACE_DAYS} days) exceeded.",
                        "max_sockets": 0,
                        "vendor": "N/A",
                    }

            grace_start = container_start if container_start else now
            await cls._log_license_event(
                "grace_period_started",
                f"Grace period started: {days} days, reason: {reason}",
                {"start": str(grace_start), "days": days, "reason": reason},
            )
            await cls._save_grace_period_to_db(grace_start, days, reason)

            # Save file backup
            try:
                os.makedirs(os.path.dirname(cls.LICENSE_INFO_FILE), exist_ok=True)
                integrity_hash = cls._calculate_integrity_hash(grace_start, container_id, days)
                info = {
                    "grace_period_start": grace_start.isoformat(),
                    "grace_period_reason": reason,
                    "grace_period_days": days,
                    "container_id": container_id,
                    "integrity_hash": integrity_hash,
                    "created_at": now.isoformat(),
                }
                with open(cls.LICENSE_INFO_FILE, "w") as fh:
                    json.dump(info, fh, indent=2)
            except Exception as exc:
                LOG.error("Failed to save grace period file: %s", exc)
        else:
            # Existing grace period — update last_checked
            try:
                from skyline_apiserver.db import api as db_api

                await db_api.update_system_state_checked(socket.gethostname())
            except Exception:
                pass

        # Calculate remaining days
        grace_end = grace_start + timedelta(days=days)
        days_elapsed = (now - grace_start).days
        days_remaining = max(0, (grace_end - now).days)

        if days_elapsed < 0:
            LOG.error("TIME MANIPULATION: days_elapsed=%d (negative)", days_elapsed)
            days_elapsed = abs(days_elapsed)
            days_remaining = max(0, days - days_elapsed)

        if reason == "no_file":
            message = f"No license file found. {days_remaining}-day trial period active."
            serial = "TRIAL-PERIOD"
        else:
            message = f"Invalid license file. System will be disabled in {days_remaining} days."
            serial = "GRACE-PERIOD"

        expired = days_remaining <= 0
        if expired:
            message = "Grace period expired. Please install a valid license."
            status = "expired"
        else:
            status = "grace_period"

        return {
            "enabled": not expired,
            "serial": serial,
            "cluster_id": socket.gethostname(),
            "license_type": "grace_period",
            "days_remaining": days_remaining,
            "days_elapsed": days_elapsed,
            "start_date": grace_start.strftime("%Y-%m-%d"),
            "end_date": grace_end.strftime("%Y-%m-%d"),
            "expired": expired,
            "warning": True,
            "status": status,
            "message": message,
            "max_sockets": 0,
            "vendor": "N/A",
        }

    # -----------------------------------------------------------------------
    # Decryption (CPU-bound — run in executor)
    # -----------------------------------------------------------------------

    @classmethod
    def _decrypt_sync(cls) -> dict | None:
        """Synchronous decryption — called via run_in_executor."""
        try:
            license_path = cls._get_license_path()
            private_key_path = cls._get_private_key_path()
            public_key_path = cls._get_public_key_path()

            if not license_path.exists():
                return None
            if not private_key_path.exists():
                LOG.error("Customer private key not found")
                return None

            encrypted_data = license_path.read_bytes()
            with open(private_key_path, "rb") as fh:
                private_key = serialization.load_pem_private_key(
                    fh.read(), password=None, backend=default_backend()
                )

            rsa_size = private_key.key_size // 8

            # Parse binary structure
            encrypted_aes_key = encrypted_data[:rsa_size]
            iv = encrypted_data[rsa_size : rsa_size + 12]
            tag = encrypted_data[rsa_size + 12 : rsa_size + 28]
            ciphertext = encrypted_data[rsa_size + 28 :]

            # Decrypt AES key with RSA-OAEP SHA-256
            aes_key = private_key.decrypt(
                encrypted_aes_key,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )

            # Decrypt ciphertext with AES-256-GCM
            cipher = Cipher(
                algorithms.AES(aes_key),
                modes.GCM(iv, tag),
                backend=default_backend(),
            )
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

            # Split: [license_json][rsa_signature]
            signature = decrypted_data[-rsa_size:]
            license_json_bytes = decrypted_data[:-rsa_size]

            # Verify signature with Xloud public key
            if public_key_path.exists():
                with open(public_key_path, "rb") as fh:
                    xloud_public_key = serialization.load_pem_public_key(
                        fh.read(), backend=default_backend()
                    )
                xloud_public_key.verify(
                    signature,
                    license_json_bytes,
                    asym_padding.PKCS1v15(),
                    hashes.SHA256(),
                )
                LOG.info("License signature verified")
            else:
                LOG.warning("Xloud public key not found — skipping signature check")

            license_data = json.loads(license_json_bytes.decode("utf-8"))
            LOG.info("License decrypted: %s", license_data.get("license_id", "UNKNOWN"))
            return license_data

        except Exception as exc:
            LOG.error("License decryption failed: %s", exc, exc_info=True)
            return None

    @classmethod
    async def _decrypt_license(cls) -> dict | None:
        """Async wrapper — offloads CPU-bound decryption to thread executor."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, cls._decrypt_sync)

    # -----------------------------------------------------------------------
    # License validation
    # -----------------------------------------------------------------------

    @classmethod
    def _validate_encrypted_license(cls, license_data: dict) -> dict:
        """Validate decrypted license: hardware UUID match + expiry check."""
        current_fp = cls._get_hardware_fingerprint()
        current_uuid = (current_fp.get("product_uuid") or "").upper()
        current_hostname = current_fp.get("hostname", "unknown")

        hosts = license_data.get("hosts", {})
        serial = license_data.get("license_id", "N/A")
        vendor = license_data.get("issued_by", "Xloud Technologies")
        lic_type = license_data.get("license_type", "production")

        if not hosts:
            return {
                "enabled": False,
                "status": "invalid_license",
                "serial": serial,
                "license_type": lic_type,
                "message": "Invalid license: no hosts defined.",
                "days_remaining": 0,
                "days_elapsed": 0,
                "start_date": "",
                "end_date": "",
                "cluster_id": current_hostname,
                "max_sockets": 0,
                "vendor": vendor,
                "expired": True,
                "warning": True,
            }

        if not current_uuid:
            return {
                "enabled": False,
                "status": "hardware_error",
                "serial": serial,
                "license_type": lic_type,
                "message": "Cannot read hardware UUID.",
                "days_remaining": 0,
                "days_elapsed": 0,
                "start_date": "",
                "end_date": "",
                "cluster_id": current_hostname,
                "max_sockets": 0,
                "vendor": vendor,
                "expired": True,
                "warning": True,
            }

        # Match product_uuid against ANY host in license
        matched_host = None
        matched_hostname = None
        for host_name, host_data in hosts.items():
            licensed_uuid = (host_data.get("product_uuid") or "").upper()
            if licensed_uuid and licensed_uuid == current_uuid:
                matched_host = host_data
                matched_hostname = host_name
                break

        if not matched_host:
            return {
                "enabled": False,
                "status": "invalid_hardware",
                "serial": serial,
                "license_type": lic_type,
                "message": f"Hardware UUID mismatch. This machine ({current_uuid[:12]}...) is not licensed.",
                "days_remaining": 0,
                "days_elapsed": 0,
                "start_date": "",
                "end_date": "",
                "cluster_id": current_hostname,
                "max_sockets": 0,
                "vendor": vendor,
                "expired": True,
                "warning": True,
            }

        hostname = matched_hostname

        # Check expiration
        try:
            expiry_date = datetime.fromisoformat(
                license_data["expiry_date"].replace("Z", "+00:00")
            )
            issued_date = datetime.fromisoformat(
                license_data["issued_date"].replace("Z", "+00:00")
            )
            now = datetime.now(timezone.utc)
            days_remaining = (expiry_date - now).days
            days_elapsed = (now - issued_date).days
        except Exception as exc:
            LOG.error("Failed to parse license dates: %s", exc)
            days_remaining = 0
            days_elapsed = 0

        max_sockets = license_data.get("total_sockets", 0)

        if days_remaining < 0:
            return {
                "enabled": False,
                "status": "expired",
                "serial": serial,
                "license_type": lic_type,
                "message": f"License expired {abs(days_remaining)} days ago. Renew immediately.",
                "days_remaining": days_remaining,
                "days_elapsed": days_elapsed,
                "start_date": issued_date.strftime("%Y-%m-%d"),
                "end_date": expiry_date.strftime("%Y-%m-%d"),
                "cluster_id": hostname,
                "max_sockets": max_sockets,
                "vendor": vendor,
                "expired": True,
                "warning": True,
            }

        warning = days_remaining < 30
        return {
            "enabled": True,
            "status": "active",
            "serial": serial,
            "license_type": lic_type,
            "message": f"License active. {days_remaining} days remaining."
            + (" Warning: expires soon!" if warning else ""),
            "days_remaining": days_remaining,
            "days_elapsed": days_elapsed,
            "start_date": issued_date.strftime("%Y-%m-%d"),
            "end_date": expiry_date.strftime("%Y-%m-%d"),
            "cluster_id": hostname,
            "max_sockets": max_sockets,
            "vendor": vendor,
            "expired": False,
            "warning": warning,
        }
