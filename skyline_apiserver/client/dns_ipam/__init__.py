from __future__ import annotations

import base64
import hashlib
import logging
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

from skyline_apiserver.config import CONF

LOG = logging.getLogger(__name__)


def _get_fernet() -> Fernet:
    key = hashlib.sha256(CONF.default.secret_key.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key))


def encrypt_password(plaintext: str) -> str:
    if not plaintext:
        return ""
    return _get_fernet().encrypt(plaintext.encode()).decode()


def decrypt_password(ciphertext: str) -> str:
    if not ciphertext:
        return ""
    try:
        return _get_fernet().decrypt(ciphertext.encode()).decode()
    except InvalidToken:
        LOG.warning("Failed to decrypt DNS IPAM password — invalid token")
        return ""


def get_provider_client(provider_type: str) -> Any:
    if provider_type == "powerdns":
        from skyline_apiserver.client.dns_ipam import powerdns

        return powerdns
    elif provider_type == "msdns":
        from skyline_apiserver.client.dns_ipam import msdns

        return msdns
    else:
        from skyline_apiserver.client.dns_ipam import infoblox

        return infoblox
