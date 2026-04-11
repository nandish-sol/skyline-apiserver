# Copyright 2025-2026 Xloud Technologies Pvt Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

"""OpenStack Notification Consumer — runs inside Skyline APIServer.

Consumes oslo.messaging notifications from RabbitMQ and writes
structured audit events to OpenSearch. Runs as a background thread
started at APIServer boot time.

Events captured: instance.create/delete/stop/start, volume.create/delete,
network.create/delete, security_group changes, image operations, etc.
"""

from __future__ import annotations

import json
import os
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx
import pika

from skyline_apiserver.log import LOG

# Configuration: read from skyline.yaml (populated by xavs-ansible from
# cluster inventory), with env var overrides for development/debugging.
# No hardcoded IPs — all connection details come from deployment config.
QUEUE_NAME = "skyline_audit"
INDEX_PREFIX = "openstack-audit"


def _get_rabbit_config():
    """Get RabbitMQ connection params from CONF (skyline.yaml) or env."""
    from skyline_apiserver.config import CONF
    return {
        "host": os.environ.get("RABBIT_HOST", CONF.openstack.rabbitmq_host),
        "port": int(os.environ.get("RABBIT_PORT", CONF.openstack.rabbitmq_port)),
        "user": os.environ.get("RABBIT_USER", CONF.openstack.rabbitmq_user),
        "password": os.environ.get("RABBIT_PASS", CONF.openstack.rabbitmq_password),
        "vhost": os.environ.get("RABBIT_VHOST", "/"),
    }


def _get_opensearch_url():
    """Get OpenSearch URL from CONF (skyline.yaml) or env."""
    from skyline_apiserver.config import CONF
    return os.environ.get("OPENSEARCH_URL", CONF.openstack.opensearch_url)

# Exchanges to bind for notifications. Most OpenStack services publish
# through the shared "openstack" topic exchange, but nova/neutron/keystone
# historically use their own exchanges, and cinder/glance/heat/barbican/
# octavia/manila/designate follow the same per-service convention when
# configured that way. Binding to all known exchanges is idempotent: the
# consumer silently skips any exchange that doesn't exist on a given
# deployment (see _consumer_loop) so this list is safe to be a superset.
EXCHANGES = [
    "openstack",
    "nova",
    "neutron",
    "keystone",
    "cinder",
    "glance",
    "heat",
    "barbican",
    "octavia",
    "manila",
    "designate",
    "placement",
    "watcher",
]

# Routing keys to bind. "notifications.info" is the default oslo.messaging
# notification topic. "audit.*" matches CADF audit events published by
# keystonemiddleware.audit when installed on service APIs — those carry
# full HTTP metadata (method, URL, status, client IP, response time).
ROUTING_KEYS = [
    "notifications.info",
    "notifications.warn",
    "notifications.error",
    "audit.http.request",
    "audit.http.response",
]

# Buffer for bulk writes
BULK_SIZE = 20
FLUSH_INTERVAL = 10  # seconds


def _parse_oslo_message(raw_body: bytes) -> Optional[Dict[str, Any]]:
    """Parse oslo.messaging 2.0 envelope and extract the notification."""
    try:
        envelope = json.loads(raw_body)
        inner = envelope.get("oslo.message")
        if inner:
            return json.loads(inner) if isinstance(inner, str) else inner
        return envelope
    except (json.JSONDecodeError, TypeError):
        return None


def _classify_action(event_type: str) -> str:
    """Classify event_type into a human-readable action category.

    Nova event_types follow the pattern: resource.action.phase
    e.g. instance.pause.start, instance.pause.end
    We strip the .start/.end phase suffix before matching to avoid
    false positives (e.g. "start" in "instance.pause.start").
    """
    et = event_type.lower()
    # Strip .start/.end phase suffix so it doesn't interfere with matching
    for suffix in (".start", ".end"):
        if et.endswith(suffix):
            et = et[: -len(suffix)]
            break
    if "delete" in et or "destroy" in et:
        return "delete"
    if "allocate" in et:
        return "create"
    if "disassociate" in et:
        return "disassociate"
    if "associate" in et:
        return "associate"
    if "create" in et or "import" in et:
        return "create"
    if "update" in et or "resize" in et or "extend" in et:
        return "update"
    if "power_off" in et or "shutdown" in et:
        return "stop"
    if "reboot" in et:
        return "reboot"
    if "unpause" in et:
        return "unpause"
    if "pause" in et:
        return "pause"
    if "unshelve" in et:
        return "unshelve"
    if "shelve" in et:
        return "shelve"
    if "resume" in et:
        return "resume"
    if "suspend" in et:
        return "suspend"
    if "power_on" in et:
        return "start"
    if "stop" in et:
        return "stop"
    if "start" in et:
        return "start"
    if "migrate" in et or "evacuat" in et:
        return "migrate"
    if "attach" in et:
        return "attach"
    if "detach" in et:
        return "detach"
    if "snapshot" in et:
        return "snapshot"
    if "unlock" in et:
        return "unlock"
    if "lock" in et:
        return "lock"
    if "authenticate" in et:
        return "authenticate"
    if "rescue" in et:
        return "rescue"
    return "action"


def _classify_resource(event_type: str) -> str:
    """Extract resource type from event_type."""
    et = event_type.lower()
    if "instance" in et or "compute" in et or "server" in et:
        return "instance"
    if "keypair" in et:
        return "keypair"
    if "volume" in et:
        return "volume"
    if "snapshot" in et:
        return "snapshot"
    if "network" in et:
        return "network"
    if "subnet" in et:
        return "subnet"
    if "port" in et:
        return "port"
    if "router" in et:
        return "router"
    if "floatingip" in et:
        return "floatingip"
    if "security_group_rule" in et:
        return "security_group_rule"
    if "security_group" in et:
        return "security_group"
    if "image" in et:
        return "image"
    if "trust" in et:
        return "trust"
    if "credential" in et:
        return "credential"
    if "role_assignment" in et:
        return "role_assignment"
    if "user" in et:
        return "user"
    if "project" in et:
        return "project"
    if "role" in et:
        return "role"
    if "domain" in et:
        return "domain"
    return "unknown"


def _extract_resource_details(
    event_type: str, payload: Dict[str, Any]
) -> Dict[str, str]:
    """Extract resource_id and resource_name from notification payload."""
    resource_id = ""
    resource_name = ""

    # Nova instance
    if payload.get("instance_id"):
        resource_id = payload["instance_id"]
        resource_name = payload.get("display_name", payload.get("hostname", ""))
    # Cinder volume
    elif payload.get("volume_id"):
        resource_id = payload["volume_id"]
        resource_name = payload.get("display_name", "")
    # Neutron (nested under resource type key)
    elif payload.get("network"):
        net = payload["network"]
        resource_id = net.get("id", "")
        resource_name = net.get("name", "")
    elif payload.get("port"):
        port = payload["port"]
        resource_id = port.get("id", "")
        resource_name = port.get("name", "")
    elif payload.get("router"):
        router = payload["router"]
        resource_id = router.get("id", "")
        resource_name = router.get("name", "")
    elif payload.get("subnet"):
        subnet = payload["subnet"]
        resource_id = subnet.get("id", "")
        resource_name = subnet.get("name", "")
    elif payload.get("floatingip"):
        fip = payload["floatingip"]
        resource_id = fip.get("id", "")
        resource_name = fip.get("floating_ip_address", "")
    elif payload.get("security_group"):
        sg = payload["security_group"]
        resource_id = sg.get("id", "")
        resource_name = sg.get("name", "")
    # Glance image
    elif payload.get("id") and "image" in event_type:
        resource_id = payload["id"]
        resource_name = payload.get("name", "")
    # Keystone
    elif payload.get("resource_info"):
        resource_id = payload["resource_info"]
    # Keypair
    elif payload.get("key_name"):
        resource_name = payload["key_name"]

    return {"resource_id": str(resource_id), "resource_name": str(resource_name)}


def _notification_to_doc(msg: Dict[str, Any]) -> Dict[str, Any]:
    """Convert an oslo.messaging notification to an OpenSearch document."""
    event_type = msg.get("event_type", "unknown")
    publisher_id = msg.get("publisher_id", "")
    payload = msg.get("payload", {})
    raw_ts = msg.get("timestamp", "")
    # oslo.messaging format: "2026-03-30 17:27:19.718592" (space, no T, no TZ)
    # OpenSearch expects ISO 8601: "2026-03-30T17:27:19.718592Z"
    if raw_ts and " " in raw_ts and "T" not in raw_ts:
        timestamp = raw_ts.replace(" ", "T") + "Z"
    elif raw_ts:
        timestamp = raw_ts
    else:
        timestamp = datetime.now(timezone.utc).isoformat()

    resource = _extract_resource_details(event_type, payload)
    service = publisher_id.split(".")[0] if publisher_id else "unknown"

    # Extract HTTP-like fields from oslo context when available
    # Nova/Neutron include request_id, roles, user_domain in context
    request_id = msg.get("_context_request_id", "")
    # Some services pass client IP in _context_remote_address
    client_ip = msg.get("_context_remote_address", "")
    # user_domain_name for richer user identification
    user_domain = msg.get("_context_user_domain_name", "")
    user_name = msg.get("_context_user_name", "")
    project_name = msg.get("_context_project_name", "")

    # Glance "basic" notifications (format=basic, the default) do NOT
    # carry any _context_* keys. The only auth hint in the payload is
    # "owner" which is the project_id (tenant) that owns the resource.
    # There is no user_id at all unless glance is configured with the
    # keystonemiddleware.audit middleware, which emits CADF format.
    # We fall back to payload.owner so at least the tenant column is
    # populated and name resolution can map it to a project name.
    #
    # For every other service the oslo context keys work fine.
    user_id = (
        payload.get("user_id")
        or msg.get("_context_user_id")
        or msg.get("_context_user")
        or ""
    )
    tenant_id = (
        payload.get("tenant_id")
        or payload.get("project_id")
        or payload.get("owner")  # Glance puts project_id here
        or msg.get("_context_project_id")
        or msg.get("_context_tenant")
        or ""
    )

    return {
        "@timestamp": timestamp,
        "event_type": event_type,
        "service": service,
        "action_type": _classify_action(event_type),
        "resource_type": _classify_resource(event_type),
        "resource_id": resource["resource_id"],
        "resource_name": resource["resource_name"],
        "user_id": user_id,
        "user_name": user_name,
        "tenant_id": tenant_id,
        "project_name": project_name,
        "node": publisher_id.split(".")[-1] if "." in publisher_id else publisher_id,
        "priority": msg.get("priority", "INFO"),
        "message_id": msg.get("message_id", ""),
        "request_id": request_id,
        "client_ip": client_ip,
        "event_category": "notification",
    }


def _bulk_write_to_opensearch(docs: List[Dict[str, Any]]) -> None:
    """Write a batch of documents to OpenSearch using the bulk API."""
    if not docs:
        return

    today = datetime.now(timezone.utc).strftime("%Y.%m.%d")
    index = f"{INDEX_PREFIX}-{today}"

    bulk_body = ""
    for doc in docs:
        action = json.dumps({"index": {"_index": index}})
        body = json.dumps(doc, default=str)
        bulk_body += f"{action}\n{body}\n"

    try:
        resp = httpx.post(
            f"{_get_opensearch_url()}/_bulk",
            content=bulk_body,
            headers={"Content-Type": "application/x-ndjson"},
            timeout=10.0,
        )
        if resp.status_code not in (200, 201):
            LOG.error("notification_consumer: bulk write failed: {}", resp.text[:200])
        else:
            result = resp.json()
            errors = result.get("errors", False)
            if errors:
                LOG.warning("notification_consumer: bulk write had errors")
            else:
                LOG.info("notification_consumer: wrote {} events to {}", len(docs), index)
    except Exception as exc:
        LOG.error("notification_consumer: OpenSearch write failed: {}", exc)


def _consumer_loop() -> None:
    """Main consumer loop — connects to RabbitMQ, consumes, writes to OpenSearch."""
    buffer: List[Dict[str, Any]] = []
    last_flush = time.time()

    while True:
        try:
            rabbit = _get_rabbit_config()
            creds = pika.PlainCredentials(rabbit["user"], rabbit["password"])
            params = pika.ConnectionParameters(
                host=rabbit["host"],
                port=rabbit["port"],
                virtual_host=rabbit["vhost"],
                credentials=creds,
                heartbeat=600,
                blocked_connection_timeout=300,
            )
            conn = pika.BlockingConnection(params)
            ch = conn.channel()

            # Declare classic queue (not quorum — we create our own)
            ch.queue_declare(
                queue=QUEUE_NAME,
                durable=True,
                arguments={"x-queue-type": "classic"},
            )

            # Bind to every (exchange, routing_key) combination. If the
            # exchange doesn't exist pika closes the channel with 404,
            # so we reopen the channel and continue — individual failures
            # must never stop the overall binding loop.
            for exchange in EXCHANGES:
                for routing_key in ROUTING_KEYS:
                    try:
                        ch.queue_bind(
                            queue=QUEUE_NAME,
                            exchange=exchange,
                            routing_key=routing_key,
                        )
                    except Exception:
                        LOG.debug(
                            "notification_consumer: bind {}:{} failed, skipping",
                            exchange, routing_key,
                        )
                        if ch.is_closed:
                            ch = conn.channel()

            LOG.info("notification_consumer: connected to RabbitMQ, consuming from {}", QUEUE_NAME)

            while True:
                method, properties, body = ch.basic_get(queue=QUEUE_NAME, auto_ack=False)

                if body:
                    msg = _parse_oslo_message(body)
                    if msg and msg.get("event_type"):
                        et = msg["event_type"]
                        # Skip .start events — only keep .end (avoids duplicates)
                        # .start has less data (no resource_id on create)
                        if et.endswith(".start"):
                            ch.basic_ack(method.delivery_tag)
                            continue
                        doc = _notification_to_doc(msg)
                        buffer.append(doc)
                        ch.basic_ack(method.delivery_tag)
                        LOG.debug(
                            "notification_consumer: {} | {} | {}",
                            doc["event_type"],
                            doc["resource_name"],
                            doc["action_type"],
                        )
                    else:
                        ch.basic_ack(method.delivery_tag)  # Discard malformed

                # Flush buffer periodically or when full
                now = time.time()
                if len(buffer) >= BULK_SIZE or (
                    buffer and now - last_flush >= FLUSH_INTERVAL
                ):
                    _bulk_write_to_opensearch(buffer)
                    buffer = []
                    last_flush = now

                if not body:
                    # No messages — sleep briefly
                    time.sleep(2)

        except pika.exceptions.AMQPConnectionError as e:
            LOG.warning("notification_consumer: RabbitMQ connection lost: {}. Reconnecting in 10s...", e)
            time.sleep(10)
        except Exception as e:
            LOG.error("notification_consumer: unexpected error: {}. Restarting in 10s...", e)
            LOG.opt(exception=True).debug("notification_consumer traceback")
            # Flush remaining buffer before restart
            if buffer:
                _bulk_write_to_opensearch(buffer)
                buffer = []
            time.sleep(10)


def start_notification_consumer() -> None:
    """Start the notification consumer in a background daemon thread."""
    thread = threading.Thread(
        target=_consumer_loop,
        name="xloud-audit-consumer",
        daemon=True,
    )
    thread.start()
    LOG.info("notification_consumer: background consumer thread started (tid={})", thread.ident)
