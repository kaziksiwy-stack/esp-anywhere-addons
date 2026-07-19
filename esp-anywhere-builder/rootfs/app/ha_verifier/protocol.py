"""Wire protocol primitives for ESP Anywhere.

This module deliberately has no Home Assistant imports so its security-sensitive
parsing can be unit tested in isolation.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
import re
from typing import Any
from uuid import uuid4

from .const import PROTOCOL_VERSION, TOPIC_ROOT

IDENTIFIER_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{2,63}$")
MAX_PAYLOAD_BYTES = 32 * 1024
ALLOWED_COMMANDS = frozenset(
    {"set_entity", "restart", "request_state", "check_update", "install_update", "enter_safe_mode"}
)

ALLOWED_SUFFIXES = frozenset(
    {
        "presence",
        "discovery",
        "state",
        "command/result",
        "event",
        "diagnostics",
        "ota/status",
        "ota/progress",
    }
)


class ProtocolError(ValueError):
    """Raised when an incoming protocol message is invalid."""


@dataclass(frozen=True, slots=True)
class Topic:
    """Validated ESP Anywhere topic."""

    tenant_id: str
    device_id: str
    suffix: str


@dataclass(frozen=True, slots=True)
class Message:
    """Validated common message envelope."""

    device_id: str
    protocol_version: str
    payload: dict[str, Any]
    raw: dict[str, Any]


def topic_filter(tenant_id: str) -> str:
    """Return the subscription filter for a validated tenant."""
    _validate_identifier(tenant_id, "tenant_id")
    return f"{TOPIC_ROOT}/{tenant_id}/#"


def command_topic(tenant_id: str, device_id: str) -> str:
    """Return the command topic for one validated device."""
    _validate_identifier(tenant_id, "tenant_id")
    _validate_identifier(device_id, "device_id")
    return f"{TOPIC_ROOT}/{tenant_id}/{device_id}/command"


def create_command(
    device_id: str,
    command: str,
    parameters: dict[str, Any],
    *,
    lifetime: timedelta = timedelta(seconds=30),
    now: datetime | None = None,
) -> tuple[str, bytes]:
    """Create a bounded, expiring command payload and return its ID."""
    _validate_identifier(device_id, "device_id")
    if command not in ALLOWED_COMMANDS:
        raise ProtocolError(f"Unsupported command: {command}")
    if lifetime <= timedelta(0) or lifetime > timedelta(minutes=5):
        raise ProtocolError("Command lifetime must be between 0 and 5 minutes")
    if not isinstance(parameters, dict):
        raise ProtocolError("Command parameters must be an object")

    issued_at = now or datetime.now(timezone.utc)
    if issued_at.tzinfo is None:
        raise ProtocolError("Command time must be timezone-aware")
    command_id = str(uuid4())
    document = {
        "protocol_version": PROTOCOL_VERSION,
        "message_id": str(uuid4()),
        "device_id": device_id,
        "command_id": command_id,
        "command": command,
        "issued_at": issued_at.isoformat(timespec="seconds").replace("+00:00", "Z"),
        "expires_at": (issued_at + lifetime).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "parameters": parameters,
    }
    encoded = json.dumps(document, separators=(",", ":")).encode("utf-8")
    if len(encoded) > MAX_PAYLOAD_BYTES:
        raise ProtocolError("Command exceeds the protocol payload limit")
    return command_id, encoded


def parse_topic(value: str) -> Topic:
    """Parse and validate an ESP Anywhere MQTT topic."""
    parts = value.split("/")
    root_parts = TOPIC_ROOT.split("/")
    root_length = len(root_parts)
    if parts[:root_length] != root_parts or len(parts) < root_length + 3:
        raise ProtocolError("Topic is outside the ESP Anywhere v1 namespace")

    tenant_id = parts[root_length]
    device_id = parts[root_length + 1]
    suffix = "/".join(parts[root_length + 2 :])
    _validate_identifier(tenant_id, "tenant_id")
    _validate_identifier(device_id, "device_id")

    if suffix.startswith("state/"):
        entity_id = suffix.removeprefix("state/")
        _validate_identifier(entity_id, "entity_id")
    elif suffix not in ALLOWED_SUFFIXES:
        raise ProtocolError(f"Unsupported topic suffix: {suffix}")

    return Topic(tenant_id=tenant_id, device_id=device_id, suffix=suffix)


def parse_message(topic: Topic, payload: bytes) -> Message:
    """Decode an envelope and bind its identity to the MQTT topic."""
    if len(payload) > MAX_PAYLOAD_BYTES:
        raise ProtocolError("Payload exceeds the 32 KiB protocol limit")
    try:
        data = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as err:
        raise ProtocolError("Payload is not a UTF-8 JSON document") from err

    if not isinstance(data, dict):
        raise ProtocolError("Payload root must be a JSON object")
    if data.get("protocol_version") != PROTOCOL_VERSION:
        raise ProtocolError("Unsupported protocol version")
    if data.get("device_id") != topic.device_id:
        raise ProtocolError("Payload device_id does not match MQTT topic")

    critical_fields = (key for key in data if key.startswith("critical_"))
    if next(critical_fields, None) is not None:
        raise ProtocolError("Unknown critical field")

    message_payload = data.get("payload", {})
    if not isinstance(message_payload, dict):
        raise ProtocolError("Message payload must be an object")

    return Message(
        device_id=topic.device_id,
        protocol_version=PROTOCOL_VERSION,
        payload=message_payload,
        raw=data,
    )


def _validate_identifier(value: str, field: str) -> None:
    """Validate a tenant, device or entity identifier."""
    if not IDENTIFIER_PATTERN.fullmatch(value):
        raise ProtocolError(f"Invalid {field}")
