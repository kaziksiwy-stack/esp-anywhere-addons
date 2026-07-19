"""Signed firmware manifest validation for ESP Anywhere."""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from datetime import datetime
import json
import re
from typing import Any
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
import rfc8785

from .protocol import PROTOCOL_VERSION, ProtocolError

SEMVER_PATTERN = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$"
)
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
GIT_COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")


@dataclass(frozen=True, slots=True)
class FirmwareManifest:
    """Verified immutable firmware release metadata."""

    version: str
    protocol_version: str
    channel: str
    hardware_profile: str
    chip_family: str
    firmware_url: str
    firmware_size: int
    firmware_sha256: str
    key_id: str
    signature: str
    published_at: str
    release_url: str | None = None
    summary: str | None = None


def parse_and_verify_manifest(
    document: bytes,
    *,
    trusted_key_id: str,
    trusted_public_key: str,
    expected_hardware_profile: str,
) -> FirmwareManifest:
    """Parse, validate and authenticate a firmware manifest."""
    if len(document) > 64 * 1024:
        raise ProtocolError("Manifest exceeds 64 KiB")
    try:
        raw = json.loads(document.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as err:
        raise ProtocolError("Manifest is not a UTF-8 JSON object") from err
    if not isinstance(raw, dict):
        raise ProtocolError("Manifest root must be an object")

    _require(raw.get("schema_version") == 1, "Unsupported manifest schema")
    _require(raw.get("project") == "esp-anywhere", "Wrong manifest project")
    _require(raw.get("protocol_version") == PROTOCOL_VERSION, "Incompatible protocol")
    version = _required_string(raw, "version", 64)
    _require(SEMVER_PATTERN.fullmatch(version) is not None, "Invalid firmware SemVer")
    channel = _required_string(raw, "channel", 16)
    _require(channel in {"stable", "beta", "dev"}, "Invalid release channel")
    hardware_profile = _required_string(raw, "hardware_profile", 64)
    _require(hardware_profile == expected_hardware_profile, "Wrong hardware profile")
    chip_family = _required_string(raw, "chip_family", 16)
    _require(
        chip_family in {"ESP32", "ESP32-C3", "ESP32-C6", "ESP32-S3"},
        "Unsupported chip family",
    )
    framework = raw.get("framework")
    if not isinstance(framework, dict):
        raise ProtocolError("Framework must be an object")
    _require(
        _required_string(framework, "name", 16) in {"esp-idf", "arduino"},
        "Unsupported framework",
    )
    _required_string(framework, "version", 64)
    _required_string(raw, "build_id", 128)
    git_commit = _required_string(raw, "git_commit", 40)
    _require(GIT_COMMIT_PATTERN.fullmatch(git_commit) is not None, "Invalid git commit")
    published_at = _required_string(raw, "published_at", 64)
    try:
        datetime.fromisoformat(published_at.replace("Z", "+00:00"))
    except ValueError as err:
        raise ProtocolError("Invalid published_at") from err

    firmware = raw.get("firmware")
    security = raw.get("security")
    if not isinstance(firmware, dict) or not isinstance(security, dict):
        raise ProtocolError("Manifest firmware and security must be objects")
    firmware_url = _required_string(firmware, "url", 1024)
    _require(firmware_url.startswith("https://"), "Firmware URL must use HTTPS")
    firmware_size = firmware.get("size")
    _require(isinstance(firmware_size, int) and firmware_size > 0, "Invalid firmware size")
    firmware_sha256 = _required_string(firmware, "sha256", 64)
    _require(SHA256_PATTERN.fullmatch(firmware_sha256) is not None, "Invalid SHA-256")

    key_id = _required_string(security, "key_id", 64)
    signature = _required_string(security, "signature", 128)
    _require(key_id == trusted_key_id, "Manifest uses an untrusted signing key")
    _verify_signature(raw, signature, trusted_public_key)

    return FirmwareManifest(
        version=version,
        protocol_version=PROTOCOL_VERSION,
        channel=channel,
        hardware_profile=hardware_profile,
        chip_family=chip_family,
        firmware_url=firmware_url,
        firmware_size=firmware_size,
        firmware_sha256=firmware_sha256,
        key_id=key_id,
        signature=signature,
        published_at=published_at,
        release_url=_optional_https(raw, "release_url"),
        summary=_optional_string(raw, "summary", 1024),
    )


def version_is_newer(candidate: str, installed: str) -> bool:
    """Compare strict SemVer values, including prerelease precedence."""
    return _semver_key(candidate) > _semver_key(installed)


def validate_manifest_url(url: str, allowed_host: str) -> None:
    """Bind manifest downloads to one explicitly configured HTTPS host."""
    parsed = urlsplit(url)
    try:
        port = parsed.port
    except ValueError as err:
        raise ProtocolError("Manifest URL contains an invalid port") from err
    if (
        parsed.scheme != "https"
        or parsed.hostname is None
        or parsed.hostname.lower() != allowed_host.lower()
        or parsed.username is not None
        or parsed.password is not None
        or port not in (None, 443)
        or not parsed.path.startswith("/")
    ):
        raise ProtocolError("Manifest URL is outside the allowed firmware host")


def _semver_key(value: str) -> tuple:
    match = SEMVER_PATTERN.fullmatch(value)
    if match is None:
        raise ProtocolError("Invalid firmware SemVer")
    prerelease = match.group(4)
    if prerelease is None:
        pre_key = ((1, ""),)
    else:
        parts = []
        for part in prerelease.split("."):
            parts.append((0, int(part)) if part.isdigit() else (1, part))
        pre_key = ((0, ""), *parts)
    return (int(match.group(1)), int(match.group(2)), int(match.group(3)), pre_key)


def _verify_signature(raw: dict[str, Any], signature: str, public_key: str) -> None:
    """Verify the Ed25519 signature over the constrained canonical JSON profile."""
    unsigned = json.loads(json.dumps(raw))
    unsigned["security"].pop("signature", None)
    try:
        canonical = rfc8785.dumps(unsigned)
    except rfc8785.CanonicalizationError as err:
        raise ProtocolError("Manifest cannot be canonicalized") from err
    try:
        key_bytes = base64.b64decode(public_key, validate=True)
        signature_bytes = base64.b64decode(signature, validate=True)
        if len(key_bytes) != 32 or len(signature_bytes) != 64:
            raise ProtocolError("Invalid Ed25519 key or signature length")
        Ed25519PublicKey.from_public_bytes(key_bytes).verify(signature_bytes, canonical)
    except (binascii.Error, ValueError, InvalidSignature) as err:
        raise ProtocolError("Invalid manifest signature") from err


def _required_string(payload: dict[str, Any], key: str, maximum: int) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ProtocolError(f"Invalid or missing {key}")
    return value


def _optional_string(
    payload: dict[str, Any], key: str, maximum: int
) -> str | None:
    value = payload.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > maximum:
        raise ProtocolError(f"Invalid {key}")
    return value


def _optional_https(payload: dict[str, Any], key: str) -> str | None:
    value = _optional_string(payload, key, 1024)
    if value is not None and not value.startswith("https://"):
        raise ProtocolError(f"{key} must use HTTPS")
    return value


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ProtocolError(message)
