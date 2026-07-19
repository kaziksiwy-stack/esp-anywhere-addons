"""ESP Anywhere Builder Home Assistant OS add-on."""
from __future__ import annotations

import base64
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import threading
from typing import Any
from urllib import error as urlerror
from urllib import request as urlrequest
from urllib.parse import urlparse
from uuid import uuid4

import rfc8785
import yaml
from cryptography import x509
from ha_verifier.manifest import parse_and_verify_manifest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

DEVICE_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{2,63}$")
YAML_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_.-]{2,127}\.ya?ml$")
SEMVER_PATTERN = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
VERSION_LINE = re.compile(r"(?m)^  firmware_version: ([^\s]+)\s*$")
PROFILE_LINE = re.compile(r"(?m)^  hardware_profile: ([a-z0-9_-]+)\s*$")
DEVICE_LINE = re.compile(r"(?m)^  device_id: ([a-z0-9_-]+)\s*$")
INITIAL_OTA_LINE = re.compile(r'(?m)^    initial_value: "OTA [^"]+ OK"\s*$')
REPOSITORY_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
KEY_ID_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{2,63}$")
CA_SECRET_LINE = re.compile(r"(?m)^\s*certificate_authority:\s*!secret\s+([A-Za-z0-9_]+)\s*$")
STAGES = {"validating", "compiling", "signing", "publishing", "ready", "failed"}
DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
CONFIG_DIR = Path(os.environ.get("ESPHOME_CONFIG_DIR", "/homeassistant/esphome"))
WORK_ROOT = Path(os.environ.get("WORK_ROOT", "/tmp/esp-anywhere-builder"))
TOKEN_FILE = DATA_DIR / "secrets/github_token"
KEY_FILE = DATA_DIR / "keys/firmware_signing_key.pem"
SETTINGS_FILE = DATA_DIR / "settings.json"
ASKPASS_FILE = DATA_DIR / "secrets/git-askpass"
DEFAULT_REPOSITORY = "kaziksiwy-stack/esp-anywhere-ota"
ALLOWED_REPOSITORIES = frozenset(filter(None, os.environ.get("ALLOWED_OTA_REPOSITORIES", DEFAULT_REPOSITORY).split(",")))
MAX_BODY = 128 * 1024


def next_patch_version(current: str) -> str:
    match = SEMVER_PATTERN.fullmatch(current)
    if match is None:
        raise ValueError("Current version is not stable SemVer")
    return f"{match.group(1)}.{match.group(2)}.{int(match.group(3)) + 1}"


def replace_firmware_version(text: str, version: str, expected_device_id: str) -> tuple[str, str]:
    if SEMVER_PATTERN.fullmatch(version) is None:
        raise ValueError("Invalid firmware version")
    if len(VERSION_LINE.findall(text)) != 1:
        raise ValueError("YAML must contain exactly one firmware_version")
    rendered = VERSION_LINE.sub(f"  firmware_version: {version}", text, count=1)
    rendered = INITIAL_OTA_LINE.sub(f'    initial_value: "OTA {version} OK"', rendered, count=1)
    profiles = PROFILE_LINE.findall(rendered)
    devices = DEVICE_LINE.findall(rendered)
    if len(profiles) != 1 or len(devices) != 1:
        raise ValueError("YAML must contain exactly one hardware_profile and device_id")
    if devices[0] != expected_device_id:
        raise ValueError("YAML device_id does not match the selected device")
    return rendered, profiles[0]


def safe_yaml_name(value: Any) -> str:
    if not isinstance(value, str) or YAML_PATTERN.fullmatch(value) is None or Path(value).name != value:
        raise ValueError("Invalid YAML filename")
    return value


def safe_device(value: Any) -> str:
    if not isinstance(value, str) or DEVICE_PATTERN.fullmatch(value) is None:
        raise ValueError("Invalid device_id")
    return value


def atomic_private_file(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        path.chmod(0o600)
    finally:
        if temporary.exists():
            temporary.unlink()


def scalar_secrets(path: Path) -> list[str]:
    if not path.is_file() or path.is_symlink():
        return []
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    found: list[str] = []
    def visit(value: Any) -> None:
        if isinstance(value, dict):
            for nested in value.values(): visit(nested)
        elif isinstance(value, list):
            for nested in value: visit(nested)
        elif isinstance(value, (str, int, float)) and len(str(value)) >= 3:
            found.append(str(value))
    visit(document)
    return sorted(found, key=len, reverse=True)


def redact(value: str, secrets: list[str] | None = None) -> str:
    text = value
    for secret in secrets or []:
        text = text.replace(secret, "<redacted>")
    text = re.sub(r"-----BEGIN [^-]+ PRIVATE KEY-----.*?-----END [^-]+ PRIVATE KEY-----", "<private-key-redacted>", text, flags=re.S)
    text = re.sub(r"(?i)(password|passwd|token|secret|api[_-]?key|mqtt_password|wifi_password)(\s*[:=]\s*)\S+", r"\1\2<redacted>", text)
    text = re.sub(r"https?://[^/@\s]+:[^/@\s]+@", "https://<credentials-redacted>@", text)
    return "\n".join(line[:400] for line in text.splitlines()[-80:])[:12000]


def validate_mqtt_ca(yaml_bytes: bytes, secrets_bytes: bytes) -> None:
    """Resolve and validate the MQTT CA without returning or logging its value."""
    try:
        names = CA_SECRET_LINE.findall(yaml_bytes.decode("utf-8"))
        if len(names) != 1:
            raise ValueError("YAML must reference exactly one MQTT CA secret")
        secrets = yaml.safe_load(secrets_bytes.decode("utf-8"))
        if not isinstance(secrets, dict):
            raise ValueError("ESPHome secrets file is invalid")
        certificate = secrets.get(names[0])
        if not isinstance(certificate, str) or not certificate.strip():
            raise ValueError("MQTT CA secret is missing")
        try:
            x509.load_pem_x509_certificate(certificate.encode("utf-8"))
        except Exception as exc:
            raise ValueError("MQTT CA certificate is not valid X.509 PEM") from exc
    except UnicodeDecodeError as exc:
        raise ValueError("ESPHome configuration is not valid UTF-8") from exc


def public_key_info() -> dict[str, Any]:
    settings = load_settings()
    if not KEY_FILE.is_file():
        return {"configured": False}
    private = serialization.load_pem_private_key(KEY_FILE.read_bytes(), password=None)
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {"configured": True, "key_id": settings["key_id"], "public_key": base64.b64encode(public).decode("ascii")}


def load_settings() -> dict[str, str]:
    defaults = {"repository": DEFAULT_REPOSITORY, "key_id": "firmware-prod-2026-01"}
    if not SETTINGS_FILE.is_file() or SETTINGS_FILE.is_symlink():
        return defaults
    try:
        raw = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return defaults
    repository = raw.get("repository", defaults["repository"])
    key_id = raw.get("key_id", defaults["key_id"])
    if repository not in ALLOWED_REPOSITORIES or KEY_ID_PATTERN.fullmatch(key_id) is None:
        return defaults
    return {"repository": repository, "key_id": key_id}


def save_settings(repository: str, key_id: str) -> None:
    if repository not in ALLOWED_REPOSITORIES or REPOSITORY_PATTERN.fullmatch(repository) is None:
        raise ValueError("Repository is not allowlisted")
    if KEY_ID_PATTERN.fullmatch(key_id) is None:
        raise ValueError("Invalid key ID")
    atomic_private_file(SETTINGS_FILE, (json.dumps({"repository": repository, "key_id": key_id}, indent=2) + "\n").encode())


def ensure_key() -> None:
    if KEY_FILE.exists():
        if KEY_FILE.is_symlink() or not KEY_FILE.is_file():
            raise RuntimeError("Signing key path is unsafe")
        return
    private = Ed25519PrivateKey.generate()
    pem = private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    atomic_private_file(KEY_FILE, pem)


def install_askpass() -> None:
    script = b'''#!/usr/bin/env python3\nimport pathlib, sys\nprompt = sys.argv[1] if len(sys.argv) > 1 else ""\nif "Username" in prompt:\n print("x-access-token")\nelse:\n print(pathlib.Path("/data/secrets/github_token").read_text().strip())\n'''
    atomic_private_file(ASKPASS_FILE, script)
    ASKPASS_FILE.chmod(0o700)


@dataclass(slots=True)
class Job:
    job_id: str
    device_id: str
    yaml_file: str
    stage: str = "validating"
    version: str | None = None
    error: str | None = None
    log: list[str] = field(default_factory=list)


class Builder:
    def __init__(self) -> None:
        self.jobs: dict[str, Job] = {}
        self.active_devices: set[str] = set()
        self.lock = threading.Lock()
        DATA_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
        WORK_ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
        ensure_key()
        install_askpass()

    def list_devices(self) -> list[dict[str, str]]:
        if not CONFIG_DIR.is_dir() or CONFIG_DIR.is_symlink():
            return []
        result = []
        for path in sorted(CONFIG_DIR.iterdir()):
            if not path.is_file() or path.is_symlink() or YAML_PATTERN.fullmatch(path.name) is None or path.name == "secrets.yaml":
                continue
            try: text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError): continue
            versions, devices = VERSION_LINE.findall(text), DEVICE_LINE.findall(text)
            if len(versions) == 1 and len(devices) == 1 and DEVICE_PATTERN.fullmatch(devices[0]):
                try: suggested = next_patch_version(versions[0])
                except ValueError: suggested = ""
                result.append({"yaml_file": path.name, "device_id": devices[0], "firmware_version": versions[0], "suggested_version": suggested})
        return result

    def validate(self, yaml_file: str, device_id: str) -> dict[str, Any]:
        yaml_file, device_id = safe_yaml_name(yaml_file), safe_device(device_id)
        job_dir = WORK_ROOT / f"validate-{uuid4().hex}"
        secrets = scalar_secrets(CONFIG_DIR / "secrets.yaml")
        try:
            config_copy = job_dir / "config"
            self._copy_config(config_copy, yaml_file)
            source = config_copy / yaml_file
            if not source.is_file() or source.is_symlink(): raise ValueError("YAML does not exist")
            text = source.read_text(encoding="utf-8")
            devices = DEVICE_LINE.findall(text)
            if devices != [device_id]: raise ValueError("YAML device_id does not match selection")
            output = self._run(["esphome", "config", str(source)], cwd=config_copy, secrets=secrets)
            return {"ok": True, "log": redact(output, secrets)}
        finally:
            shutil.rmtree(job_dir, ignore_errors=True)

    def create_job(self, yaml_file: str, device_id: str, version: str | None) -> Job:
        yaml_file, device_id = safe_yaml_name(yaml_file), safe_device(device_id)
        if version is not None and SEMVER_PATTERN.fullmatch(version) is None: raise ValueError("Invalid version")
        with self.lock:
            if device_id in self.active_devices: raise RuntimeError("A build for this device is already active")
            job = Job(str(uuid4()), device_id, yaml_file, version=version)
            self.jobs[job.job_id] = job
            self.active_devices.add(device_id)
            self._persist(job)
        threading.Thread(target=self._build_boundary, args=(job,), daemon=True).start()
        return job

    def _build_boundary(self, job: Job) -> None:
        directory = WORK_ROOT / job.job_id
        try:
            self._build(job, directory)
        except Exception as exc:
            self._stage(job, "failed", error=redact(str(exc), scalar_secrets(CONFIG_DIR / "secrets.yaml"))[:240])
        finally:
            shutil.rmtree(directory, ignore_errors=True)
            with self.lock: self.active_devices.discard(job.device_id)

    def _build(self, job: Job, directory: Path) -> None:
        if not TOKEN_FILE.is_file() or TOKEN_FILE.is_symlink(): raise ValueError("GitHub token is not configured")
        if not KEY_FILE.is_file() or KEY_FILE.is_symlink(): raise ValueError("Signing key is not configured")
        signing_key_pem = KEY_FILE.read_bytes()
        signing_key = serialization.load_pem_private_key(signing_key_pem, password=None)
        if not isinstance(signing_key, Ed25519PrivateKey): raise ValueError("Signing key must be Ed25519")
        signing_public = base64.b64encode(signing_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode("ascii")
        settings = load_settings(); repository = settings["repository"]
        secrets = scalar_secrets(CONFIG_DIR / "secrets.yaml")
        config_copy = directory / "config"; self._copy_config(config_copy, job.yaml_file)
        yaml_path = config_copy / job.yaml_file
        if not yaml_path.is_file() or yaml_path.is_symlink(): raise ValueError("YAML does not exist")
        repo = directory / "ota"
        self._run(["git", "clone", f"https://github.com/{repository}.git", str(repo)], secrets=secrets)
        manifest_path = repo / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        current = manifest.get("version")
        if not isinstance(current, str) or SEMVER_PATTERN.fullmatch(current) is None: raise ValueError("OTA manifest version is invalid")
        version = job.version or next_patch_version(current)
        if tuple(map(int, version.split("."))) <= tuple(map(int, current.split("."))): raise ValueError("New version must be greater than current OTA version")
        job.version = version
        rendered, profile = replace_firmware_version(yaml_path.read_text(encoding="utf-8"), version, job.device_id)
        yaml_path.write_text(rendered, encoding="utf-8")
        self._append(job, self._run(["esphome", "config", str(yaml_path)], cwd=config_copy, secrets=secrets))
        self._stage(job, "compiling")
        shutil.rmtree(config_copy / ".esphome", ignore_errors=True)
        self._append(job, self._run(["esphome", "compile", str(yaml_path)], cwd=config_copy, secrets=secrets))
        candidates = list(config_copy.rglob("firmware.ota.bin"))
        if len(candidates) != 1: raise ValueError("Build did not produce exactly one firmware.ota.bin")
        firmware_name = f"firmware-{version}.ota.bin"; firmware = repo / firmware_name
        shutil.copy2(candidates[0], firmware)
        self._git_identity(repo)
        self._run(["git", "add", firmware_name], cwd=repo)
        self._run(["git", "commit", "-m", f"Add ESP Anywhere firmware {version}"], cwd=repo)
        firmware_commit = self._run(["git", "rev-parse", "HEAD"], cwd=repo).strip()
        self._stage(job, "signing")
        document = self._manifest(version, profile, firmware_commit, firmware, repository, settings["key_id"], signing_key)
        final_manifest = (json.dumps(document, indent=2) + "\n").encode("utf-8")
        parse_and_verify_manifest(final_manifest, trusted_key_id=settings["key_id"], trusted_public_key=signing_public, expected_hardware_profile=profile)
        if KEY_FILE.read_bytes() != signing_key_pem: raise RuntimeError("Signing key changed during build")
        manifest_path.write_bytes(final_manifest)
        self._run(["git", "add", "manifest.json"], cwd=repo)
        self._run(["git", "commit", "-m", f"Publish signed manifest for {version}"], cwd=repo)
        tag = f"firmware-v{version}"; self._run(["git", "tag", tag], cwd=repo)
        self._stage(job, "publishing")
        if KEY_FILE.read_bytes() != signing_key_pem: raise RuntimeError("Signing key changed before publication")
        env = self._git_env()
        self._run(["git", "push", "origin", "main"], cwd=repo, env=env)
        self._run(["git", "push", "origin", f"refs/tags/{tag}:refs/tags/{tag}"], cwd=repo, env=env)
        self._create_release(repository, tag, version, firmware_name)
        self._stage(job, "ready")

    def _copy_config(self, destination: Path, yaml_file: str) -> None:
        if not CONFIG_DIR.is_dir() or CONFIG_DIR.is_symlink(): raise ValueError("ESPHome config directory is unavailable")
        source_yaml = CONFIG_DIR / yaml_file
        source_secrets = CONFIG_DIR / "secrets.yaml"
        if not source_yaml.is_file() or source_yaml.is_symlink(): raise ValueError("YAML does not exist")
        if not source_secrets.is_file() or source_secrets.is_symlink(): raise ValueError("ESPHome secrets file is unavailable")
        yaml_bytes = source_yaml.read_bytes()
        secrets_bytes = source_secrets.read_bytes()
        validate_mqtt_ca(yaml_bytes, secrets_bytes)
        shutil.copytree(CONFIG_DIR, destination, ignore=shutil.ignore_patterns(".git", ".esphome", "build", "*.bin", "*.elf", "*.pem", "*.key"))
        atomic_private_file(destination / yaml_file, yaml_bytes)
        atomic_private_file(destination / "secrets.yaml", secrets_bytes)

    def _stage(self, job: Job, stage: str, error: str | None = None) -> None:
        if stage not in STAGES: raise ValueError("Invalid stage")
        with self.lock: job.stage, job.error = stage, error; self._persist(job)

    def _append(self, job: Job, output: str) -> None:
        clean = redact(output, scalar_secrets(CONFIG_DIR / "secrets.yaml"))
        with self.lock: job.log = (job.log + clean.splitlines())[-80:]; self._persist(job)

    def _persist(self, job: Job) -> None:
        safe = asdict(job)
        atomic_private_file(DATA_DIR / "jobs" / f"{job.job_id}.json", (json.dumps(safe, indent=2) + "\n").encode())

    @staticmethod
    def _run(args: list[str], cwd: Path | None = None, env: dict[str, str] | None = None, secrets: list[str] | None = None) -> str:
        result = subprocess.run(args, cwd=cwd, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=3600, check=False)
        output = redact(result.stdout, secrets)
        if result.returncode != 0: raise RuntimeError(output)
        return output

    @staticmethod
    def _git_identity(repo: Path) -> None:
        Builder._run(["git", "config", "user.name", "ESP Anywhere Builder"], cwd=repo)
        Builder._run(["git", "config", "user.email", "esp-anywhere-builder@localhost"], cwd=repo)

    @staticmethod
    def _git_env() -> dict[str, str]:
        env = os.environ.copy(); env.update({"GIT_ASKPASS": str(ASKPASS_FILE), "GIT_TERMINAL_PROMPT": "0"})
        return env

    @staticmethod
    def _manifest(version: str, profile: str, commit: str, firmware: Path, repository: str, key_id: str, private: Ed25519PrivateKey) -> dict[str, Any]:
        document: dict[str, Any] = {"schema_version": 1, "project": "esp-anywhere", "version": version, "protocol_version": "1.0", "channel": "stable", "hardware_profile": profile, "chip_family": "ESP32-C3", "framework": {"name": "esp-idf", "version": "5.5.4"}, "build_id": f"{version}-{commit[:12]}", "git_commit": commit, "published_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"), "release_url": f"https://github.com/{repository}/releases/tag/firmware-v{version}", "summary": f"ESP Anywhere firmware {version}", "firmware": {"url": f"https://raw.githubusercontent.com/{repository}/{commit}/{firmware.name}", "size": firmware.stat().st_size, "sha256": hashlib.sha256(firmware.read_bytes()).hexdigest()}, "security": {"key_id": key_id}}
        document["security"]["signature"] = base64.b64encode(private.sign(rfc8785.dumps(document))).decode("ascii")
        return document

    @staticmethod
    def _verify(document: dict[str, Any]) -> None:
        unsigned = json.loads(json.dumps(document)); signature = base64.b64decode(unsigned["security"].pop("signature"), validate=True)
        private = serialization.load_pem_private_key(KEY_FILE.read_bytes(), password=None)
        public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        Ed25519PublicKey.from_public_bytes(public).verify(signature, rfc8785.dumps(unsigned))

    @staticmethod
    def _create_release(repository: str, tag: str, version: str, firmware_name: str) -> None:
        token = TOKEN_FILE.read_text(encoding="utf-8").strip()
        payload = json.dumps({"tag_name": tag, "name": f"ESP Anywhere firmware {version}", "body": f"Signed OTA firmware `{firmware_name}` for ESP Anywhere {version}.", "draft": False, "prerelease": False}).encode()
        request = urlrequest.Request(f"https://api.github.com/repos/{repository}/releases", data=payload, method="POST", headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json", "Content-Type": "application/json", "X-GitHub-Api-Version": "2022-11-28"})
        try:
            with urlrequest.urlopen(request, timeout=30) as response:
                if response.status != 201: raise RuntimeError("GitHub release creation failed")
        except urlerror.HTTPError as exc:
            raise RuntimeError(f"GitHub release creation failed with HTTP {exc.code}") from None


HTML = r'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ESP Anywhere Builder</title><style>
:root{font-family:system-ui,sans-serif;color-scheme:light dark}body{margin:0;background:#111827;color:#f9fafb}.wrap{max-width:760px;margin:auto;padding:16px}.card{background:#1f2937;border-radius:14px;padding:16px;margin:12px 0;box-shadow:0 4px 18px #0005}h1{font-size:1.45rem}label{display:block;margin:12px 0 5px}select,input,textarea,button{width:100%;box-sizing:border-box;font:inherit;padding:12px;border-radius:9px;border:1px solid #4b5563;background:#111827;color:#fff}button{margin-top:10px;background:#0d9488;border:0;font-weight:700}button.secondary{background:#374151}.grid{display:grid;grid-template-columns:1fr 1fr;gap:10px}.stages{display:flex;gap:5px;overflow:auto}.stage{padding:6px 9px;border-radius:20px;background:#374151;font-size:.78rem}.active{background:#0d9488}.failed{background:#b91c1c}pre{white-space:pre-wrap;word-break:break-word;max-height:260px;overflow:auto;background:#030712;padding:10px;border-radius:8px}.ok{color:#5eead4}.error{color:#fca5a5}@media(max-width:520px){.grid{grid-template-columns:1fr}}
</style></head><body><div class="wrap"><h1>ESP Anywhere Builder</h1><div class="card"><div id="key"></div><label>GitHub token</label><input id="token" type="password" autocomplete="off"><div class="grid"><button onclick="saveToken()">Save/change token</button><button class="secondary" onclick="deleteToken()">Remove token</button></div><label>Import Ed25519 private key (PEM)</label><textarea id="pem" rows="3" autocomplete="off"></textarea><label>Key ID</label><input id="keyid" value="firmware-prod-2026-01"><button class="secondary" onclick="importKey()">Import key once</button></div><div class="card"><label>ESPHome device</label><select id="device" onchange="choose()"></select><label>Current firmware</label><input id="current" readonly><label>New version</label><input id="version"><div class="grid"><button class="secondary" onclick="validateYaml()">Validate</button><button onclick="build()">Build & Publish OTA</button></div></div><div class="card"><div class="stages" id="stages"></div><div id="message"></div><pre id="log">Ready.</pre></div></div><script>
const order=['validating','compiling','signing','publishing','ready'];let devices=[],job=null;const api=(p,o={})=>fetch(p,{headers:{'Content-Type':'application/json'},...o}).then(async r=>{let x=await r.json();if(!r.ok)throw Error(x.error||'Request failed');return x});function esc(x){return String(x||'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]))}function stages(s){document.querySelector('#stages').innerHTML=order.map(x=>`<span class="stage ${x===s?'active':''}">${x}</span>`).join('')}async function load(){let s=await api('api/state');devices=s.devices;document.querySelector('#device').innerHTML=devices.map((d,i)=>`<option value="${i}">${esc(d.device_id)} — ${esc(d.yaml_file)}</option>`).join('');document.querySelector('#key').innerHTML=s.key.configured?`Key: <b>${esc(s.key.key_id)}</b><br>Public Base64: <code>${esc(s.key.public_key)}</code>`:'No signing key';choose();stages('')}function choose(){let d=devices[+document.querySelector('#device').value];if(!d)return;current.value=d.firmware_version;version.value=d.suggested_version}function selected(){let d=devices[+device.value];if(!d)throw Error('Select a device');return d}function show(x,ok=true){message.className=ok?'ok':'error';message.textContent=x}async function validateYaml(){try{let d=selected();show('Validating…');let r=await api('api/validate',{method:'POST',body:JSON.stringify(d)});log.textContent=r.log||'Configuration valid';show('YAML is valid')}catch(e){show(e.message,false)}}async function build(){try{let d=selected();let r=await api('api/build',{method:'POST',body:JSON.stringify({...d,version:version.value})});job=r.job_id;poll()}catch(e){show(e.message,false)}}async function poll(){try{let r=await api('api/jobs/'+job);stages(r.stage);log.textContent=(r.log||[]).join('\n');if(r.stage==='ready'){show('Published firmware '+r.version);await load()}else if(r.stage==='failed')show(r.error||'Build failed',false);else setTimeout(poll,1500)}catch(e){show(e.message,false)}}async function saveToken(){try{await api('api/settings/token',{method:'POST',body:JSON.stringify({token:token.value})});token.value='';show('Token stored')}catch(e){show(e.message,false)}}async function deleteToken(){try{await api('api/settings/token',{method:'DELETE'});show('Token removed')}catch(e){show(e.message,false)}}async function importKey(){try{await api('api/settings/key/import',{method:'POST',body:JSON.stringify({pem:pem.value,key_id:keyid.value})});pem.value='';show('Signing key imported');load()}catch(e){show(e.message,false)}}load().catch(e=>show(e.message,false));</script></body></html>'''


class Handler(BaseHTTPRequestHandler):
    builder: Builder
    def _trusted(self) -> bool:
        return self.client_address[0] in {"127.0.0.1", "172.30.32.2"} or (os.environ.get("ALLOW_TEST_CLIENTS") == "1" and self.client_address[0] in {"172.17.0.1", "172.18.0.1"})
    def do_GET(self) -> None:
        if not self._trusted(): self._json(HTTPStatus.FORBIDDEN, {"error": "ingress_only"}); return
        path = urlparse(self.path).path.rstrip("/") or "/"
        if path == "/healthz": self._json(HTTPStatus.OK, {"status": "ok"})
        elif path == "/": self._body(HTTPStatus.OK, "text/html; charset=utf-8", HTML.encode())
        elif path == "/api/state": self._json(HTTPStatus.OK, {"devices": self.builder.list_devices(), "key": public_key_info(), "token_configured": TOKEN_FILE.is_file(), "repository": load_settings()["repository"]})
        elif (match := re.fullmatch(r"/api/jobs/([0-9a-f-]{36})", path)):
            job = self.builder.jobs.get(match.group(1)); self._json(HTTPStatus.OK if job else HTTPStatus.NOT_FOUND, asdict(job) if job else {"error": "unknown_job"})
        else: self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
    def do_POST(self) -> None:
        if not self._trusted(): self._json(HTTPStatus.FORBIDDEN, {"error": "ingress_only"}); return
        try:
            raw = self._read_json(); path = urlparse(self.path).path
            if path == "/api/validate": self._json(HTTPStatus.OK, self.builder.validate(raw.get("yaml_file"), raw.get("device_id")))
            elif path == "/api/build":
                job = self.builder.create_job(raw.get("yaml_file"), raw.get("device_id"), raw.get("version") or None); self._json(HTTPStatus.ACCEPTED, asdict(job))
            elif path == "/api/settings/token":
                token = raw.get("token");
                if not isinstance(token, str) or not 20 <= len(token) <= 512 or any(c.isspace() for c in token): raise ValueError("Invalid token")
                atomic_private_file(TOKEN_FILE, token.encode()); self._json(HTTPStatus.OK, {"stored": True})
            elif path == "/api/settings/key/import":
                with self.builder.lock:
                    if self.builder.active_devices: raise RuntimeError("Cannot change signing key during an active build")
                pem, key_id = raw.get("pem"), raw.get("key_id")
                if not isinstance(pem, str) or len(pem) > 16384 or not isinstance(key_id, str) or KEY_ID_PATTERN.fullmatch(key_id) is None: raise ValueError("Invalid key import")
                key = serialization.load_pem_private_key(pem.encode(), password=None)
                if not isinstance(key, Ed25519PrivateKey): raise ValueError("Key must be Ed25519")
                atomic_private_file(KEY_FILE, key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
                settings = load_settings(); save_settings(settings["repository"], key_id); self._json(HTTPStatus.OK, public_key_info())
            elif path == "/api/settings/repository":
                settings = load_settings(); save_settings(raw.get("repository"), settings["key_id"]); self._json(HTTPStatus.OK, {"repository": load_settings()["repository"]})
            else: self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
        except RuntimeError as exc: self._json(HTTPStatus.CONFLICT, {"error": redact(str(exc))[:240]})
        except Exception as exc: self._json(HTTPStatus.BAD_REQUEST, {"error": redact(str(exc))[:240]})
    def do_DELETE(self) -> None:
        if not self._trusted(): self._json(HTTPStatus.FORBIDDEN, {"error": "ingress_only"}); return
        if urlparse(self.path).path != "/api/settings/token": self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"}); return
        if TOKEN_FILE.exists(): TOKEN_FILE.unlink()
        self._json(HTTPStatus.OK, {"stored": False})
    def _read_json(self) -> dict[str, Any]:
        if self.headers.get_content_type() != "application/json": raise ValueError("Content-Type must be application/json")
        length = int(self.headers.get("Content-Length", "0"))
        if not 1 <= length <= MAX_BODY: raise ValueError("Invalid request size")
        raw = json.loads(self.rfile.read(length).decode("utf-8"))
        if not isinstance(raw, dict): raise ValueError("JSON object required")
        return raw
    def _json(self, status: HTTPStatus, value: dict[str, Any]) -> None: self._body(status, "application/json", json.dumps(value, separators=(",", ":")).encode())
    def _body(self, status: HTTPStatus, content_type: str, body: bytes) -> None:
        self.send_response(status); self.send_header("Content-Type", content_type); self.send_header("Content-Length", str(len(body))); self.send_header("Cache-Control", "no-store"); self.send_header("X-Content-Type-Options", "nosniff"); self.send_header("Content-Security-Policy", "default-src 'self' 'unsafe-inline'"); self.end_headers(); self.wfile.write(body)
    def log_message(self, fmt: str, *args: Any) -> None: print(f"builder-web {self.client_address[0]} {redact(fmt % args)}")


def main() -> None:
    for path in (DATA_DIR, DATA_DIR / "keys", DATA_DIR / "secrets", DATA_DIR / "jobs", WORK_ROOT): path.mkdir(parents=True, exist_ok=True, mode=0o700)
    Handler.builder = Builder()
    server = ThreadingHTTPServer(("0.0.0.0", 8099), Handler)
    print("ESP Anywhere Builder Ingress service listening on 8099")
    server.serve_forever()

if __name__ == "__main__": main()
