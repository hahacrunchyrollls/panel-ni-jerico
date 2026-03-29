import base64
import copy
import hashlib
import html
import json
import os
import re
import secrets
import shutil
import socket
import threading
import time
import urllib.parse
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from functools import lru_cache
from pathlib import Path

try:
    from zoneinfo import ZoneInfo
except ImportError:
    ZoneInfo = None

from flask import Flask, Response, jsonify, has_request_context, redirect, render_template_string, request, session
from markupsafe import Markup


IS_VERCEL = bool(os.environ.get("VERCEL"))
PORT = int(os.environ.get("PORT", "8000"))
STATE_DIR = Path("/tmp/webmenu_state") if IS_VERCEL else Path.cwd() / ".webmenu_state"
VISITS_FILE = STATE_DIR / "visits.json"
CONFIG_FILE = STATE_DIR / "config.json"
COUNTS_FILE = STATE_DIR / "counts.json"
AUDIT_FILE = STATE_DIR / "audit.json"
COOLDOWN_FILE = STATE_DIR / "cooldowns.json"
SESSION_SECRET_FILE = STATE_DIR / "session_secret.txt"
README_FILE = Path.cwd() / "README.md"
FAVICON_SOURCE_URL = "https://raw.githubusercontent.com/hahacrunchyrollls/logo-s/refs/heads/main/aika.jpg"
NAVBAR_LOGO_URL = "https://raw.githubusercontent.com/hahacrunchyrollls/logo-s/refs/heads/main/aika.jpg"

CREATE_EXPIRY_DEFAULTS = {"ssh": 5, "vless": 3, "hysteria": 5, "wireguard": 2, "openvpn": 3}
DAILY_ACCOUNT_LIMIT_DEFAULT = 30
CREATE_COOLDOWN_SECONDS = 600
MAX_VLESS_BYPASS_OPTIONS = 30
SERVER_HEALTH_CACHE_TTL = 15
SERVER_HEALTH_TIMEOUT = 2
REMOTE_PANEL_CONFIG_CACHE_TTL = 15
REMOTE_PANEL_STATE_CACHE_TTL = 3
BACKEND_SUMMARY_CACHE_TTL = 5
BACKEND_STATUS_SUMMARY_CACHE_TTL = 5
BACKEND_LOCATION_CACHE_TTL = 3600
ADMIN_ACCOUNT_GROUPS_CACHE_TTL = 10
PANEL_VISIT_SYNC_MIN_INTERVAL = 10
SUPPORTED_IMAGE_MIMES = {"image/png", "image/jpeg", "image/webp", "image/gif", "image/svg+xml"}
ADS_ENABLED = str(os.environ.get("ENABLE_ADS", "")).strip().lower() in {"1", "true", "yes", "on"}
DAILY_RESET_TIME_LABEL = "12:00 AM PH time"
TURNSTILE_VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
TURNSTILE_TIMEOUT_SECONDS = 8
try:
    PHILIPPINE_TIMEZONE = ZoneInfo("Asia/Manila") if ZoneInfo is not None else None
except Exception:
    PHILIPPINE_TIMEZONE = None

SERVICE_META = [
    ("ssh", "SSH", "https://raw.githubusercontent.com/hahacrunchyrollls/logo-s/refs/heads/main/icon-ssh.png"),
    ("vless", "VLESS", "https://raw.githubusercontent.com/hahacrunchyrollls/logo-s/refs/heads/main/icon-v2ray.png"),
    ("hysteria", "HYSTERIA", "https://raw.githubusercontent.com/hahacrunchyrollls/logo-s/refs/heads/main/icon-hysteria.png"),
    ("wireguard", "WIREGUARD", "https://raw.githubusercontent.com/hahacrunchyrollls/logo-s/refs/heads/main/icon-wireguard.png"),
    ("openvpn", "OPENVPN", "https://raw.githubusercontent.com/hahacrunchyrollls/logo-s/refs/heads/main/icon-openvpn.png"),
]
STATUS_SERVICE_ORDER = [
    "SSH",
    "DNSTT",
    "SQUID",
    "WEBSOCKET",
    "SSL",
    "XRAY",
    "BADVPN-UDPGW",
    "HYSTERIA",
    "WIREGUARD",
    "SLIPSTREAM",
    "MULTIPLEXER",
    "OPENVPN",
]

state_lock = threading.Lock()
traffic_lock = threading.Lock()
server_health_lock = threading.Lock()
last_traffic_snapshot = {"time": None, "rx": 0, "tx": 0, "source": None}
server_health_cache = {}
panel_config_lock = threading.Lock()
panel_config_cache = {"loaded_at": 0.0, "config": None}
panel_state_lock = threading.Lock()
panel_state_cache = {"loaded_at": 0.0, "state": None}
backend_summary_lock = threading.Lock()
backend_summary_cache = {
    "loaded_at": 0.0,
    "counters": {
        "online_users": 0,
        "total_accounts": 0,
        "ssh_online_users": 0,
        "openvpn_online_users": 0,
        "online_entries": [],
    },
}
backend_status_summary_lock = threading.Lock()
backend_status_summary_cache = {}
backend_location_lock = threading.Lock()
backend_location_cache = {}
backend_location_refreshing = set()
backend_cache_lock = threading.Lock()
backend_cache = {"signature": None, "backends": [], "by_id": {}}
announcement_cache_lock = threading.Lock()
announcement_cache = {"stat": None, "exists": False, "raw": "", "html": ""}
admin_account_groups_lock = threading.Lock()
admin_account_groups_cache = {"loaded_at": 0.0, "groups": None}
panel_visit_sync_lock = threading.Lock()
panel_visit_sync_cache = {"last_synced_at": 0.0}

app = Flask(__name__)
app.url_map.strict_slashes = False


def _clone(value):
    return copy.deepcopy(value)


def stable_session_secret():
    explicit_secret = os.environ.get("FLASK_SECRET_KEY") or os.environ.get("SESSION_SECRET")
    if explicit_secret:
        return explicit_secret

    seed_parts = []
    for key in (
        "ADMIN_USERNAME",
        "ADMIN_PASSWORD",
        "SERVER_BACKENDS_JSON",
        "SERVER_API_URL",
        "SERVER_API_TOKEN",
        "SERVER_API_UR",
        "SERVER_URL",
    ):
        value = os.environ.get(key, "").strip()
        if value:
            seed_parts.append(f"{key}={value}")
    for index in range(1, 33):
        url_value = os.environ.get(f"SERVER_API_URL_{index}", "").strip()
        token_value = os.environ.get(f"SERVER_API_TOKEN_{index}", "").strip()
        if url_value:
            seed_parts.append(f"SERVER_API_URL_{index}={url_value}")
        if token_value:
            seed_parts.append(f"SERVER_API_TOKEN_{index}={token_value}")
    if seed_parts:
        digest = hashlib.sha256()
        for part in seed_parts:
            digest.update(part.encode("utf-8"))
            digest.update(b"\0")
        return digest.hexdigest()

    if not IS_VERCEL:
        try:
            SESSION_SECRET_FILE.parent.mkdir(parents=True, exist_ok=True)
            if SESSION_SECRET_FILE.exists():
                saved = SESSION_SECRET_FILE.read_text(encoding="utf-8").strip()
                if saved:
                    return saved
            generated = secrets.token_hex(32)
            SESSION_SECRET_FILE.write_text(generated, encoding="utf-8")
            return generated
        except Exception:
            pass

    fallback_seed = "|".join(
        [
            "fuji-webpanel",
            str(Path.cwd()),
            os.environ.get("VERCEL_PROJECT_PRODUCTION_URL", "").strip(),
            os.environ.get("VERCEL_URL", "").strip(),
        ]
    )
    return hashlib.sha256(fallback_seed.encode("utf-8")).hexdigest()


app.secret_key = stable_session_secret()


def ensure_state_dir():
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass


def load_json(path: Path, default):
    ensure_state_dir()
    candidates = [path, path.with_suffix(path.suffix + ".tmp")]
    ranked = []
    for candidate in candidates:
        try:
            ranked.append((candidate.stat().st_mtime, candidate))
        except Exception:
            continue
    for _, candidate in sorted(ranked, key=lambda item: item[0], reverse=True):
        try:
            with candidate.open("r", encoding="utf-8") as handle:
                return json.load(handle)
        except Exception:
            continue
    return _clone(default)


def save_json(path: Path, payload):
    ensure_state_dir()
    tmp = path.with_suffix(path.suffix + ".tmp")
    try:
        raw = json.dumps(payload)
        with tmp.open("w", encoding="utf-8") as handle:
            handle.write(raw)
        try:
            os.replace(tmp, path)
        except Exception:
            with path.open("w", encoding="utf-8") as handle:
                handle.write(raw)
            try:
                if tmp.exists():
                    tmp.unlink()
            except Exception:
                pass
        return True
    except Exception:
        return False


def _ph_now():
    if PHILIPPINE_TIMEZONE is not None:
        return datetime.now(PHILIPPINE_TIMEZONE)
    return datetime.utcnow() + timedelta(hours=8)


def _ph_date():
    return _ph_now().strftime("%Y-%m-%d")


def get_request_ip():
    if not has_request_context():
        return "127.0.0.1"
    forwarded = request.headers.get("X-Forwarded-For") or request.headers.get("X-Real-IP") or ""
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "127.0.0.1"


def current_host():
    if not has_request_context():
        return "localhost"
    host = request.headers.get("X-Forwarded-Host") or request.host or "localhost"
    return host.split(":")[0]


def current_year_label():
    return _ph_now().strftime("%Y")


def legal_last_updated_label():
    return _ph_now().strftime("%B %d, %Y").replace(" 0", " ")


def env_first(*names):
    for name in names:
        value = os.environ.get(name, "").strip()
        if value:
            return value
    return ""


def turnstile_site_key():
    return env_first("CLOUDFLARE_TURNSTILE_SITE_KEY", "TURNSTILE_SITE_KEY")


def turnstile_secret_key():
    return env_first("CLOUDFLARE_TURNSTILE_SECRET_KEY", "TURNSTILE_SECRET_KEY")


def turnstile_configured():
    return bool(turnstile_site_key() and turnstile_secret_key())


def turnstile_setup_message():
    return "Account creation is temporarily unavailable while the site security check is being configured."


def turnstile_error_message(error_codes=None):
    codes = {str(code or "").strip().lower() for code in (error_codes or []) if str(code or "").strip()}
    if not codes:
        return "Captcha verification failed. Please try again."
    if "timeout-or-duplicate" in codes:
        return "Captcha expired or was already used. Please complete it again."
    if "missing-input-response" in codes or "invalid-input-response" in codes:
        return "Complete the captcha before creating your account."
    if "missing-input-secret" in codes or "invalid-input-secret" in codes:
        return turnstile_setup_message()
    return "Captcha verification failed. Please try again."


def verify_turnstile_response(token, remote_ip=""):
    if not turnstile_configured():
        return False, turnstile_setup_message()
    token = str(token or "").strip()
    if not token:
        return False, "Complete the captcha before creating your account."
    payload = {"secret": turnstile_secret_key(), "response": token}
    remote_ip = str(remote_ip or "").strip()
    if remote_ip:
        payload["remoteip"] = remote_ip
    encoded = urllib.parse.urlencode(payload).encode("utf-8")
    req = urllib.request.Request(
        TURNSTILE_VERIFY_URL,
        data=encoded,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(req, timeout=TURNSTILE_TIMEOUT_SECONDS) as response:
            raw = response.read().decode("utf-8")
        data = json.loads(raw)
    except Exception:
        return False, "Captcha verification is unavailable right now. Please try again."
    if bool(data.get("success")):
        return True, ""
    return False, turnstile_error_message(data.get("error-codes"))


def configured_server_api_url():
    return env_first("SERVER_API_URL", "SERVER_API_UR", "SERVER_URL").rstrip("/")


def configured_server_api_token():
    return env_first("SERVER_API_TOKEN", "API_TOKEN")


def load_numbered_backends():
    indexed = []
    indices = set()
    for key in os.environ:
        match = re.fullmatch(r"SERVER_API_URL_(\d+)", key) or re.fullmatch(r"SERVER_API_UR_(\d+)", key) or re.fullmatch(r"SERVER_URL_(\d+)", key)
        if match:
            indices.add(match.group(1))
    for index in sorted(indices, key=int):
        api_url = env_first(f"SERVER_API_URL_{index}", f"SERVER_API_UR_{index}", f"SERVER_URL_{index}").rstrip("/")
        api_token = env_first(f"SERVER_API_TOKEN_{index}", f"API_TOKEN_{index}")
        if not api_url or not api_token:
            continue
        backend_id = os.environ.get(f"SERVER_ID_{index}", "").strip() or f"server_{index}"
        label = (
            os.environ.get(f"SERVER_LABEL_{index}", "").strip()
            or os.environ.get(f"SERVER_COUNTRY_{index}", "").strip()
            or backend_id
        )
        indexed.append(
            (
                int(index),
                {
                    "id": backend_id,
                    "label": label,
                    "api_url": api_url,
                    "api_token": api_token,
                    "country": os.environ.get(f"SERVER_COUNTRY_{index}", "").strip(),
                    "countryCode": os.environ.get(f"SERVER_COUNTRY_CODE_{index}", "").strip(),
                    "city": os.environ.get(f"SERVER_CITY_{index}", "").strip(),
                    "lookup": os.environ.get(f"SERVER_LOOKUP_{index}", "").strip(),
                },
            )
        )
    indexed.sort(key=lambda item: item[0])
    return [backend for _, backend in indexed]


def default_panel_config():
    return {
        "daily_limit": DAILY_ACCOUNT_LIMIT_DEFAULT,
        "create_expiry": dict(CREATE_EXPIRY_DEFAULTS),
        "vless_bypass_options": [],
        "updated_at": 0,
    }


def load_config():
    local_config = load_local_panel_config()
    if backend_configured() and (IS_VERCEL or int(local_config.get("updated_at", 0) or 0) == 0):
        remote_config = load_remote_panel_config()
        if remote_config and int(remote_config.get("updated_at", 0) or 0) >= int(local_config.get("updated_at", 0) or 0):
            return remote_config
    return local_config


def _backend_env_signature():
    relevant = []
    for key in sorted(os.environ):
        if key.startswith("SERVER_") or key == "API_TOKEN" or re.fullmatch(r"API_TOKEN_\d+", key):
            relevant.append((key, os.environ.get(key, "")))
    return tuple(relevant)


def _build_backends():
    backends = []
    raw = os.environ.get("SERVER_BACKENDS_JSON", "").strip()
    if raw:
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                parsed = parsed.get("servers", [])
            if isinstance(parsed, list):
                for index, item in enumerate(parsed):
                    if not isinstance(item, dict):
                        continue
                    api_url = str(item.get("api_url", "")).strip().rstrip("/")
                    api_token = str(item.get("api_token", "")).strip()
                    if not api_url or not api_token:
                        continue
                    backend_id = str(item.get("id") or item.get("key") or f"server_{index + 1}").strip()
                    label = str(item.get("label") or item.get("name") or item.get("country") or backend_id).strip()
                    backends.append(
                        {
                            "id": backend_id,
                            "label": label,
                            "api_url": api_url,
                            "api_token": api_token,
                            "country": str(item.get("country", "")).strip(),
                            "countryCode": str(item.get("countryCode", item.get("flag_code", ""))).strip(),
                            "city": str(item.get("city", "")).strip(),
                            "lookup": str(item.get("lookup", "")).strip(),
                        }
                    )
        except Exception:
            pass
    if not backends:
        backends = load_numbered_backends()
    if not backends and configured_server_api_url() and configured_server_api_token():
        backends.append(
            {
                "id": "default",
                "label": os.environ.get("SERVER_LABEL", "Main Server").strip() or "Main Server",
                "api_url": configured_server_api_url(),
                "api_token": configured_server_api_token(),
                "country": os.environ.get("SERVER_COUNTRY", "").strip(),
                "countryCode": os.environ.get("SERVER_COUNTRY_CODE", "").strip(),
                "city": os.environ.get("SERVER_CITY", "").strip(),
                "lookup": os.environ.get("SERVER_LOOKUP", "").strip(),
            }
        )
    return backends


def load_backends():
    signature = _backend_env_signature()
    with backend_cache_lock:
        if backend_cache.get("signature") == signature:
            return _clone(backend_cache.get("backends", []))
    backends = _build_backends()
    by_id = {str(backend.get("id", "")).strip(): dict(backend) for backend in backends if str(backend.get("id", "")).strip()}
    with backend_cache_lock:
        backend_cache["signature"] = signature
        backend_cache["backends"] = _clone(backends)
        backend_cache["by_id"] = by_id
    return _clone(backends)


def backend_by_id(backend_id):
    backend_key = str(backend_id or "").strip()
    if not backend_key:
        return None
    signature = _backend_env_signature()
    with backend_cache_lock:
        if backend_cache.get("signature") == signature and backend_key in backend_cache.get("by_id", {}):
            return dict(backend_cache["by_id"][backend_key])
    load_backends()
    with backend_cache_lock:
        cached = backend_cache.get("by_id", {}).get(backend_key)
        return dict(cached) if isinstance(cached, dict) else None


def backend_configured():
    return bool(load_backends())


def normalize_panel_config(raw_config):
    config = raw_config if isinstance(raw_config, dict) else {}
    normalized = default_panel_config()
    raw_expiry = config.get("create_expiry")
    if not isinstance(raw_expiry, dict):
        raw_expiry = {}
    for service, default in CREATE_EXPIRY_DEFAULTS.items():
        try:
            normalized["create_expiry"][service] = max(1, min(int(raw_expiry.get(service, default)), 3650))
        except Exception:
            normalized["create_expiry"][service] = default
    raw_bypass_options = config.get("vless_bypass_options")
    if raw_bypass_options is None and "bypass_options" in config:
        raw_bypass_options = config.get("bypass_options")
    normalized["vless_bypass_options"] = normalize_vless_bypass_options(raw_bypass_options)
    try:
        normalized["daily_limit"] = max(1, min(int(config.get("daily_limit", DAILY_ACCOUNT_LIMIT_DEFAULT)), 999))
    except Exception:
        normalized["daily_limit"] = DAILY_ACCOUNT_LIMIT_DEFAULT
    try:
        normalized["updated_at"] = max(int(config.get("updated_at", 0) or 0), 0)
    except Exception:
        normalized["updated_at"] = 0
    return normalized


def load_local_panel_config():
    return normalize_panel_config(load_json(CONFIG_FILE, default_panel_config()))


def cache_panel_config(config):
    normalized = normalize_panel_config(config)
    with panel_config_lock:
        panel_config_cache["loaded_at"] = time.time()
        panel_config_cache["config"] = dict(normalized)
    return normalized


def load_remote_panel_config(force=False):
    if not backend_configured():
        return None
    now = time.time()
    with panel_config_lock:
        cached = panel_config_cache.get("config")
        loaded_at = float(panel_config_cache.get("loaded_at", 0.0) or 0.0)
        if cached and not force and now - loaded_at < REMOTE_PANEL_CONFIG_CACHE_TTL:
            return dict(cached)
    best_config = None
    best_updated_at = -1
    for backend in load_backends():
        try:
            data = backend_request_for(backend, "/panel-config", payload=None, method="GET")
        except Exception:
            continue
        candidate = normalize_panel_config(data.get("config", data) if isinstance(data, dict) else {})
        updated_at = int(candidate.get("updated_at", 0) or 0)
        if best_config is None or updated_at >= best_updated_at:
            best_config = candidate
            best_updated_at = updated_at
    if best_config:
        save_json(CONFIG_FILE, best_config)
        cache_panel_config(best_config)
    return best_config


def push_panel_config_to_backends(config):
    if not backend_configured():
        return True
    normalized = normalize_panel_config(config)
    successful_syncs = 0
    latest_config = normalized
    for backend in load_backends():
        try:
            data = backend_request_for(backend, "/panel-config", payload=normalized, method="POST")
            successful_syncs += 1
            if isinstance(data, dict) and isinstance(data.get("config"), dict):
                latest_config = normalize_panel_config(data["config"])
        except Exception:
            continue
    if successful_syncs:
        save_json(CONFIG_FILE, latest_config)
        cache_panel_config(latest_config)
    return successful_syncs > 0


def save_panel_config(config):
    normalized = normalize_panel_config(config)
    normalized["updated_at"] = max(int(time.time()), int(normalized.get("updated_at", 0) or 0))
    local_ok = save_json(CONFIG_FILE, normalized)
    cache_panel_config(normalized)
    if not backend_configured():
        return local_ok
    remote_ok = push_panel_config_to_backends(normalized)
    if IS_VERCEL:
        return bool(local_ok and remote_ok)
    return bool(local_ok or remote_ok)


def default_counts_state():
    return {"date": _ph_date(), "counts": {}}


def normalize_counts_state(raw_data, today=None):
    today = today or _ph_date()
    data = raw_data if isinstance(raw_data, dict) else {}
    date_label = str(data.get("date", "") or "").strip() or today
    raw_counts = data.get("counts", {})
    counts = {}
    if isinstance(raw_counts, dict):
        if raw_counts and all(not isinstance(value, dict) for value in raw_counts.values()):
            raw_counts = {"default": raw_counts}
        for backend_id, bucket in raw_counts.items():
            backend_key = str(backend_id or "").strip() or "default"
            if not isinstance(bucket, dict):
                continue
            normalized_bucket = {}
            for service, value in bucket.items():
                service_key = str(service or "").strip()
                if not service_key:
                    continue
                try:
                    amount = max(int(value or 0), 0)
                except Exception:
                    continue
                if amount:
                    normalized_bucket[service_key] = amount
            if normalized_bucket:
                counts[backend_key] = normalized_bucket
    if date_label != today:
        date_label = today
        counts = {}
    return {"date": date_label, "counts": counts}


def merge_counts_state(primary, secondary):
    left = normalize_counts_state(primary)
    right = normalize_counts_state(secondary, today=left["date"])
    merged = {"date": left["date"], "counts": {}}
    for source in (left.get("counts", {}), right.get("counts", {})):
        for backend_id, bucket in source.items():
            merged_bucket = merged["counts"].setdefault(backend_id, {})
            for service, amount in (bucket or {}).items():
                merged_bucket[service] = max(int(merged_bucket.get(service, 0) or 0), int(amount or 0))
    merged["counts"] = {backend_id: bucket for backend_id, bucket in merged["counts"].items() if bucket}
    return merged


def counts_state_from_panel_state(state):
    return normalize_counts_state({"date": (state or {}).get("daily_date"), "counts": (state or {}).get("daily_counts", {})})


def default_panel_state():
    counts_state = default_counts_state()
    return {
        "total_visits": 0,
        "total_accounts": 0,
        "updated_at": 0,
        "daily_date": counts_state["date"],
        "daily_counts": counts_state["counts"],
        "last_online_users": 0,
        "last_status_total_accounts": 0,
    }


def normalize_panel_state(raw_state):
    state = raw_state if isinstance(raw_state, dict) else {}
    normalized = default_panel_state()
    try:
        normalized["total_visits"] = max(int(state.get("total_visits", 0) or 0), 0)
    except Exception:
        normalized["total_visits"] = 0
    try:
        normalized["total_accounts"] = max(int(state.get("total_accounts", 0) or 0), 0)
    except Exception:
        normalized["total_accounts"] = 0
    try:
        normalized["updated_at"] = max(int(state.get("updated_at", 0) or 0), 0)
    except Exception:
        normalized["updated_at"] = 0
    counts_state = counts_state_from_panel_state(state)
    normalized["daily_date"] = counts_state["date"]
    normalized["daily_counts"] = counts_state["counts"]
    try:
        normalized["last_online_users"] = max(int(state.get("last_online_users", 0) or 0), 0)
    except Exception:
        normalized["last_online_users"] = 0
    try:
        normalized["last_status_total_accounts"] = max(int(state.get("last_status_total_accounts", 0) or 0), 0)
    except Exception:
        normalized["last_status_total_accounts"] = 0
    return normalized


def primary_panel_backend():
    backends = load_backends()
    return backends[0] if backends else None


def cache_panel_state(state):
    normalized = normalize_panel_state(state)
    with panel_state_lock:
        panel_state_cache["loaded_at"] = time.time()
        panel_state_cache["state"] = dict(normalized)
    return normalized


def update_local_panel_state(state):
    normalized = normalize_panel_state(state)
    with state_lock:
        visits = load_json(VISITS_FILE, {"total_visits": 0, "total_accounts": 0, "daily": {}})
        visits.setdefault("daily", {})
        visits["total_visits"] = max(int(visits.get("total_visits", 0) or 0), normalized["total_visits"])
        visits["total_accounts"] = max(int(visits.get("total_accounts", 0) or 0), normalized["total_accounts"])
        save_json(VISITS_FILE, visits)
        counts_state = merge_counts_state(load_json(COUNTS_FILE, default_counts_state()), {"date": normalized["daily_date"], "counts": normalized["daily_counts"]})
        save_json(COUNTS_FILE, counts_state)
    return cache_panel_state(normalized)


def get_cached_panel_state():
    with panel_state_lock:
        cached = panel_state_cache.get("state")
        return dict(cached) if isinstance(cached, dict) else None


def load_remote_panel_state(force=False):
    backend = primary_panel_backend()
    if not backend:
        return None
    now = time.time()
    with panel_state_lock:
        cached = panel_state_cache.get("state")
        loaded_at = float(panel_state_cache.get("loaded_at", 0.0) or 0.0)
        if cached and not force and now - loaded_at < REMOTE_PANEL_STATE_CACHE_TTL:
            return dict(cached)
    try:
        data = backend_request_for(backend, "/panel-state", payload=None, method="GET")
    except Exception:
        with panel_state_lock:
            cached = panel_state_cache.get("state")
            return dict(cached) if cached else None
    state = normalize_panel_state(data.get("state", data) if isinstance(data, dict) else {})
    update_local_panel_state(state)
    return state


def mutate_remote_panel_state(path, payload=None):
    backend = primary_panel_backend()
    if not backend:
        return None
    try:
        data = backend_request_for(backend, path, payload=payload or {}, method="POST")
    except Exception:
        return None
    state = normalize_panel_state(data.get("state", data) if isinstance(data, dict) else {})
    update_local_panel_state(state)
    return state


def _backend_cache_key(backend):
    backend = backend or {}
    return str(backend.get("id") or backend.get("api_url") or backend.get("lookup") or backend.get("label") or "").strip()


def load_backend_status_summary(backend, force=False):
    backend_key = _backend_cache_key(backend)
    if not backend_key:
        data = backend_request_for(backend, "/status", payload=None, method="GET")
        return extract_backend_status_summary(data, backend=backend)
    now = time.time()
    with backend_status_summary_lock:
        cached = backend_status_summary_cache.get(backend_key)
        if cached and not force and now - float(cached.get("loaded_at", 0.0) or 0.0) < BACKEND_STATUS_SUMMARY_CACHE_TTL:
            return _clone(cached.get("summary", _empty_backend_summary()))
    data = backend_request_for(backend, "/status", payload=None, method="GET")
    summary = extract_backend_status_summary(data, backend=backend)
    with backend_status_summary_lock:
        backend_status_summary_cache[backend_key] = {"loaded_at": time.time(), "summary": _clone(summary)}
    return summary


def should_sync_panel_visit():
    now = time.time()
    with panel_visit_sync_lock:
        last_synced_at = float(panel_visit_sync_cache.get("last_synced_at", 0.0) or 0.0)
        if now - last_synced_at < PANEL_VISIT_SYNC_MIN_INTERVAL:
            return False
        panel_visit_sync_cache["last_synced_at"] = now
        return True


def load_backend_summary_counters(force=False):
    if not backend_configured():
        return _empty_backend_summary()
    now = time.time()
    with backend_summary_lock:
        cached = backend_summary_cache.get("counters")
        loaded_at = float(backend_summary_cache.get("loaded_at", 0.0) or 0.0)
        if cached and not force and now - loaded_at < BACKEND_SUMMARY_CACHE_TTL:
            return _clone(cached)
    counters = _empty_backend_summary()
    successful = False
    backends = load_backends()
    max_workers = max(1, min(6, len(backends)))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [(backend, executor.submit(load_backend_status_summary, backend, force)) for backend in backends]
        for _backend, future in futures:
            try:
                extracted = future.result()
                counters["total_accounts"] += extracted["total_accounts"]
                counters["ssh_online_users"] += extracted["ssh_online_users"]
                counters["openvpn_online_users"] += extracted["openvpn_online_users"]
                counters["online_entries"].extend(extracted["online_entries"])
                successful = True
            except Exception:
                continue
    counters["online_users"] = counters["ssh_online_users"] + counters["openvpn_online_users"]
    counters["online_entries"] = _sort_online_entries(counters["online_entries"])
    if successful:
        with backend_summary_lock:
            backend_summary_cache["loaded_at"] = time.time()
            backend_summary_cache["counters"] = _clone(counters)
        mutate_remote_panel_state(
            "/panel-state/summary",
            {"online_users": counters["online_users"], "status_total_accounts": counters["total_accounts"]},
        )
        return counters
    remote_state = load_remote_panel_state()
    if remote_state:
        fallback = _empty_backend_summary()
        fallback.update(
            {
            "online_users": max(int(remote_state.get("last_online_users", 0) or 0), 0),
            "total_accounts": max(int(remote_state.get("last_status_total_accounts", 0) or 0), 0),
            }
        )
        return fallback
    with backend_summary_lock:
        cached = backend_summary_cache.get("counters")
        return _clone(cached) if cached else counters


def load_admin_backend_online_breakdown(force=False):
    totals = {"ssh_online_users": 0, "openvpn_online_users": 0, "online_users": 0}
    backends = load_backends()
    if not backends:
        return {"totals": totals, "servers": []}
    servers = []
    max_workers = max(1, min(6, len(backends)))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [(backend, executor.submit(load_backend_status_summary, backend, force)) for backend in backends]
        for backend, future in futures:
            entry = {
                "backend_id": str(backend.get("id", "") or "").strip(),
                "backend_label": admin_backend_label(backend),
                "backend_host": backend_host(backend),
                "ssh_online_users": 0,
                "openvpn_online_users": 0,
                "online_users": 0,
                "error": "",
            }
            try:
                summary = future.result()
                entry["ssh_online_users"] = max(int(summary.get("ssh_online_users", 0) or 0), 0)
                entry["openvpn_online_users"] = max(int(summary.get("openvpn_online_users", 0) or 0), 0)
                entry["online_users"] = entry["ssh_online_users"] + entry["openvpn_online_users"]
            except Exception as exc:
                entry["error"] = backend_error_message(exc)
            totals["ssh_online_users"] += entry["ssh_online_users"]
            totals["openvpn_online_users"] += entry["openvpn_online_users"]
            totals["online_users"] += entry["online_users"]
            servers.append(entry)
    return {"totals": totals, "servers": servers}


def get_cached_backend_summary_counters():
    with backend_summary_lock:
        cached = backend_summary_cache.get("counters")
        return _clone(cached) if cached else None


def clear_admin_account_groups_cache():
    with admin_account_groups_lock:
        admin_account_groups_cache["loaded_at"] = 0.0
        admin_account_groups_cache["groups"] = None


def load_main_online_stats(force=False):
    selected = explicitly_selected_backend()
    if selected:
        try:
            summary = load_backend_status_summary(selected, force=force)
            summary["scope"] = "selected"
            summary["scope_label"] = backend_display_label(selected)
            summary["scope_note"] = f"Selected: {backend_display_label(selected)}"
            return summary
        except Exception:
            pass
    summary = load_backend_summary_counters(force=force)
    summary["scope"] = "all"
    summary["scope_label"] = "All Servers"
    summary["scope_note"] = "All connected servers"
    if selected:
        summary["scope_note"] = f"{backend_display_label(selected)} is unavailable, showing all servers"
    return summary


def default_backend_id():
    options = load_backends()
    if not options:
        return None
    preferred = os.environ.get("DEFAULT_SERVER_ID", "").strip()
    for backend in options:
        if backend["id"] == preferred:
            return preferred
    return options[0]["id"]


def selected_backend_id():
    selected = explicitly_selected_backend_id()
    if selected:
        return selected
    return default_backend_id()


def explicitly_selected_backend_id():
    options = load_backends()
    if not options:
        return None
    valid_ids = {backend["id"] for backend in options}
    if has_request_context():
        selected = session.get("selected_backend_id")
        if selected in valid_ids:
            return selected
    return None


def has_explicit_backend_selection():
    return explicitly_selected_backend_id() is not None


def explicitly_selected_backend():
    return backend_by_id(explicitly_selected_backend_id())


def require_backend_selection():
    if has_explicit_backend_selection():
        return None
    return redirect("/main?error=" + urllib.parse.quote("Please choose a server first."), code=303)


def selected_backend():
    return backend_by_id(selected_backend_id())


def set_selected_backend(backend_id):
    if backend_by_id(backend_id) and has_request_context():
        session["selected_backend_id"] = backend_id
        return True
    return False


def clear_selected_backend():
    if has_request_context():
        session.pop("selected_backend_id", None)


def backend_host(backend=None):
    backend = backend or selected_backend()
    if backend:
        api_url = backend.get("api_url", "")
        if api_url:
            parsed = urllib.parse.urlsplit(api_url)
            if parsed.hostname:
                return parsed.hostname
    return current_host()


def backend_port(backend=None):
    backend = backend or selected_backend()
    if backend:
        api_url = backend.get("api_url", "")
        if api_url:
            parsed = urllib.parse.urlsplit(api_url)
            if parsed.port:
                return parsed.port
            if parsed.scheme == "https":
                return 443
            if parsed.scheme == "http":
                return 80
    return 0


def backend_health_url(backend=None):
    backend = backend or selected_backend()
    api_url = str((backend or {}).get("api_url", "")).strip()
    if not api_url:
        return ""
    parsed = urllib.parse.urlsplit(api_url)
    health_path = (parsed.path or "").rstrip("/") + "/healthz"
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, health_path, "", ""))


def backend_probe_hosts(backend=None):
    backend = backend or selected_backend()
    hosts = []
    for value in (str((backend or {}).get("lookup", "")).strip(), backend_host(backend)):
        candidate = value.strip().strip("/").strip()
        if not candidate:
            continue
        candidate = re.sub(r"^[a-z]+://", "", candidate, flags=re.IGNORECASE)
        candidate = candidate.split("/", 1)[0].split(":", 1)[0].strip()
        if candidate and candidate not in hosts:
            hosts.append(candidate)
    return hosts


def probe_backend_health(backend):
    host = backend_host(backend)
    port = backend_port(backend)
    payload = {
        "backend_id": str((backend or {}).get("id", "")).strip(),
        "host": host,
        "port": port,
        "alive": False,
        "latency_ms": None,
        "text": "Dead",
    }
    if not host:
        return payload

    health_url = backend_health_url(backend)
    start = time.perf_counter()
    try:
        request_obj = urllib.request.Request(
            health_url,
            headers={"User-Agent": "FUJI-VPN server health"},
            method="GET",
        )
        with urllib.request.urlopen(request_obj, timeout=SERVER_HEALTH_TIMEOUT) as response:
            body = response.read().decode("utf-8", errors="ignore")
        if body:
            try:
                data = json.loads(body)
                if isinstance(data, dict) and data.get("ok") is False:
                    raise RuntimeError(data.get("error") or "Health check failed")
            except json.JSONDecodeError:
                pass
        latency_ms = max(1, int((time.perf_counter() - start) * 1000))
        payload["alive"] = True
        payload["latency_ms"] = latency_ms
        payload["text"] = f"Alive • {latency_ms} ms"
        return payload
    except Exception:
        pass

    if not port:
        return payload

    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=SERVER_HEALTH_TIMEOUT):
            pass
        latency_ms = max(1, int((time.perf_counter() - start) * 1000))
        payload["alive"] = True
        payload["latency_ms"] = latency_ms
        payload["text"] = f"Alive • {latency_ms} ms"
        return payload
    except Exception:
        return payload


def probe_backend_health_metadata(backend):
    host = backend_host(backend)
    port = backend_port(backend)
    health_url = backend_health_url(backend)
    payload = {
        "backend_id": str((backend or {}).get("id", "")).strip(),
        "host": host,
        "port": port,
        "health_url": health_url,
        "probe_hosts": backend_probe_hosts(backend),
        "alive": False,
        "latency_ms": None,
        "text": "Dead",
        "source": "panel",
    }
    if not host:
        return payload

    start = time.perf_counter()
    try:
        request_obj = urllib.request.Request(
            health_url,
            headers={"User-Agent": "FUJI-VPN server health"},
            method="GET",
        )
        with urllib.request.urlopen(request_obj, timeout=SERVER_HEALTH_TIMEOUT) as response:
            body = response.read().decode("utf-8", errors="ignore")
        if body:
            try:
                data = json.loads(body)
                if isinstance(data, dict) and data.get("ok") is False:
                    raise RuntimeError(data.get("error") or "Health check failed")
            except json.JSONDecodeError:
                pass
        payload["alive"] = True
        payload["latency_ms"] = max(1, int((time.perf_counter() - start) * 1000))
        payload["text"] = f"Ping {payload['latency_ms']} ms"
        return payload
    except Exception:
        pass

    if not port:
        return payload

    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=SERVER_HEALTH_TIMEOUT):
            pass
        payload["alive"] = True
        payload["latency_ms"] = max(1, int((time.perf_counter() - start) * 1000))
        payload["text"] = f"Ping {payload['latency_ms']} ms"
        return payload
    except Exception:
        return payload


def get_backend_health(backend, force=False):
    backend_id = str((backend or {}).get("id", "")).strip()
    if not backend_id:
        return probe_backend_health_metadata(backend)
    now = time.time()
    with server_health_lock:
        cached = server_health_cache.get(backend_id)
        if cached and not force and now - cached.get("checked_at", 0) < SERVER_HEALTH_CACHE_TTL:
            return dict(cached.get("payload", {}))
    payload = probe_backend_health_metadata(backend)
    with server_health_lock:
        server_health_cache[backend_id] = {"checked_at": time.time(), "payload": dict(payload)}
    return payload


def get_all_backend_health_statuses(force=False):
    backends = load_backends()
    if not backends:
        return {}
    statuses = {}
    max_workers = min(6, len(backends))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [(backend["id"], executor.submit(get_backend_health, backend, force)) for backend in backends]
        for backend_id, future in futures:
            try:
                statuses[backend_id] = future.result()
            except Exception:
                statuses[backend_id] = {
                    "backend_id": backend_id,
                    "host": backend_host(next((item for item in backends if item["id"] == backend_id), None)),
                    "port": backend_port(next((item for item in backends if item["id"] == backend_id), None)),
                    "health_url": backend_health_url(next((item for item in backends if item["id"] == backend_id), None)),
                    "probe_hosts": backend_probe_hosts(next((item for item in backends if item["id"] == backend_id), None)),
                    "alive": False,
                    "latency_ms": None,
                    "text": "Dead",
                    "source": "panel",
                }
    return statuses


def _backend_base_display_label(backend=None, backend_geo=None):
    backend = backend or selected_backend()
    if not backend:
        return "Unknown"
    raw_label = str(backend.get("label", "")).strip()
    backend_id = str(backend.get("id", "")).strip()
    generic_label = (
        not raw_label
        or raw_label == backend_id
        or raw_label.lower() in {"server", "main server", "default"}
        or re.fullmatch(r"server[_\-\s]*\d+", raw_label, flags=re.IGNORECASE) is not None
    )
    if generic_label:
        backend_geo = backend_geo or backend_location(backend)
        country = str(backend.get("country") or backend_geo.get("country") or "").strip()
        if country and country.lower() != "unknown":
            return country
        city = str(backend.get("city") or backend_geo.get("city") or "").strip()
        if city:
            return city
    return raw_label or backend_id or backend_host(backend)


def build_backend_display_labels(backends=None, backend_locations=None):
    backends = list(backends or load_backends())
    backend_locations = backend_locations or {}
    base_labels = {}
    duplicate_totals = {}
    for backend in backends:
        backend_id = str(backend.get("id", "")).strip()
        base_label = _backend_base_display_label(backend, backend_locations.get(backend_id))
        base_labels[backend_id] = base_label
        duplicate_totals[base_label] = int(duplicate_totals.get(base_label, 0) or 0) + 1
    labels = {}
    seen_per_label = {}
    for backend in backends:
        backend_id = str(backend.get("id", "")).strip()
        base_label = base_labels.get(backend_id, "Unknown")
        if duplicate_totals.get(base_label, 0) <= 1:
            labels[backend_id] = base_label
            continue
        seen_per_label[base_label] = int(seen_per_label.get(base_label, 0) or 0) + 1
        labels[backend_id] = f"{base_label} {seen_per_label[base_label]}"
    return labels


def backend_display_label(backend=None):
    backend = backend or selected_backend()
    if not backend:
        return "Unknown"
    backend_id = str(backend.get("id", "")).strip()
    labels = build_backend_display_labels()
    return str(labels.get(backend_id) or _backend_base_display_label(backend) or "Unknown")


def backend_location(backend=None):
    backend = backend or selected_backend()
    if backend and backend.get("country") and backend.get("countryCode"):
        return {
            "country": backend.get("country", "Unknown"),
            "countryCode": backend.get("countryCode", ""),
            "city": backend.get("city", ""),
        }
    lookup = (backend or {}).get("lookup") or backend_host(backend)
    if not lookup:
        return {"country": "Unknown", "countryCode": "", "city": ""}
    cache_key = str((backend or {}).get("id") or lookup or "").strip()
    now = time.time()
    with backend_location_lock:
        cached = backend_location_cache.get(cache_key)
        if cached and now - float(cached.get("loaded_at", 0.0) or 0.0) < BACKEND_LOCATION_CACHE_TTL:
            return dict(cached.get("location", {"country": "Unknown", "countryCode": "", "city": ""}))
    try:
        if not re.match(r"^\d+\.\d+\.\d+\.\d+$", lookup):
            lookup = socket.gethostbyname(lookup)
    except Exception:
        pass
    try:
        with urllib.request.urlopen(f"http://ip-api.com/json/{urllib.parse.quote(lookup)}", timeout=2) as response:
            data = json.load(response)
        if data.get("status") != "success":
            return {"country": "Unknown", "countryCode": "", "city": ""}
        location = {
            "country": data.get("country", "Unknown"),
            "countryCode": data.get("countryCode", ""),
            "city": data.get("city", ""),
        }
        with backend_location_lock:
            backend_location_cache[cache_key] = {"loaded_at": time.time(), "location": dict(location)}
        return location
    except Exception:
        return {"country": "Unknown", "countryCode": "", "city": ""}


def backend_location_snapshot(backend=None):
    backend = backend or selected_backend()
    fallback = {
        "country": str((backend or {}).get("country", "") or "").strip() or "Unknown",
        "countryCode": str((backend or {}).get("countryCode", "") or "").strip(),
        "city": str((backend or {}).get("city", "") or "").strip(),
    }
    lookup = (backend or {}).get("lookup") or backend_host(backend)
    if not lookup:
        return fallback
    cache_key = str((backend or {}).get("id") or lookup or "").strip()
    now = time.time()
    with backend_location_lock:
        cached = backend_location_cache.get(cache_key)
        if cached and now - float(cached.get("loaded_at", 0.0) or 0.0) < BACKEND_LOCATION_CACHE_TTL:
            return dict(cached.get("location", fallback))
    return fallback


def backend_location_snapshots(backends=None):
    snapshots = {}
    for backend in list(backends or load_backends()):
        backend_id = str(backend.get("id", "")).strip()
        if backend_id:
            snapshots[backend_id] = backend_location_snapshot(backend)
    return snapshots


def warm_backend_location_cache_async(backends=None):
    candidates = []
    now = time.time()
    for backend in list(backends or load_backends()):
        if backend and backend.get("country") and backend.get("countryCode"):
            continue
        cache_key = str((backend or {}).get("id") or (backend or {}).get("lookup") or backend_host(backend) or "").strip()
        if not cache_key:
            continue
        with backend_location_lock:
            cached = backend_location_cache.get(cache_key)
            if cached and now - float(cached.get("loaded_at", 0.0) or 0.0) < BACKEND_LOCATION_CACHE_TTL:
                continue
            if cache_key in backend_location_refreshing:
                continue
            backend_location_refreshing.add(cache_key)
        candidates.append((cache_key, backend))
    if not candidates:
        return

    def worker(entries):
        try:
            for _cache_key, backend in entries:
                try:
                    backend_location(backend)
                except Exception:
                    continue
        finally:
            with backend_location_lock:
                for cache_key, _backend in entries:
                    backend_location_refreshing.discard(cache_key)

    threading.Thread(target=worker, args=(candidates,), daemon=True).start()


def backend_request_for(backend, path, payload=None, method="POST"):
    if not backend:
        raise RuntimeError(
            "No backend is configured. Set SERVER_BACKENDS_JSON, numbered SERVER_API_URL_n / SERVER_API_TOKEN_n pairs, or SERVER_API_URL / SERVER_API_TOKEN."
        )
    body = None
    headers = {"Authorization": "Bearer " + backend.get("api_token", "")}
    if has_request_context():
        client_ip = get_request_ip().strip()
        if client_ip:
            headers["X-Forwarded-For"] = client_ip
            headers["X-Real-IP"] = client_ip
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(backend.get("api_url", "").rstrip("/") + path, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            raw = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="ignore")
        try:
            parsed = json.loads(body)
            raise RuntimeError(parsed.get("error", body or f"HTTP {exc.code}"))
        except json.JSONDecodeError:
            raise RuntimeError(body or f"HTTP {exc.code}") from exc
    return json.loads(raw) if raw else {}


def backend_request(path, payload=None, method="POST"):
    return backend_request_for(selected_backend(), path, payload=payload, method=method)


def get_daily_account_limit():
    return int(load_config()["daily_limit"])


def set_daily_account_limit(value):
    try:
        limit = max(1, min(int(value), 999))
    except Exception:
        return False
    with state_lock:
        config = load_config()
        config["daily_limit"] = limit
        return save_panel_config(config)


def get_create_account_expiry(service=None):
    expiry = load_config()["create_expiry"]
    if service:
        return int(expiry.get(service, CREATE_EXPIRY_DEFAULTS.get(service, 3)))
    return expiry


def set_create_account_expiry(service, days):
    if service not in CREATE_EXPIRY_DEFAULTS:
        return False
    try:
        value = max(1, min(int(days), 3650))
    except Exception:
        return False
    with state_lock:
        config = load_config()
        config["create_expiry"][service] = value
        return save_panel_config(config)


def _clean_bypass_field(value, limit=255):
    return str(value or "").strip()[:limit]


def normalize_vless_bypass_options(raw_options):
    if isinstance(raw_options, dict):
        raw_options = raw_options.get("options", [])
    if not isinstance(raw_options, list):
        return []
    normalized = []
    seen_ids = set()
    for index, item in enumerate(raw_options, 1):
        if not isinstance(item, dict):
            continue
        name = _clean_bypass_field(item.get("name") or item.get("label"), 80)
        if not name:
            continue
        raw_id = _clean_bypass_field(item.get("id") or item.get("key"), 80)
        base_id = re.sub(r"[^a-z0-9_-]+", "_", (raw_id or name).lower()).strip("_") or f"bypass_{index}"
        option_id = base_id
        suffix = 2
        while option_id in seen_ids:
            option_id = f"{base_id}_{suffix}"
            suffix += 1
        seen_ids.add(option_id)
        tls = item.get("tls") if isinstance(item.get("tls"), dict) else {}
        nontls = item.get("nontls")
        if not isinstance(nontls, dict):
            nontls = item.get("non_tls")
        if not isinstance(nontls, dict):
            nontls = item.get("nonTls")
        if not isinstance(nontls, dict):
            nontls = {}
        normalized.append(
            {
                "id": option_id,
                "name": name,
                "tls": {
                    "address": _clean_bypass_field(tls.get("address")),
                    "host": _clean_bypass_field(tls.get("host")),
                    "sni": _clean_bypass_field(tls.get("sni")),
                },
                "nontls": {
                    "address": _clean_bypass_field(nontls.get("address")),
                    "host": _clean_bypass_field(nontls.get("host")),
                },
            }
        )
        if len(normalized) >= MAX_VLESS_BYPASS_OPTIONS:
            break
    return normalized


def get_vless_bypass_options():
    return list(load_config().get("vless_bypass_options", []))


def find_vless_bypass_option(option_id):
    option_id = str(option_id or "").strip()
    if not option_id:
        return None
    for option in get_vless_bypass_options():
        if option.get("id") == option_id:
            return option
    return None


def save_vless_bypass_options(raw_options):
    normalized = normalize_vless_bypass_options(raw_options)
    with state_lock:
        config = load_config()
        config["vless_bypass_options"] = normalized
        return save_panel_config(config), normalized


def set_vless_bypass_options_from_json(raw_json):
    try:
        parsed = json.loads(raw_json or "[]")
    except Exception:
        return False, []
    if not isinstance(parsed, list):
        return False, []
    return save_vless_bypass_options(parsed)


def load_counts(force_remote=False):
    data = normalize_counts_state(load_json(COUNTS_FILE, default_counts_state()))
    remote_state = load_remote_panel_state(force=force_remote) if force_remote else get_cached_panel_state()
    if remote_state:
        merged = merge_counts_state(data, counts_state_from_panel_state(remote_state))
        if merged != data:
            save_json(COUNTS_FILE, merged)
        return merged
    return data


def _sum_service_counts(counts):
    if not isinstance(counts, dict):
        return 0
    total = 0
    for value in counts.values():
        try:
            total += int(value)
        except Exception:
            continue
    return total


def get_daily_created_count(service=None, backend_id=None, force_remote=False):
    data = load_counts(force_remote=force_remote)
    backend_id = backend_id or selected_backend_id() or "default"
    counts = data.get("counts", {}).get(backend_id, {})
    if service:
        try:
            return int(counts.get(service, 0))
        except Exception:
            return 0
    return _sum_service_counts(counts)


def get_total_daily_created_count(service=None, force_remote=False):
    data = load_counts(force_remote=force_remote)
    total = 0
    for counts in data.get("counts", {}).values():
        if service:
            try:
                total += int((counts or {}).get(service, 0))
            except Exception:
                continue
        else:
            total += _sum_service_counts(counts)
    return total


def get_scoped_daily_created_count(service=None, backend_id=None, force_remote=False):
    return get_daily_created_count(service=service, backend_id=backend_id or selected_backend_id() or "default", force_remote=force_remote)


def increment_daily_created_count(service, backend_id=None):
    backend_id = backend_id or selected_backend_id() or "default"
    remote_state = mutate_remote_panel_state(
        "/panel-state/daily-account",
        {"service": service, "backend_id": backend_id, "amount": 1, "date": _ph_date()},
    )
    if remote_state:
        counts_state = counts_state_from_panel_state(remote_state)
        return int((counts_state.get("counts", {}).get(backend_id, {}) or {}).get(service, 0) or 0)
    with state_lock:
        data = normalize_counts_state(load_json(COUNTS_FILE, default_counts_state()))
        data["counts"].setdefault(backend_id, {})
        data["counts"][backend_id][service] = int(data["counts"][backend_id].get(service, 0) or 0) + 1
        save_json(COUNTS_FILE, data)
        return data["counts"][backend_id][service]


def load_visits(force_remote=False):
    data = load_json(VISITS_FILE, {"total_visits": 0, "total_accounts": 0, "daily": {}})
    data.setdefault("total_visits", 0)
    data.setdefault("total_accounts", 0)
    data.setdefault("daily", {})
    remote_state = load_remote_panel_state(force=force_remote) if force_remote else get_cached_panel_state()
    if remote_state:
        data["total_visits"] = max(int(data.get("total_visits", 0) or 0), int(remote_state.get("total_visits", 0) or 0))
        data["total_accounts"] = max(int(data.get("total_accounts", 0) or 0), int(remote_state.get("total_accounts", 0) or 0))
    return data


def _merge_remote_visit_state(remote_state):
    if not isinstance(remote_state, dict):
        return None
    with state_lock:
        data = load_json(VISITS_FILE, {"total_visits": 0, "total_accounts": 0, "daily": {}})
        data.setdefault("daily", {})
        data["total_visits"] = max(int(data.get("total_visits", 0) or 0), int(remote_state.get("total_visits", 0) or 0))
        save_json(VISITS_FILE, data)
        return data


def _sync_visit_count_remote():
    remote_state = mutate_remote_panel_state("/panel-state/visit", {})
    _merge_remote_visit_state(remote_state)


def bump_visit_count(async_remote=False):
    with state_lock:
        data = load_json(VISITS_FILE, {"total_visits": 0, "total_accounts": 0, "daily": {}})
        today = _ph_date()
        data["total_visits"] += 1
        day_bucket = data["daily"].setdefault(today, {"visits": 0})
        day_bucket["visits"] += 1
        keys = sorted(data["daily"].keys())[-14:]
        data["daily"] = {key: data["daily"][key] for key in keys}
        save_json(VISITS_FILE, data)
        local_snapshot = dict(data)
    if not should_sync_panel_visit():
        return local_snapshot
    if async_remote:
        threading.Thread(target=_sync_visit_count_remote, daemon=True).start()
        return local_snapshot
    remote_state = mutate_remote_panel_state("/panel-state/visit", {})
    return _merge_remote_visit_state(remote_state) or local_snapshot


def increment_total_accounts():
    with state_lock:
        data = load_json(VISITS_FILE, {"total_visits": 0, "total_accounts": 0, "daily": {}})
        current_total = int(data.get("total_accounts", 0) or 0)
        data["total_accounts"] = max(current_total + 1, get_total_daily_created_count())
        save_json(VISITS_FILE, data)
    remote_state = mutate_remote_panel_state("/panel-state/account", {"amount": 1})
    if remote_state:
        with state_lock:
            data = load_json(VISITS_FILE, {"total_visits": 0, "total_accounts": 0, "daily": {}})
            data["total_accounts"] = max(int(data.get("total_accounts", 0) or 0), int(remote_state.get("total_accounts", 0) or 0))
            save_json(VISITS_FILE, data)
            return data["total_accounts"]
    return load_visits(force_remote=False)["total_accounts"]


def get_display_total_accounts(visits=None, counters=None, force_remote=False):
    visits = visits if isinstance(visits, dict) else load_visits(force_remote=force_remote)
    remote_state = load_remote_panel_state(force=True) if force_remote else get_cached_panel_state()
    candidates = [get_total_daily_created_count(force_remote=force_remote)]
    try:
        candidates.append(max(int(visits.get("total_accounts", 0) or 0), 0))
    except Exception:
        pass
    if isinstance(remote_state, dict):
        try:
            candidates.append(max(int(remote_state.get("total_accounts", 0) or 0), 0))
        except Exception:
            pass
    return max(candidates) if candidates else 0


def load_create_cooldowns():
    data = load_json(COOLDOWN_FILE, {"ips": {}})
    ips = data.get("ips", {})
    normalized = {}
    if isinstance(ips, dict):
        for ip_address, services in ips.items():
            normalized[ip_address] = services if isinstance(services, dict) else {}
    data["ips"] = normalized
    return data


def get_create_cooldown_remaining(ip_address, service):
    if not ip_address or not service:
        return 0
    now = int(time.time())
    data = load_create_cooldowns()
    try:
        until = int(data.get("ips", {}).get(ip_address, {}).get(service, 0))
    except Exception:
        until = 0
    return max(until - now, 0)


def set_create_cooldown(ip_address, service, seconds=CREATE_COOLDOWN_SECONDS):
    if not ip_address or not service:
        return
    now = int(time.time())
    expires_at = now + int(seconds)
    with state_lock:
        data = load_create_cooldowns()
        cleaned = {}
        for key, service_map in data.get("ips", {}).items():
            active = {}
            if isinstance(service_map, dict):
                for protocol, value in service_map.items():
                    try:
                        expiry = int(value)
                    except Exception:
                        continue
                    if expiry > now:
                        active[protocol] = expiry
            if active:
                cleaned[key] = active
        cleaned.setdefault(ip_address, {})[service] = expires_at
        save_json(COOLDOWN_FILE, {"ips": cleaned})


def format_cooldown_label(seconds):
    total = max(int(seconds), 0)
    minutes, remainder = divmod(total, 60)
    if minutes and remainder:
        return f"{minutes}m {remainder}s"
    if minutes:
        return f"{minutes} minute" if minutes == 1 else f"{minutes} minutes"
    return f"{remainder} second" if remainder == 1 else f"{remainder} seconds"


def log_admin_event(action, status="success", details=None):
    events = load_json(AUDIT_FILE, {"events": []}).get("events", [])
    if not isinstance(events, list):
        events = []
    events.append(
        {
            "time": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "action": str(action),
            "status": str(status),
            "ip": get_request_ip() if has_request_context() else "-",
            "details": details if isinstance(details, dict) else {},
        }
    )
    save_json(AUDIT_FILE, {"events": events[-100:]})


def recent_admin_events(limit=10):
    events = load_json(AUDIT_FILE, {"events": []}).get("events", [])
    if not isinstance(events, list):
        return []
    return list(reversed(events[-limit:]))


def admin_credentials_valid(username, password):
    expected_user = os.environ.get("ADMIN_USERNAME", "root")
    expected_password = os.environ.get("ADMIN_PASSWORD")
    return bool(expected_password) and username == expected_user and password == expected_password


def load_announcement_document():
    stat_key = None
    exists = False
    raw = ""
    html_output = "<div style='color:var(--error);font-weight:600;text-align:center;'>NO ANNOUNCEMENT!</div>"
    try:
        stat = README_FILE.stat()
        stat_key = (int(stat.st_mtime_ns), int(stat.st_size))
        exists = stat.st_size > 0
    except Exception:
        stat_key = ("missing", 0)
        exists = False
    with announcement_cache_lock:
        if announcement_cache.get("stat") == stat_key:
            return dict(announcement_cache)
    if exists:
        try:
            raw = README_FILE.read_text(encoding="utf-8").strip()
            exists = bool(raw)
        except Exception:
            raw = ""
            exists = False
    if exists:
        text = html.escape(raw)
        text = re.sub(r"(^|\n)### (.*)", r"\1<h3>\2</h3>", text)
        text = re.sub(r"(^|\n)## (.*)", r"\1<h2>\2</h2>", text)
        text = re.sub(r"(^|\n)# (.*)", r"\1<h1>\2</h1>", text)
        text = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", text)
        text = re.sub(r"\*(.+?)\*", r"<i>\1</i>", text)
        text = re.sub(r"\[(.+?)\]\((.+?)\)", r'<a href="\2" target="_blank">\1</a>', text)
        text = re.sub(
            r"(https?://[^\s<]+)",
            r'<a href="\1" target="_blank" style="color:#06b6d4;text-decoration:underline;">\1</a>',
            text,
        )
        html_output = text.replace("\n", "<br>")
    document = {"stat": stat_key, "exists": exists, "raw": raw, "html": html_output}
    with announcement_cache_lock:
        announcement_cache.update(document)
    return dict(document)


def announcement_exists():
    return bool(load_announcement_document().get("exists"))


def announcement_html():
    return str(load_announcement_document().get("html") or "<div style='color:var(--error);font-weight:600;text-align:center;'>NO ANNOUNCEMENT!</div>")


def format_expiry(timestamp):
    try:
        return datetime.fromtimestamp(int(timestamp)).strftime("%b %d, %Y %I:%M:%S %p")
    except Exception:
        return "N/A"


def backend_error_message(exc):
    try:
        return str(exc.reason)
    except Exception:
        pass
    try:
        return str(exc)
    except Exception:
        return "Backend request failed."


def find_backend_config(backend_id):
    return backend_by_id(backend_id)


def admin_backend_label(backend):
    backend = backend or {}
    display_label = str(backend_display_label(backend) or "").strip()
    if display_label:
        return display_label
    return backend_host(backend)


def _service_sort_rank(service):
    for index, (slug, _label, _icon) in enumerate(SERVICE_META):
        if slug == service:
            return index
    return len(SERVICE_META)


def normalize_admin_account(raw, backend):
    if not isinstance(raw, dict):
        return None
    service = str(raw.get("service", "") or "").strip().lower()
    if service not in CREATE_EXPIRY_DEFAULTS:
        return None
    username = str(raw.get("username", "") or "").strip()
    if not username:
        return None
    try:
        expires_at = int(raw.get("expires_at", 0) or 0)
    except Exception:
        expires_at = 0
    try:
        days_remaining = max(int(raw.get("days_remaining", 0) or 0), 0)
    except Exception:
        days_remaining = 0
    active = bool(raw.get("active", expires_at <= 0 or expires_at > int(time.time())))
    return {
        "service": service,
        "service_label": service_label(service),
        "username": username,
        "expires_at": expires_at,
        "days_remaining": days_remaining,
        "active": active,
        "backend_id": backend.get("id", ""),
        "backend_label": admin_backend_label(backend),
        "backend_host": backend_host(backend),
    }


def load_backend_admin_accounts(backend):
    result = {
        "backend": backend,
        "backend_id": backend.get("id", ""),
        "backend_label": admin_backend_label(backend),
        "backend_host": backend_host(backend),
        "accounts": [],
        "error": "",
    }
    try:
        data = backend_request_for(backend, "/accounts", payload=None, method="GET")
        raw_accounts = data.get("accounts", []) if isinstance(data, dict) else []
        accounts = []
        for item in raw_accounts if isinstance(raw_accounts, list) else []:
            normalized = normalize_admin_account(item, backend)
            if normalized:
                accounts.append(normalized)
        accounts.sort(key=lambda item: (_service_sort_rank(item["service"]), item["username"].lower(), item["expires_at"]))
        result["accounts"] = accounts
    except Exception as exc:
        result["error"] = backend_error_message(exc)
    return result


def load_admin_account_groups(force=False):
    backends = load_backends()
    if not backends:
        return []
    now = time.time()
    with admin_account_groups_lock:
        cached = admin_account_groups_cache.get("groups")
        loaded_at = float(admin_account_groups_cache.get("loaded_at", 0.0) or 0.0)
        if cached is not None and not force and now - loaded_at < ADMIN_ACCOUNT_GROUPS_CACHE_TTL:
            return _clone(cached)
    groups = []
    max_workers = min(6, len(backends))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [(backend, executor.submit(load_backend_admin_accounts, backend)) for backend in backends]
        for backend, future in futures:
            try:
                groups.append(future.result())
            except Exception as exc:
                groups.append(
                    {
                        "backend": backend,
                        "backend_id": backend.get("id", ""),
                        "backend_label": admin_backend_label(backend),
                        "backend_host": backend_host(backend),
                        "accounts": [],
                        "error": backend_error_message(exc),
                    }
                )
    with admin_account_groups_lock:
        admin_account_groups_cache["loaded_at"] = time.time()
        admin_account_groups_cache["groups"] = _clone(groups)
    return groups


def format_days_remaining_label(days_remaining, active):
    if not active:
        return "Expired"
    try:
        days = max(int(days_remaining or 0), 0)
    except Exception:
        days = 0
    if days <= 0:
        return "Less than 1 day"
    return f"{days} day left" if days == 1 else f"{days} days left"


def default_account_expiry_days(account):
    service = str((account or {}).get("service", "") or "").strip().lower()
    try:
        days = max(int((account or {}).get("days_remaining", 0) or 0), 0)
    except Exception:
        days = 0
    if days:
        return days
    return int(CREATE_EXPIRY_DEFAULTS.get(service, 1))


def render_admin_account_card(account):
    username = str(account.get("username", "") or "").strip()
    service = str(account.get("service", "") or "").strip().lower()
    backend_id = str(account.get("backend_id", "") or "").strip()
    service_name = html.escape(str(account.get("service_label", service.upper()) or service.upper()))
    username_display = html.escape(username)
    username_attr = html.escape(username, quote=True)
    service_attr = html.escape(service, quote=True)
    backend_attr = html.escape(backend_id, quote=True)
    expires_at = int(account.get("expires_at", 0) or 0)
    expires_text = format_expiry(expires_at) if expires_at > 0 else "No expiry saved"
    remaining_text = format_days_remaining_label(account.get("days_remaining", 0), account.get("active", False))
    status_label = "Active" if account.get("active") else "Expired"
    status_style = "background:rgba(16,185,129,.12);color:var(--success);" if account.get("active") else "background:rgba(239,68,68,.12);color:var(--error);"
    confirm_text = json.dumps(f"Remove {username} from {service_name} on {account.get('backend_label', 'this server')}?")
    return f"""
<div class="link-box" data-admin-account-card data-service="{service_attr}" style="display:flex;flex-direction:column;gap:.9rem;">
  <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:12px;flex-wrap:wrap;">
    <div>
      <div style="font-weight:800;font-size:1.05rem;">{username_display}</div>
      <div style="color:var(--text-muted);font-size:.92rem;">{service_name}</div>
    </div>
    <div style="padding:6px 10px;border-radius:999px;border:2px solid var(--card-border);{status_style}font-weight:700;">{status_label}</div>
  </div>
  <div style="color:var(--text-secondary);font-size:.94rem;display:grid;gap:6px;">
    <div><strong>Expires:</strong> {html.escape(expires_text)}</div>
    <div><strong>Remaining:</strong> {html.escape(remaining_text)}</div>
  </div>
  <form method="POST" action="/admin" style="margin:0;">
    <input type="hidden" name="action" value="update_account_expiry">
    <input type="hidden" name="backend_id" value="{backend_attr}">
    <input type="hidden" name="service" value="{service_attr}">
    <input type="hidden" name="username" value="{username_attr}">
    <div class="form-group" style="margin-bottom:.7rem;">
      <label class="form-label" style="font-size:.9rem;">New expiration in days from now</label>
      <div class="form-input-container" style="max-width:none;"><input type="number" name="days" min="1" max="3650" value="{default_account_expiry_days(account)}"></div>
    </div>
    <button type="submit" style="width:100%;max-width:none;"><i class="fa-solid fa-calendar-check"></i> Change Expiration</button>
  </form>
  <form method="POST" action="/admin" style="margin:0;" onsubmit='return confirm({confirm_text});'>
    <input type="hidden" name="action" value="delete_account">
    <input type="hidden" name="backend_id" value="{backend_attr}">
    <input type="hidden" name="service" value="{service_attr}">
    <input type="hidden" name="username" value="{username_attr}">
    <button type="submit" style="width:100%;max-width:none;background:linear-gradient(180deg,#fff5f5 0%,#ffdfe4 100%);color:var(--error);border:3px solid rgba(127,29,29,.35);box-shadow:4px 4px 0 rgba(127,29,29,.18);"><i class="fa-solid fa-trash"></i> Remove Account</button>
  </form>
</div>"""


def render_admin_account_manager(force=False):
    groups = load_admin_account_groups(force=force)
    if not groups:
        return """
<div data-admin-account-manager-root style="margin-top:1.2rem;">
  <div class="link-box">
    <div style="font-weight:700;margin-bottom:.45rem;">Account Manager</div>
    <div style="color:var(--text-secondary);">Connect at least one backend to list and manage SSH, VLESS, Hysteria, WireGuard, and OpenVPN accounts.</div>
  </div>
</div>"""
    protocol_options = ['<option value="all" selected>All</option>']
    for service, label, _icon in SERVICE_META:
        protocol_options.append(f'<option value="{html.escape(service, quote=True)}">{html.escape(label)}</option>')
    sections = []
    for group in groups:
        backend_label = html.escape(str(group.get("backend_label", "Server") or "Server"))
        backend_host_text = html.escape(str(group.get("backend_host", "") or "Unknown host"))
        accounts = list(group.get("accounts", []))
        error = str(group.get("error", "") or "").strip()
        section_attrs = 'data-admin-account-section data-account-total="0"'
        if error:
            body = f'<div class="success-msg" style="background:rgba(239,68,68,.1);border-left-color:var(--error);margin-top:1rem;"><i class="fa-solid fa-triangle-exclamation" style="color:var(--error);"></i><div>{html.escape(error)}</div></div>'
        elif not accounts:
            body = '<div class="success-msg" style="margin-top:1rem;background:rgba(124,16,39,.06);border-left-color:var(--warning);"><i class="fa-solid fa-circle-info" style="color:var(--warning);"></i><div>No managed accounts found on this server yet.</div></div>'
        else:
            service_order = {service: index for index, (service, _label, _icon) in enumerate(SERVICE_META)}
            ordered_accounts = sorted(
                accounts,
                key=lambda account: (
                    service_order.get(str(account.get("service", "") or "").strip().lower(), len(service_order)),
                    str(account.get("username", "") or "").strip().lower(),
                ),
            )
            summary_bits = []
            for service, label, _icon in SERVICE_META:
                service_total = sum(1 for account in ordered_accounts if account.get("service") == service)
                if service_total:
                    summary_bits.append(
                        f'<span class="server-badge" data-admin-service-summary data-service="{html.escape(service, quote=True)}" style="background:rgba(124,16,39,.08);">{html.escape(label)}: {service_total}</span>'
                    )
            summary_html = "".join(summary_bits)
            cards_html = "".join(render_admin_account_card(account) for account in ordered_accounts)
            section_attrs = f'data-admin-account-section data-account-total="{len(ordered_accounts)}"'
            body = f"""
<div style="margin-top:1rem;">
  <div style="display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap;margin-bottom:.75rem;">
    <div style="font-weight:800;">Server Accounts</div>
    <div style="color:var(--text-muted);font-size:.92rem;"><span data-admin-account-visible-total>{len(ordered_accounts)}</span> <span data-admin-account-count-label>total</span></div>
  </div>
  {'<div style="display:flex;flex-wrap:wrap;gap:8px;margin-bottom:.9rem;">' + summary_html + '</div>' if summary_html else ''}
  <div class="admin-account-grid" data-admin-account-grid>{cards_html}</div>
  <div class="success-msg" data-admin-account-filter-empty style="display:none;margin-top:1rem;background:rgba(124,16,39,.06);border-left-color:var(--warning);"><i class="fa-solid fa-circle-info" style="color:var(--warning);"></i><div>No matching accounts for this protocol on this server.</div></div>
</div>"""
        sections.append(
            f"""
<div class="link-box" {section_attrs} style="margin-top:1rem;">
  <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:14px;flex-wrap:wrap;">
    <div>
      <div style="font-weight:800;font-size:1.05rem;">{backend_label}</div>
      <div style="color:var(--text-muted);font-size:.92rem;">{backend_host_text}</div>
    </div>
  </div>
  {body}
</div>"""
        )
    return (
        """
<div style="margin-top:1.2rem;" data-admin-account-manager-root>
  <div style="font-weight:700;margin-bottom:.4rem;">Account Manager</div>
  <div style="color:var(--text-secondary);margin-bottom:.4rem;">Review live SSH, VLESS, Hysteria, WireGuard, and OpenVPN accounts on every connected backend, remove accounts instantly, or set a new expiration in days from now.</div>
  <div class="link-box" style="margin-top:1rem;">
    <form style="margin:0;align-items:flex-start;">
      <div class="form-group" style="margin:0;align-items:flex-start;text-align:left;">
        <label class="form-label" style="margin-bottom:.55rem;text-align:left;max-width:none;"><i class="fa-solid fa-filter"></i> Sort by Protocol</label>
        <div class="form-input-container" style="justify-content:flex-start;max-width:320px;">
          <select data-admin-protocol-filter style="max-width:none;">
            """
        + "".join(protocol_options)
        + """
          </select>
        </div>
      </div>
    </form>
  </div>
  """
        + "".join(sections)
        + """
</div>"""
    )


def guess_image_mime(url):
    lower = urllib.parse.urlsplit(url or "").path.lower()
    if lower.endswith(".png"):
        return "image/png"
    if lower.endswith(".jpg") or lower.endswith(".jpeg"):
        return "image/jpeg"
    if lower.endswith(".webp"):
        return "image/webp"
    if lower.endswith(".gif"):
        return "image/gif"
    if lower.endswith(".svg"):
        return "image/svg+xml"
    return "application/octet-stream"


def detect_image_mime(payload):
    blob = payload or b""
    if blob.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if blob.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if blob[:6] in (b"GIF87a", b"GIF89a"):
        return "image/gif"
    if blob.startswith(b"RIFF") and blob[8:12] == b"WEBP":
        return "image/webp"
    if b"<svg" in blob[:512].lower():
        return "image/svg+xml"
    return ""


def decode_data_image_uri(source_url):
    if not (source_url or "").startswith("data:image/"):
        return b"", ""
    try:
        header, encoded = source_url.split(",", 1)
        mime = header[5:].split(";", 1)[0].strip() or "application/octet-stream"
        if ";base64" in header:
            payload = base64.b64decode(encoded)
        else:
            payload = urllib.parse.unquote_to_bytes(encoded)
        return payload, mime
    except Exception:
        return b"", ""


@lru_cache(maxsize=8)
def image_source_asset(source_url):
    source_url = (source_url or "").strip()
    if not source_url:
        return b"", ""
    payload, mime = decode_data_image_uri(source_url)
    if payload:
        if mime not in SUPPORTED_IMAGE_MIMES:
            mime = detect_image_mime(payload) or guess_image_mime(source_url)
        return payload, mime
    try:
        req = urllib.request.Request(source_url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=10) as response:
            payload = response.read()
            mime = response.headers.get_content_type() or ""
        if mime not in SUPPORTED_IMAGE_MIMES:
            mime = guess_image_mime(source_url)
        if mime not in SUPPORTED_IMAGE_MIMES:
            mime = detect_image_mime(payload)
        return payload, mime if mime in SUPPORTED_IMAGE_MIMES else "application/octet-stream"
    except Exception:
        return b"", ""


@lru_cache(maxsize=1)
def favicon_data_uri():
    payload, mime = image_source_asset(FAVICON_SOURCE_URL)
    if not payload or not mime:
        return ""
    encoded = base64.b64encode(payload).decode("ascii")
    return f"data:{mime};base64,{encoded}"


def strip_ansi(text):
    return re.sub(r"\x1B\[[0-?]*[ -/]*[@-~]", "", str(text or ""))


def format_ssh_details_text(raw_text):
    text = strip_ansi(raw_text).replace("\r", "\n")
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"-{10,}\s*", "\n", text)

    markers = [
        "PORTS INFORMATION",
        "SERVICES STATUS",
        "SSH:",
        "SSH + WS:",
        "SSH + SSL:",
        "SSH + WS + SSL:",
        "XRAY + WS:",
        "XRAY + WS + TLS:",
        "OPENVPN TCP:",
        "SQUID:",
        "UDP HYSTERIA:",
        "DNSTT:",
        "SLIPSTREAM:",
        "BADVPN-UDPGW:",
        "SSH -",
        "DNSTT -",
        "SLIPSTREAM -",
        "BADVPN -",
        "XRAY -",
        "SSL -",
        "HYSTERIA -",
        "MULTIPLEXER -",
        "OPENVPN -",
        "SQUID -",
        "WEBSOCKET -",
        "OS :",
        "IP :",
        "A :",
        "NS :",
        "Public Key :",
        "Main Command:",
    ]
    for marker in markers:
        text = text.replace(marker, "\n" + marker)

    text = text.replace(" ●", " ONLINE")
    text = text.replace("●", "ONLINE")
    text = re.sub(r"\n{2,}", "\n", text)
    lines = [line.strip() for line in text.split("\n") if line.strip()]
    if lines and re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", lines[-1]):
        lines = lines[:-1]
    return "\n".join(lines)


def extract_ipv4(text):
    match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", strip_ansi(text))
    return match.group(0) if match else ""


def extract_labeled_value(text, labels):
    cleaned = format_ssh_details_text(text)
    lines = cleaned.split("\n")
    for line in lines:
        for label in labels:
            prefix = label + " :"
            if line.startswith(prefix):
                return line[len(prefix) :].strip()
            prefix = label + ":"
            if line.startswith(prefix):
                return line[len(prefix) :].strip()
    return ""


def render_service_status_summary():
    try:
        payload = get_status_payload()
        services = normalize_service_entries(payload.get("services", []))
    except Exception:
        services = []
    if not services:
        return ""
    items = []
    for entry in services:
        if not isinstance(entry, (list, tuple)) or len(entry) < 2:
            continue
        name = html.escape(str(entry[0]))
        ok = coerce_service_online(entry[1])
        items.append(
            f'<div>{name}</div><div style="color:{"var(--success)" if ok else "var(--error)"};font-weight:700;">{"ONLINE" if ok else "OFFLINE"}</div>'
        )
    if not items:
        return ""
    return """
  <div class="link-box">
    <div class="link-title tls"><img src="https://raw.githubusercontent.com/hahacrunchyrollls/logo-s/refs/heads/main/icon-ssh.png" style="height:1.05em;"> Services Status</div>
    <div style="display:grid;grid-template-columns:1fr auto;gap:.7rem 1rem;">""" + "".join(items) + "</div></div>"


def coerce_service_online(value, default=False):
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if value is None:
        return default
    text = str(value).strip().lower()
    if text in {"active", "online", "running", "up", "true", "1", "ok", "healthy", "yes"}:
        return True
    if text in {"inactive", "offline", "stopped", "down", "false", "0", "failed", "dead", "error", "no"}:
        return False
    positive_tokens = ("active", "online", "running", "healthy", "started", "ready", "up")
    negative_tokens = ("inactive", "offline", "stopped", "failed", "dead", "error", "unhealthy", "down")
    if any(token in text for token in positive_tokens) and not any(token in text for token in negative_tokens):
        return True
    if any(token in text for token in negative_tokens):
        return False
    return default


def service_status_candidates(value):
    if isinstance(value, dict):
        candidates = []
        for key in ("online", "is_online", "active", "is_active", "running", "ok", "healthy", "status", "state", "health", "result"):
            if key in value:
                candidates.append(value.get(key))
        return candidates
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


def resolve_service_online(entry):
    candidates = []
    if isinstance(entry, dict):
        candidates.extend(
            service_status_candidates(
                {
                    key: entry.get(key)
                    for key in ("online", "is_online", "active", "is_active", "running", "ok", "healthy", "status", "state", "health", "result")
                    if key in entry
                }
            )
        )
    elif isinstance(entry, (list, tuple)) and len(entry) >= 2:
        for value in entry[1:]:
            candidates.extend(service_status_candidates(value))
    else:
        candidates.extend(service_status_candidates(entry))
    seen = False
    for value in candidates:
        if value in (None, ""):
            continue
        seen = True
        if coerce_service_online(value, default=False):
            return True
    if seen:
        return False
    return False


def normalize_service_entries(services):
    normalized = {}
    order = []
    if isinstance(services, dict):
        entries = list(services.items())
    else:
        entries = list(services or [])
    for entry in entries:
        raw_name = ""
        if isinstance(entry, dict):
            raw_name = str(entry.get("name") or entry.get("service") or entry.get("unit") or entry.get("key") or "").strip()
        elif isinstance(entry, (list, tuple)) and len(entry) >= 2:
            raw_name = str(entry[0]).strip()
        else:
            continue
        if not raw_name:
            continue
        is_online = resolve_service_online(entry)
        upper_name = raw_name.upper().replace(".SERVICE", "")
        display_name = upper_name
        if upper_name in {"HYSTERIA", "HYSTERIA-UDP", "HYSTERIA SERVER", "HYSTERIA-SERVER"} or "HYSTERIA" in upper_name:
            display_name = "HYSTERIA"
        elif upper_name == "BADVPN":
            display_name = "BADVPN-UDPGW"
        elif upper_name == "MULTIPLEXER":
            display_name = "MULTIPLEXER"
        elif upper_name == "OPENVPN":
            display_name = "OPENVPN"
        elif upper_name == "WEBSOCKET":
            display_name = "WEBSOCKET"
        elif upper_name in {"WIREGUARD", "WG", "WG-QUICK"} or "WIREGUARD" in upper_name:
            display_name = "WIREGUARD"
        elif upper_name == "SLIPSTREAM" or "SLIPSTREAM" in upper_name:
            display_name = "SLIPSTREAM"
        elif upper_name == "SSHD":
            display_name = "SSH"
        elif upper_name.endswith(".SERVICE"):
            display_name = upper_name[:-8]
        if display_name not in normalized:
            normalized[display_name] = is_online
            order.append(display_name)
        else:
            normalized[display_name] = normalized[display_name] or is_online
    ordered = []
    for name in STATUS_SERVICE_ORDER:
        ordered.append([name, normalized.get(name, False)])
    for name in order:
        if name not in STATUS_SERVICE_ORDER:
            ordered.append([name, normalized[name]])
    return ordered


def get_memory_stats():
    result = {"total": 0, "used": 0, "available": 0}
    try:
        values = {}
        with open("/proc/meminfo", "r", encoding="utf-8") as handle:
            for line in handle:
                parts = line.split()
                if len(parts) >= 2:
                    values[parts[0].rstrip(":")] = int(parts[1])
        total = values.get("MemTotal", 0)
        available = values.get("MemAvailable", values.get("MemFree", 0))
        result["total"] = total // 1024
        result["available"] = available // 1024
        result["used"] = max(total - available, 0) // 1024
    except Exception:
        pass
    return result


def get_storage_stats():
    try:
        usage = shutil.disk_usage("/")
        return {
            "total": usage.total // (1024 * 1024),
            "used": usage.used // (1024 * 1024),
            "free": usage.free // (1024 * 1024),
        }
    except Exception:
        return {"total": 0, "used": 0, "free": 0}


def get_cpu_percent():
    try:
        with open("/proc/stat", "r", encoding="utf-8") as handle:
            first = [float(x) for x in handle.readline().split()[1:]]
        time.sleep(0.05)
        with open("/proc/stat", "r", encoding="utf-8") as handle:
            second = [float(x) for x in handle.readline().split()[1:]]
        idle1, total1 = first[3], sum(first)
        idle2, total2 = second[3], sum(second)
        if total2 <= total1:
            return 0.0
        return round(100.0 * (1 - (idle2 - idle1) / (total2 - total1)), 2)
    except Exception:
        return 0.0


def get_load_average():
    try:
        return [f"{value:.2f}" for value in os.getloadavg()]
    except Exception:
        return ["0.00", "0.00", "0.00"]


def get_total_network_bytes():
    rx_total = 0
    tx_total = 0
    try:
        with open("/proc/net/dev", "r", encoding="utf-8") as handle:
            for line in handle.readlines()[2:]:
                if ":" not in line:
                    continue
                iface, data = line.split(":", 1)
                if iface.strip() == "lo":
                    continue
                fields = data.split()
                rx_total += int(fields[0])
                tx_total += int(fields[8])
    except Exception:
        pass
    return rx_total, tx_total


def _coerce_non_negative_int(value):
    try:
        return max(int(value), 0)
    except Exception:
        return 0


def _network_source_key():
    backend = selected_backend()
    if backend:
        return "backend:" + str(backend.get("id") or backend.get("api_url") or "default")
    return "local"


def build_live_network_stats(net=None, source=None):
    net = net if isinstance(net, dict) else {}
    rx_total = _coerce_non_negative_int(net.get("rx_bytes", 0))
    tx_total = _coerce_non_negative_int(net.get("tx_bytes", 0))
    source_key = source or "local"
    now = time.time()
    with traffic_lock:
        previous = dict(last_traffic_snapshot)
        if previous["time"] is None or previous.get("source") != source_key:
            rx_rate = tx_rate = 0
        else:
            delta = max(now - previous["time"], 0.001)
            rx_rate = max((rx_total - previous["rx"]) / delta, 0)
            tx_rate = max((tx_total - previous["tx"]) / delta, 0)
        last_traffic_snapshot["time"] = now
        last_traffic_snapshot["rx"] = rx_total
        last_traffic_snapshot["tx"] = tx_total
        last_traffic_snapshot["source"] = source_key
    return {"rx_bytes": rx_total, "tx_bytes": tx_total, "rx_rate": rx_rate, "tx_rate": tx_rate}


def _coerce_number(value, default=0):
    try:
        return float(value)
    except Exception:
        return default


def _pick_first(mapping, *keys):
    if not isinstance(mapping, dict):
        return None
    for key in keys:
        if key in mapping and mapping.get(key) not in (None, ""):
            return mapping.get(key)
    return None


def _normalize_load_value(value):
    if isinstance(value, (list, tuple)):
        return [str(item) for item in list(value)[:3]]
    if isinstance(value, str):
        parts = [part.strip() for part in re.split(r"[,\s]+", value.strip()) if part.strip()]
        if parts:
            return parts[:3]
    return get_load_average()


def _normalize_metric_block(payload, block_keys, field_aliases):
    result = {field: 0 for field in field_aliases}
    block = {}
    for key in block_keys:
        value = payload.get(key) if isinstance(payload, dict) else None
        if isinstance(value, dict):
            block = value
            break
    for field, aliases in field_aliases.items():
        result[field] = _coerce_non_negative_int(_pick_first(block, *aliases))
        if result[field] == 0 and isinstance(payload, dict):
            result[field] = _coerce_non_negative_int(_pick_first(payload, *aliases))
    return result


def _status_payload_candidates(payload):
    candidates = []
    queue = [payload]
    seen = set()
    while queue:
        current = queue.pop(0)
        if not isinstance(current, dict):
            continue
        marker = id(current)
        if marker in seen:
            continue
        seen.add(marker)
        candidates.append(current)
        for key in ("data", "result", "payload", "status", "server", "stats"):
            nested = current.get(key)
            if isinstance(nested, dict):
                queue.append(nested)
    return candidates


def _empty_backend_summary():
    return {
        "online_users": 0,
        "total_accounts": 0,
        "ssh_online_users": 0,
        "openvpn_online_users": 0,
        "online_entries": [],
    }


def _normalize_online_service(value):
    service = str(value or "").strip().lower()
    if service in {"ssh", "sshd", "dropbear"}:
        return "ssh"
    if service in {"openvpn", "open-vpn", "ovpn"}:
        return "openvpn"
    return ""


def _online_service_label(service):
    if service == "ssh":
        return "SSH"
    if service == "openvpn":
        return "OPENVPN"
    return str(service or "ONLINE").strip().upper() or "ONLINE"


def _normalize_backend_online_entry(raw, backend=None):
    if isinstance(raw, str):
        raw = {"username": raw}
    if not isinstance(raw, dict):
        return None
    service = _normalize_online_service(
        _pick_first(raw, "service", "protocol", "type", "kind")
    )
    username = str(
        _pick_first(raw, "username", "user", "common_name", "commonName", "name", "client") or ""
    ).strip()
    remote_addr = str(
        _pick_first(
            raw,
            "remote_addr",
            "remoteAddr",
            "real_address",
            "realAddress",
            "ip",
            "address",
            "host",
        )
        or ""
    ).strip()
    tty = str(_pick_first(raw, "tty", "terminal", "pts") or "").strip()
    source = str(_pick_first(raw, "source", "via") or "").strip()
    if not service and not username and not remote_addr:
        return None
    if not username:
        username = "Connected client" if service == "openvpn" else "Connected session"
    backend = backend or {}
    return {
        "service": service or "ssh",
        "service_label": _online_service_label(service or "ssh"),
        "username": username,
        "remote_addr": remote_addr,
        "tty": tty,
        "source": source,
        "backend_id": str(backend.get("id") or "").strip(),
        "backend_label": backend_display_label(backend) if backend else "",
        "backend_host": backend_host(backend) if backend else "",
    }


def _sort_online_entries(entries):
    return sorted(
        entries or [],
        key=lambda item: (
            str(item.get("backend_label") or item.get("backend_host") or ""),
            str(item.get("service") or ""),
            str(item.get("username") or ""),
            str(item.get("remote_addr") or ""),
            str(item.get("tty") or ""),
        ),
    )


def extract_backend_status_summary(payload, backend=None):
    for candidate in _status_payload_candidates(payload):
        total_accounts = _pick_first(
            candidate,
            "total_accounts",
            "totalAccounts",
            "accounts_created",
            "accountsCreated",
            "created_accounts",
            "createdAccounts",
        )
        ssh_online_users = _pick_first(
            candidate,
            "ssh_online_users",
            "sshOnlineUsers",
            "ssh_users_online",
            "sshUsersOnline",
        )
        openvpn_online_users = _pick_first(
            candidate,
            "openvpn_online_users",
            "openvpnOnlineUsers",
            "openvpn_users_online",
            "openvpnUsersOnline",
            "ovpn_online_users",
            "ovpnOnlineUsers",
        )
        raw_entries = _pick_first(
            candidate,
            "online_sessions",
            "onlineSessions",
            "online_entries",
            "onlineEntries",
            "connected_users",
            "connectedUsers",
        )
        online_entries = []
        if isinstance(raw_entries, list):
            for raw_entry in raw_entries:
                normalized_entry = _normalize_backend_online_entry(raw_entry, backend=backend)
                if normalized_entry:
                    online_entries.append(normalized_entry)
        entry_ssh_online_users = sum(1 for entry in online_entries if entry.get("service") == "ssh")
        entry_openvpn_online_users = sum(1 for entry in online_entries if entry.get("service") == "openvpn")
        has_ssh_field = ssh_online_users not in (None, "")
        has_openvpn_field = openvpn_online_users not in (None, "")
        if has_ssh_field:
            ssh_online_users = _coerce_non_negative_int(ssh_online_users)
        else:
            ssh_online_users = entry_ssh_online_users
        if has_openvpn_field:
            openvpn_online_users = _coerce_non_negative_int(openvpn_online_users)
        else:
            openvpn_online_users = entry_openvpn_online_users
        online_users = ssh_online_users + openvpn_online_users
        if (
            not has_ssh_field
            and not has_openvpn_field
            and total_accounts in (None, "")
            and not online_entries
        ):
            continue
        return {
            "online_users": _coerce_non_negative_int(online_users),
            "total_accounts": _coerce_non_negative_int(total_accounts),
            "ssh_online_users": _coerce_non_negative_int(ssh_online_users),
            "openvpn_online_users": _coerce_non_negative_int(openvpn_online_users),
            "online_entries": _sort_online_entries(online_entries),
        }
    return _empty_backend_summary()


def normalize_backend_status_payload(payload):
    for candidate in _status_payload_candidates(payload):
        services = _pick_first(candidate, "services", "service_statuses", "serviceStatuses", "service_status", "serviceStatus", "statuses")
        net = _normalize_metric_block(
            candidate,
            ("net", "network"),
            {
                "rx_bytes": ("rx_bytes", "download_bytes", "downloadBytes", "received_bytes", "receivedBytes"),
                "tx_bytes": ("tx_bytes", "upload_bytes", "uploadBytes", "sent_bytes", "sentBytes"),
                "rx_rate": ("rx_rate", "download_rate", "downloadRate", "rx_per_sec", "rxPerSec"),
                "tx_rate": ("tx_rate", "upload_rate", "uploadRate", "tx_per_sec", "txPerSec"),
            },
        )
        mem = _normalize_metric_block(
            candidate,
            ("mem", "memory"),
            {
                "total": ("total", "total_mb", "totalMb"),
                "used": ("used", "used_mb", "usedMb"),
                "available": ("available", "free", "available_mb", "availableMb", "free_mb", "freeMb"),
            },
        )
        storage = _normalize_metric_block(
            candidate,
            ("storage", "disk"),
            {
                "total": ("total", "total_mb", "totalMb"),
                "used": ("used", "used_mb", "usedMb"),
                "free": ("free", "available", "free_mb", "freeMb", "available_mb", "availableMb"),
            },
        )
        cpu_raw = _pick_first(candidate, "cpu", "cpu_usage", "cpuUsage")
        load_raw = _pick_first(candidate, "load", "load_average", "loadAverage", "loadavg")
        has_status_keys = any(
            key in candidate
            for key in (
                "services",
                "service_statuses",
                "serviceStatuses",
                "service_status",
                "serviceStatus",
                "statuses",
                "net",
                "network",
                "mem",
                "memory",
                "storage",
                "disk",
                "cpu",
                "cpu_usage",
                "cpuUsage",
                "load",
                "load_average",
                "loadAverage",
                "loadavg",
            )
        )
        if not has_status_keys:
            continue
        return {
            "cpu": _coerce_number(cpu_raw, 0),
            "load": _normalize_load_value(load_raw),
            "mem": mem,
            "storage": storage,
            "net": net,
            "services": services or [],
        }
    return None


def extract_backend_status_counters(payload):
    summary = extract_backend_status_summary(payload)
    return {"online_users": summary["online_users"], "total_accounts": summary["total_accounts"]}


def get_status_payload():
    backend = selected_backend() if backend_configured() else None
    backend_error = ""
    if backend:
        try:
            data = backend_request("/status", payload=None, method="GET")
            normalized = normalize_backend_status_payload(data)
            if normalized:
                normalized["services"] = normalize_service_entries(normalized.get("services") or [])
                normalized["net"] = build_live_network_stats(normalized.get("net"), source=_network_source_key())
                normalized["status_source"] = "backend"
                normalized["backend_error"] = ""
                normalized["backend_label"] = backend.get("label", "")
                normalized["backend_host"] = backend_host(backend)
                return normalized
            backend_error = "Unsupported backend /status response."
        except Exception as exc:
            backend_error = backend_error_message(exc)
        return {
            "cpu": 0,
            "load": ["0.00", "0.00", "0.00"],
            "mem": {"total": 0, "used": 0, "available": 0},
            "storage": {"total": 0, "used": 0, "free": 0},
            "net": build_live_network_stats({"rx_bytes": 0, "tx_bytes": 0}, source=_network_source_key()),
            "services": [[name, None] for name in STATUS_SERVICE_ORDER],
            "status_source": "backend",
            "backend_error": backend_error,
            "backend_label": backend.get("label", ""),
            "backend_host": backend_host(backend),
        }
    rx_total, tx_total = get_total_network_bytes()
    services = [[name, None if backend else False] for name in STATUS_SERVICE_ORDER]
    return {
        "cpu": get_cpu_percent(),
        "load": get_load_average(),
        "mem": get_memory_stats(),
        "storage": get_storage_stats(),
        "net": build_live_network_stats({"rx_bytes": rx_total, "tx_bytes": tx_total}, source="local"),
        "services": services,
        "status_source": "local",
        "backend_error": backend_error,
        "backend_label": backend.get("label", "") if backend else "",
        "backend_host": backend_host(backend) if backend else "",
    }


BASE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
<title>{{ title }}</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="icon" type="image/svg+xml" href="/site-icon.svg">
<link rel="apple-touch-icon" href="/site-icon.svg">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@shoelace-style/shoelace@2.13.0/cdn/themes/light.css" />
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Bangers&family=Comic+Neue:wght@400;700&display=swap">
<script type="module" src="https://cdn.jsdelivr.net/npm/@shoelace-style/shoelace@2.13.0/cdn/shoelace.js"></script>
<style>
:root{--primary-color:#7c1027;--primary-hover:#5d0919;--accent-color:#a91e3c;--accent-hover:#c13350;--bg-gradient:linear-gradient(180deg,#fffefb 0%,#f8ebef 48%,#fff8fa 100%);--card-bg:linear-gradient(180deg,#ffffff 0%,#fff2f5 100%);--card-border:#5d0919;--card-shadow:8px 8px 0 rgba(93,9,25,.88);--soft-shadow:0 20px 42px rgba(93,9,25,.14);--success:#8f1730;--error:#391019;--warning:#b54e61;--text-primary:#381018;--text-secondary:#6a2030;--text-muted:#955663;--surface:#ffffff;--surface-alt:#fff3f6;--paper:#fffaf8;--ink:#1f060c;--border-radius:18px;--transition:all .22s ease;}
body{background:var(--bg-gradient);color:var(--text-primary);font-family:'Comic Neue','Trebuchet MS',sans-serif;margin:0;min-height:100vh;line-height:1.6;overflow-x:hidden;position:relative;display:flex;flex-direction:column;}
body::before{content:"";position:fixed;inset:0;z-index:-2;background:radial-gradient(circle,rgba(124,16,39,.13) 0 1.6px,transparent 1.8px 100%) 0 0/24px 24px,radial-gradient(circle,rgba(124,16,39,.08) 0 1.4px,transparent 1.7px 100%) 12px 12px/24px 24px,linear-gradient(135deg,rgba(124,16,39,.06) 0%,transparent 35%,rgba(124,16,39,.04) 100%);}
a{color:var(--primary-color);}
button{background:linear-gradient(180deg,var(--primary-color) 0%,var(--accent-color) 100%);color:#fff;border:3px solid var(--ink);border-radius:16px;font-weight:700;font-size:1rem;padding:14px 28px;cursor:pointer;transition:var(--transition);display:inline-flex;align-items:center;justify-content:center;gap:8px;box-shadow:5px 5px 0 var(--ink);font-family:'Bangers','Comic Neue',cursive;letter-spacing:.08em;text-transform:uppercase;}
button:hover,button:focus{transform:translate(3px,3px);box-shadow:2px 2px 0 var(--ink);background:linear-gradient(180deg,var(--accent-hover) 0%,var(--primary-color) 100%);outline:none;}
button:disabled{cursor:not-allowed;opacity:.72;transform:none!important;box-shadow:5px 5px 0 rgba(31,6,12,.45)!important;filter:saturate(.7);}
.page-main{flex:1 0 auto;}
.container{width:min(100%,1180px);max-width:1180px;margin:2rem auto;padding:0 1rem;box-sizing:border-box;}
.neo-box{background:var(--card-bg);border-radius:var(--border-radius);box-shadow:var(--card-shadow),var(--soft-shadow);padding:1.8rem 1.5rem;margin-bottom:2rem;border:3px solid var(--card-border);position:relative;overflow:hidden;}
.neo-box::before{content:"";position:absolute;top:14px;right:-48px;width:160px;height:34px;background:rgba(124,16,39,.08);transform:rotate(28deg);}
.section-title{font-family:'Bangers','Comic Neue',cursive;font-size:clamp(2rem,5vw,3rem);letter-spacing:.08em;margin-bottom:1rem;color:var(--primary-color);background:none;-webkit-text-fill-color:initial;text-shadow:2px 2px 0 rgba(31,6,12,.14);}
.success-msg{display:flex;align-items:center;background:linear-gradient(180deg,#ffffff 0%,#fff6f8 100%);border:3px solid var(--success);border-radius:var(--border-radius);padding:1rem;margin-bottom:1.5rem;font-weight:700;font-size:1.05em;color:var(--text-primary);box-shadow:4px 4px 0 rgba(93,9,25,.24);}
.info-grid,.status-grid-2,.services-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px;}
.admin-account-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px;align-items:start;}
.admin-account-grid > *{min-width:0;}
.info-grid{gap:.8rem 1.2rem;font-family:'Comic Neue','Trebuchet MS',sans-serif;background:linear-gradient(180deg,#ffffff 0%,#fff7f8 100%);border-radius:var(--border-radius);padding:1.2rem;margin-bottom:1.5rem;border:3px solid var(--card-border);box-shadow:4px 4px 0 rgba(93,9,25,.16);}
.info-grid div:nth-child(2n){font-weight:700;color:var(--primary-color);word-break:break-all;}
.link-box,.status-card,.service-item{background:linear-gradient(180deg,var(--surface) 0%,var(--surface-alt) 100%);border-radius:var(--border-radius);padding:1rem;border:3px solid var(--card-border);box-shadow:4px 4px 0 rgba(93,9,25,.16);}
.link-title{font-family:'Bangers','Comic Neue',cursive;font-weight:700;margin-bottom:.8rem;display:flex;align-items:center;gap:8px;letter-spacing:.06em;color:var(--primary-color)}.link-title.tls{color:var(--primary-color)}
input[type="text"],input[type="password"],input[type="search"],input[type="number"],select{background:#fff;border:3px solid var(--card-border);border-radius:16px;color:var(--text-primary);font-size:1rem;padding:12px 16px;width:100%;box-sizing:border-box;max-width:400px;display:block;outline:none;box-shadow:inset 0 -4px 0 rgba(124,16,39,.08);}
input[type="text"]:focus,input[type="password"]:focus,input[type="search"]:focus,input[type="number"]:focus,select:focus{box-shadow:0 0 0 4px rgba(124,16,39,.12),inset 0 -4px 0 rgba(124,16,39,.08);}
.form-group{margin-bottom:1.8rem;text-align:center;width:100%;display:flex;flex-direction:column;align-items:center;}
.form-label{display:block;font-family:'Bangers','Comic Neue',cursive;font-weight:700;letter-spacing:.06em;margin-bottom:.8rem;width:100%;max-width:400px;text-align:center;color:var(--primary-color);}
.form-input-container{width:100%;display:flex;justify-content:center;max-width:400px;}
form{display:flex;flex-direction:column;align-items:center;width:100%;margin-bottom:1.5rem;}
.turnstile-shell{width:100%;max-width:400px;display:flex;justify-content:center;}
.turnstile-shell > div{width:100%;}
.turnstile-help{width:100%;max-width:400px;margin-top:.7rem;color:var(--text-muted);font-size:.94rem;font-weight:700;text-align:center;}
.turnstile-config-note{width:100%;max-width:400px;margin:0 auto 1.4rem auto;}
.navbar{width:100%;background:rgba(255,250,249,.97);backdrop-filter:blur(10px);border-bottom:4px solid var(--card-border);box-shadow:0 8px 0 rgba(93,9,25,.18);display:flex;align-items:center;justify-content:space-between;padding:1rem max(1.5rem,5%);position:sticky;top:0;z-index:100;box-sizing:border-box;}
.navbar-brand{display:flex;align-items:center;gap:10px;font-family:'Bangers','Comic Neue',cursive;font-weight:700;font-size:clamp(1.1rem,3vw,1.6rem);letter-spacing:.06em;color:var(--primary-color);text-decoration:none;line-height:1.1;}
.brand-icon{height:2.1em;width:2.1em;object-fit:cover;border-radius:50%;border:2px solid var(--card-border);background:#fff;box-shadow:3px 3px 0 rgba(93,9,25,.2);flex:0 0 auto;}
.navbar-nav{display:flex;align-items:center;gap:10px;margin-left:auto;}
.nav-link{color:var(--text-secondary);text-decoration:none;font-weight:700;padding:8px 16px;border-radius:14px;border:2px solid transparent;transition:var(--transition);font-size:.98rem;background:rgba(124,16,39,.05);}
.nav-link:hover,.nav-link.active{color:#fff;background:var(--primary-color);border-color:var(--ink);}
.burger-btn{display:none;background:var(--surface);border:3px solid var(--card-border);color:var(--primary-color);padding:0;border-radius:12px;height:46px;width:46px;box-shadow:4px 4px 0 rgba(93,9,25,.22);}
.mobile-menu{display:none;position:absolute;top:calc(100% + 8px);right:12px;min-width:220px;max-width:92vw;background:var(--surface);border:3px solid var(--card-border);border-radius:16px;box-shadow:8px 8px 0 rgba(93,9,25,.22);padding:8px;z-index:1000;flex-direction:column;gap:6px;}
.mobile-menu a{display:block;text-decoration:none;color:var(--text-primary);padding:10px 12px;border-radius:10px;font-weight:700;}
.mobile-menu a:hover{background:var(--primary-color);color:#fff;}
.status-label{color:var(--text-muted);font-size:.92rem;font-weight:700;display:flex;align-items:center;gap:6px;}.status-value{font-family:'Bangers','Comic Neue',cursive;font-size:1.35rem;letter-spacing:.04em;font-weight:700}
.status-subtitle{font-family:'Bangers','Comic Neue',cursive;font-size:1.15rem;font-weight:700;letter-spacing:.05em;margin:1.2rem 0 .8rem 0;color:var(--primary-color);display:flex;align-items:center;gap:8px;}
.stats-container{display:flex;justify-content:center;gap:1rem;margin:1.5rem 0;flex-wrap:wrap;}
.stat-item{background:linear-gradient(180deg,var(--surface) 0%,var(--surface-alt) 100%);border-radius:var(--border-radius);padding:.8rem 1.5rem;display:flex;align-items:center;gap:10px;border:3px solid var(--card-border);box-shadow:4px 4px 0 rgba(93,9,25,.16);flex:1;min-width:200px;max-width:300px;}
.stat-icon{color:var(--primary-color);font-size:1.2rem}.stat-value{font-family:'Bangers','Comic Neue',cursive;font-weight:700;font-size:1.3rem;letter-spacing:.04em}.stat-label{font-size:.9rem;color:var(--text-secondary);font-weight:700}
.server-selector{max-width:1040px;margin:0 auto 1.35rem auto;padding:1.2rem 1.25rem;background:linear-gradient(180deg,#ffffff 0%,#fff2f5 100%);border:3px solid var(--card-border);border-radius:22px;box-shadow:6px 6px 0 rgba(93,9,25,.24);}
.server-selector-head{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:1rem;text-align:left;}
.server-selector-kicker{display:inline-flex;align-items:center;gap:8px;color:var(--primary-color);font-family:'Bangers','Comic Neue',cursive;font-weight:700;font-size:1rem;letter-spacing:.08em;text-transform:uppercase;}
.server-selector-title{font-family:'Bangers','Comic Neue',cursive;font-size:1.35rem;font-weight:700;color:var(--primary-color);margin-top:.35rem;letter-spacing:.04em;}
.server-selector-note{color:var(--text-muted);font-size:.95rem;max-width:420px;font-weight:700;}
.server-selector-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px;}
.server-card-form{display:block;width:100%;margin:0;}
button.server-card-button{width:100%;padding:0;border-radius:18px;display:block;text-align:left;background:linear-gradient(180deg,#ffffff 0%,#fff3f6 100%);border:3px solid var(--card-border);box-shadow:4px 4px 0 rgba(93,9,25,.22);overflow:hidden;color:var(--text-primary);font-family:'Comic Neue','Trebuchet MS',sans-serif;letter-spacing:0;text-transform:none;}
button.server-card-button:hover,button.server-card-button:focus{transform:translate(3px,3px);border-color:var(--primary-color);background:linear-gradient(180deg,#ffffff 0%,#ffe6ed 100%);box-shadow:1px 1px 0 rgba(93,9,25,.22);}
button.server-card-button.is-active{background:linear-gradient(180deg,var(--accent-color) 0%,var(--primary-color) 100%);border-color:var(--ink);box-shadow:4px 4px 0 var(--ink);color:#fff;}
button.server-card-button.is-active .server-card-title,button.server-card-button.is-active .server-card-location,button.server-card-button.is-active .server-card-host{color:#fff;}
button.server-card-button.is-active .server-badge{background:#fff;color:var(--primary-color);border-color:var(--ink);}
.server-card-main{display:flex;align-items:flex-start;gap:12px;padding:14px 15px 10px 15px;}
.server-flag{height:36px;width:48px;border-radius:12px;object-fit:cover;border:2px solid var(--card-border);background:#fff;box-shadow:3px 3px 0 rgba(93,9,25,.2);}
.server-flag-fallback{display:inline-flex;align-items:center;justify-content:center;height:36px;width:48px;border-radius:12px;background:rgba(124,16,39,.08);border:2px solid var(--card-border);color:var(--primary-color);font-size:1rem;}
.server-copy{flex:1;min-width:0;}
.server-card-title{display:flex;align-items:center;gap:8px;justify-content:space-between;font-weight:800;font-size:1rem;color:var(--text-primary);}
.server-card-location{margin-top:4px;color:var(--text-secondary);font-size:.92rem;word-break:break-word;}
.server-card-health{display:inline-flex;align-items:center;gap:8px;margin-top:10px;padding:6px 10px;border-radius:999px;border:2px solid rgba(93,9,25,.16);background:rgba(124,16,39,.05);color:var(--text-secondary);font-size:.78rem;font-weight:800;letter-spacing:.02em;}
.server-card-health-dot{height:10px;width:10px;border-radius:50%;background:#f59e0b;box-shadow:0 0 0 4px rgba(245,158,11,.18);flex:none;}
.server-card-health.is-alive{background:rgba(34,197,94,.12);border-color:rgba(34,197,94,.24);color:#166534;}
.server-card-health.is-alive .server-card-health-dot{background:#16a34a;box-shadow:0 0 0 4px rgba(22,163,74,.16);}
.server-card-health.is-dead{background:rgba(239,68,68,.12);border-color:rgba(239,68,68,.22);color:#991b1b;}
.server-card-health.is-dead .server-card-health-dot{background:#dc2626;box-shadow:0 0 0 4px rgba(220,38,38,.16);}
button.server-card-button.is-active .server-card-health{background:rgba(255,255,255,.12);border-color:rgba(255,255,255,.28);color:#fff;}
button.server-card-button.is-active .server-card-health-dot{background:#fde68a;box-shadow:0 0 0 4px rgba(253,230,138,.18);}
button.server-card-button.is-active .server-card-health.is-alive .server-card-health-dot{background:#86efac;box-shadow:0 0 0 4px rgba(134,239,172,.2);}
button.server-card-button.is-active .server-card-health.is-dead .server-card-health-dot{background:#fecaca;box-shadow:0 0 0 4px rgba(254,202,202,.18);}
.server-card-host{display:flex;align-items:center;gap:8px;padding:10px 15px 14px 15px;border-top:2px dashed rgba(93,9,25,.25);color:var(--text-muted);font-size:.86rem;background:rgba(124,16,39,.04);}
.server-badge{display:inline-flex;align-items:center;gap:6px;padding:6px 10px;border-radius:999px;border:2px solid rgba(93,9,25,.18);font-size:.78rem;font-weight:800;letter-spacing:.04em;text-transform:uppercase;color:var(--text-secondary);background:rgba(124,16,39,.05);}
.server-badge.active{background:#fff;color:var(--primary-color);border-color:var(--ink);}
.server-current-pill{display:flex;align-items:center;justify-content:center;gap:10px;flex-wrap:wrap;max-width:1040px;margin:0 auto 1.35rem auto;padding:.9rem 1rem;border-radius:999px;background:var(--surface);border:3px solid var(--card-border);box-shadow:4px 4px 0 rgba(93,9,25,.18);color:var(--text-secondary);font-size:.95rem;font-weight:700;}
.server-current-dot{height:10px;width:10px;border-radius:50%;background:var(--success);box-shadow:0 0 0 6px rgba(143,23,48,.12);}
.server-current-name{color:var(--primary-color);font-weight:800;font-family:'Bangers','Comic Neue',cursive;letter-spacing:.04em;}
.server-current-meta{color:var(--text-muted);}
.site-footer{margin-top:auto;padding:0;background:linear-gradient(180deg,#8f1730 0%,#5d0919 42%,#26070d 100%);color:#fff;position:relative;overflow:hidden;border-top:1px solid rgba(255,255,255,.08);}
.site-footer::before{content:"";position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,rgba(255,255,255,.22),transparent);}
.site-footer::after{content:"";position:absolute;left:-140px;top:-120px;width:360px;height:360px;background:radial-gradient(circle,rgba(255,255,255,.08) 0%,rgba(255,255,255,0) 72%);pointer-events:none;}
.footer-shell{width:min(100%,1120px);margin:0 auto;padding:2.7rem 1.25rem 1.15rem;position:relative;z-index:1;box-sizing:border-box;}
.footer-grid{display:grid;grid-template-columns:minmax(260px,1.55fr) repeat(3,minmax(150px,1fr));gap:30px;position:relative;z-index:1;}
.footer-brand-panel{padding-right:1rem;}
.footer-brand-row{display:flex;align-items:center;gap:12px;margin-bottom:.9rem;}
.footer-logo{height:54px;width:54px;object-fit:cover;border-radius:16px;border:1px solid rgba(255,255,255,.18);background:rgba(255,255,255,.94);flex:none;}
.footer-title{font-family:'Bangers','Comic Neue',cursive;font-size:1.7rem;letter-spacing:.06em;color:#fff;line-height:1;}
.footer-subtitle{margin-top:.28rem;color:rgba(255,232,238,.76);font-size:.8rem;font-weight:800;letter-spacing:.13em;text-transform:uppercase;}
.footer-copy{color:rgba(255,241,245,.88);font-weight:700;max-width:560px;}
.footer-badges{display:flex;gap:8px;flex-wrap:wrap;margin-top:1rem;}
.footer-badge{display:inline-flex;align-items:center;gap:8px;padding:.45rem .76rem;border-radius:999px;background:transparent;border:1px solid rgba(255,255,255,.16);color:#fff;font-size:.82rem;font-weight:800;}
.footer-referral{display:inline-flex;align-items:center;justify-content:center;margin-top:1rem;padding:.5rem .6rem;border-radius:18px;background:rgba(255,255,255,.08);border:1px solid rgba(255,255,255,.14);max-width:220px;box-sizing:border-box;}
.footer-referral img{display:block;width:100%;height:auto;max-width:170px;}
.footer-column{display:flex;flex-direction:column;gap:.9rem;min-width:0;position:relative;z-index:1;}
.footer-heading{font-family:'Bangers','Comic Neue',cursive;font-size:1rem;letter-spacing:.08em;color:#ffd8df;}
.footer-link-list{display:flex;flex-direction:column;gap:.62rem;}
.footer-link{display:inline-flex;align-items:center;gap:10px;padding:.12rem 0;text-decoration:none;font-weight:700;color:rgba(255,243,246,.84);transition:var(--transition);}
.footer-link i{width:16px;text-align:center;color:#ffd8df;}
.footer-link:hover,.footer-link:focus{color:#fff;transform:translateX(4px);outline:none;}
.footer-bottom{display:flex;align-items:center;justify-content:space-between;gap:14px;flex-wrap:wrap;border-top:1px solid rgba(255,255,255,.14);padding-top:1rem;margin-top:1.6rem;position:relative;z-index:1;}
.footer-meta{display:flex;align-items:center;gap:12px;flex-wrap:wrap;color:rgba(255,229,235,.72);font-size:.92rem;font-weight:700;}
.footer-reset-note{display:inline-flex;align-items:center;gap:8px;color:rgba(255,238,242,.82);}
.footer-reset-note i{color:#ffd8df;}
.footer-separator{opacity:.4;}
.footer-bottom-links{display:flex;gap:16px;flex-wrap:wrap;}
.footer-bottom-link{color:rgba(255,243,246,.78);text-decoration:none;font-weight:700;transition:var(--transition);}
.footer-bottom-link:hover,.footer-bottom-link:focus{color:#fff;outline:none;}
.legal-card{max-width:1100px;margin:0 auto;}
.legal-intro{max-width:920px;margin:0 auto 1.2rem auto;text-align:center;color:var(--text-secondary);font-weight:700;}
.legal-sections{display:grid;gap:1rem;}
.global-ad-wrap{width:min(100% - 2rem,1180px);margin:1rem auto 0 auto;padding:0 1rem;box-sizing:border-box;}
.global-ad-shell{background:transparent;border:0;border-radius:0;box-shadow:none;padding:0;overflow:visible;}
ins.adsbygoogle[data-ad-status="unfilled"]{display:none!important;}
.loading-overlay{display:none;position:fixed;inset:0;z-index:9999;background:rgba(93,9,25,.78);backdrop-filter:blur(4px);justify-content:center;align-items:center;flex-direction:column;gap:1.5rem}.loading-overlay.active{display:flex}.loading-spinner{width:56px;height:56px;border:4px solid rgba(255,255,255,.24);border-top-color:#fff;border-radius:50%;animation:spin .7s linear infinite}.loading-text{font-family:'Bangers','Comic Neue',cursive;font-size:1.2rem;letter-spacing:.06em;color:#fff}
@keyframes spin{to{transform:rotate(360deg);}}
@media (max-width:960px){.server-selector-grid{grid-template-columns:1fr;}}
@media (max-width:980px){.footer-grid{grid-template-columns:1fr 1fr;}.footer-brand-panel{grid-column:1/-1;padding-right:0;}}
@media (max-width:880px){.navbar-nav{display:none}.burger-btn{display:inline-flex;align-items:center;justify-content:center;}.navbar{padding:.6rem .8rem}}
@media (max-width:576px){.container{width:100%;padding:0 .75rem}.neo-box{padding:1.2rem 1rem}.info-grid,.status-grid-2,.services-grid,.server-selector-grid,.admin-account-grid{grid-template-columns:1fr}.stats-container{flex-direction:column;align-items:center}.server-selector{padding:1rem}.server-current-pill{border-radius:18px}.navbar-brand{flex-wrap:wrap;justify-content:flex-start}.section-title{font-size:2.2rem}.footer-shell{padding:1.4rem .9rem .85rem}.footer-grid{grid-template-columns:repeat(2,minmax(0,1fr));gap:16px}.footer-brand-panel{grid-column:1/-1;padding-right:0}.footer-brand-row{align-items:flex-start;margin-bottom:.55rem}.footer-logo{height:44px;width:44px}.footer-title{font-size:1.4rem}.footer-copy{font-size:.92rem}.footer-badges{display:none}.footer-referral{margin-top:.75rem;padding:.35rem .45rem;max-width:180px}.footer-referral img{max-width:150px}.footer-column{gap:.5rem}.footer-heading{font-size:.9rem}.footer-link-list{gap:.28rem}.footer-link{font-size:.88rem}.footer-bottom{flex-direction:column;align-items:flex-start;margin-top:.9rem;padding-top:.75rem;gap:8px}.footer-meta{flex-direction:column;align-items:flex-start;gap:4px;font-size:.84rem}.footer-reset-note{font-size:.82rem;line-height:1.35}.footer-separator{display:none}.footer-bottom-links{width:100%;display:flex;gap:12px;flex-wrap:wrap}.footer-link:hover,.footer-link:focus{transform:none}}
</style>
</head>
<body>
<div class="loading-overlay" id="loadingOverlay"><div class="loading-spinner"></div><div class="loading-text">Creating your account...</div></div>
{{ navbar|safe }}
<main class="page-main">
{% if show_ads %}
<div class="global-ad-wrap">
  <script async src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=ca-pub-2897141099701828" crossorigin="anonymous"></script>
  <div class="global-ad-shell">
    <ins class="adsbygoogle"
         style="display:block"
         data-ad-client="ca-pub-2897141099701828"
         data-ad-slot="8320243336"
         data-ad-format="auto"
         data-full-width-responsive="true"></ins>
  </div>
  <script>
       (adsbygoogle = window.adsbygoogle || []).push({});
  </script>
</div>
{% endif %}
{{ content|safe }}
{% if show_ads %}
<div class="global-ad-wrap">
  <div class="global-ad-shell">
    <ins class="adsbygoogle"
         style="display:block"
         data-ad-format="autorelaxed"
         data-ad-client="ca-pub-2897141099701828"
         data-ad-slot="7495347879"></ins>
  </div>
  <script>
       (adsbygoogle = window.adsbygoogle || []).push({});
  </script>
</div>
{% endif %}
 </main>
{{ footer|safe }}
<script>
document.addEventListener('DOMContentLoaded',function(){const n=v=>{if(!v||v==='/')return '/';return v.replace(/\/+$/,'')||'/';};const p=n(window.location.pathname);document.querySelectorAll('.nav-link').forEach(a=>{const h=n(a.getAttribute('href'));if(p===h||(p==='/'&&h==='/main'))a.classList.add('active');});const b=document.getElementById('navbar-burger');const m=document.getElementById('mobile-menu');if(b&&m){b.addEventListener('click',function(e){e.stopPropagation();const open=m.style.display==='flex';m.style.display=open?'none':'flex';});document.addEventListener('click',function(e){if(!m.contains(e.target)&&!b.contains(e.target))m.style.display='none';});}});
</script>
</body>
</html>
"""


def navbar_html():
    announcement_link = '<a href="/readme" class="nav-link"><i class="fa-solid fa-bullhorn"></i> Announcement</a>' if announcement_exists() else ""
    mobile_announcement = '<a href="/readme"><i class="fa-solid fa-bullhorn"></i> Announcement</a>' if announcement_exists() else ""
    guide_link = '<a href="/guide" class="nav-link"><i class="fa-solid fa-book-open"></i> Guide</a>'
    mobile_guide = '<a href="/guide"><i class="fa-solid fa-book-open"></i> Guide</a>'
    show_status_link = has_explicit_backend_selection()
    status_link = '<a href="/status" class="nav-link"><i class="fa-solid fa-server"></i> Status</a>' if show_status_link else ""
    mobile_status_link = '<a href="/status"><i class="fa-solid fa-server"></i> Status</a>' if show_status_link else ""
    visitor_ip = html.escape(get_request_ip())
    return f"""
<nav class="navbar">
  <a href="/main" class="navbar-brand">
    <img src="/site-logo" alt="FUJI VPN" class="brand-icon">
    <span>FUJI VPN</span>
    <span style="display:inline-flex;align-items:center;font-size:.78rem;font-weight:700;color:var(--text-secondary);margin-left:.55rem;padding:.24rem .55rem;background:var(--surface);border-radius:999px;border:2px solid var(--card-border);box-shadow:3px 3px 0 rgba(93,9,25,.18);white-space:nowrap;">IP: {visitor_ip}</span>
  </a>
  <div class="navbar-nav">
    <a href="/main" class="nav-link"><i class="fa-solid fa-house"></i> Home</a>
    {status_link}
    {guide_link}
    <a href="/hostname-to-ip" class="nav-link"><i class="fa-solid fa-globe"></i> Hostname to IP</a>
    <a href="/ip-lookup" class="nav-link"><i class="fa-solid fa-location-dot"></i> IP Lookup</a>
    {announcement_link}
    <a href="/donate" class="nav-link"><i class="fa-solid fa-donate"></i> Donate</a>
  </div>
  <button class="burger-btn" id="navbar-burger" type="button"><i class="fa-solid fa-bars"></i></button>
  <div class="mobile-menu" id="mobile-menu">
    <a href="/main"><i class="fa-solid fa-house"></i> Home</a>
    {mobile_status_link}
    {mobile_guide}
    <a href="/hostname-to-ip"><i class="fa-solid fa-globe"></i> Hostname to IP</a>
    <a href="/ip-lookup"><i class="fa-solid fa-location-dot"></i> IP Lookup</a>
    {mobile_announcement}
    <a href="/donate"><i class="fa-solid fa-donate"></i> Donate</a>
  </div>
</nav>
"""


def footer_html():
    host = html.escape(current_host())
    year = html.escape(current_year_label())
    reset_time = html.escape(DAILY_RESET_TIME_LABEL)
    announcement_link = '<a href="/readme" class="footer-link"><i class="fa-solid fa-bullhorn"></i><span>Announcement</span></a>' if announcement_exists() else ""
    tools_tail_link = (
        '<a href="/status" class="footer-link"><i class="fa-solid fa-server"></i><span>Server Status</span></a>'
        if has_explicit_backend_selection()
        else '<a href="/main" class="footer-link"><i class="fa-solid fa-earth-asia"></i><span>Choose Server</span></a>'
    )
    return f"""
<footer class="site-footer">
  <div class="footer-shell">
    <div class="footer-grid">
      <div class="footer-brand-panel">
        <div class="footer-brand-row">
          <img src="/site-logo" alt="FUJI VPN" class="footer-logo">
          <div>
            <div class="footer-title">FUJI VPN</div>
            <div class="footer-subtitle">VPN Account Panel</div>
          </div>
        </div>
        <div class="footer-copy">Choose a server, create VPN accounts, review guides, and use quick network tools from one clean panel experience.</div>
        <div class="footer-badges">
          <span class="footer-badge"><i class="fa-solid fa-earth-asia"></i> Multi Server</span>
          <span class="footer-badge"><i class="fa-solid fa-bolt"></i> Fast Tools</span>
          <span class="footer-badge"><i class="fa-solid fa-shield-halved"></i> Panel Access</span>
        </div>
        <a class="footer-referral" href="https://www.digitalocean.com/?refcode=197466ae9d8c&utm_campaign=Referral_Invite&utm_medium=Referral_Program&utm_source=badge" target="_blank" rel="noopener noreferrer">
          <img src="https://web-platforms.sfo2.cdn.digitaloceanspaces.com/WWW/Badge%201.svg" alt="DigitalOcean Referral Badge" loading="lazy">
        </a>
      </div>
      <div class="footer-column">
        <div class="footer-heading">Explore</div>
        <div class="footer-link-list">
          <a href="/main" class="footer-link"><i class="fa-solid fa-house"></i><span>Home</span></a>
          <a href="/guide" class="footer-link"><i class="fa-solid fa-book-open"></i><span>Guide</span></a>
          <a href="/donate" class="footer-link"><i class="fa-solid fa-donate"></i><span>Donate</span></a>
          {announcement_link}
        </div>
      </div>
      <div class="footer-column">
        <div class="footer-heading">Tools</div>
        <div class="footer-link-list">
          <a href="/hostname-to-ip" class="footer-link"><i class="fa-solid fa-globe"></i><span>Hostname to IP</span></a>
          <a href="/ip-lookup" class="footer-link"><i class="fa-solid fa-location-dot"></i><span>IP Lookup</span></a>
          {tools_tail_link}
        </div>
      </div>
      <div class="footer-column">
        <div class="footer-heading">Legal</div>
        <div class="footer-link-list">
          <a href="/terms-of-service" class="footer-link"><i class="fa-solid fa-file-signature"></i><span>Terms of Service</span></a>
          <a href="/privacy-policy" class="footer-link"><i class="fa-solid fa-user-shield"></i><span>Privacy Policy</span></a>
        </div>
      </div>
    </div>
    <div class="footer-bottom">
      <div class="footer-meta">
        <span>Copyright {year} FUJI VPN</span>
        <span class="footer-separator">|</span>
        <span>Serving {host}</span>
        <span class="footer-separator">|</span>
        <span class="footer-reset-note"><i class="fa-regular fa-clock"></i> Daily limit reset: {reset_time}</span>
      </div>
      <div class="footer-bottom-links">
        <a href="/terms-of-service" class="footer-bottom-link">Terms</a>
        <a href="/privacy-policy" class="footer-bottom-link">Privacy</a>
      </div>
    </div>
  </div>
</footer>
"""


def render_page(title, content, show_ads=False):
    return render_template_string(
        BASE_TEMPLATE,
        title=title,
        navbar=Markup(navbar_html()),
        footer=Markup(footer_html()),
        content=Markup(content),
        show_ads=bool(ADS_ENABLED and show_ads),
    )


def build_service_cards():
    cards = []
    daily_limit = get_daily_account_limit()
    backend_id = selected_backend_id() or "default"
    enabled = backend_configured()
    for service, label, icon in SERVICE_META:
        service_created_today = get_scoped_daily_created_count(service=service, backend_id=backend_id)
        anchor_attr = "" if enabled else 'onclick="return false;"'
        button_attr = "" if enabled else "disabled"
        style_attr = "width:100%;display:flex;align-items:center;justify-content:space-between;gap:10px;padding:12px 14px;"
        if not enabled:
            style_attr += "opacity:.55;cursor:not-allowed;"
        cards.append(
            f"""
<div class="create-cell">
  <a href="/{service}" {anchor_attr}>
    <button class="create-btn" {button_attr} style="{style_attr}">
      <div style="display:flex;align-items:center;gap:10px;font-weight:700;color:var(--text-primary);"><img src="{icon}" style="height:1.1em;"> CREATE {label}</div>
      <div><span style="background:var(--primary-color);padding:4px 8px;border-radius:999px;font-weight:700;color:#fff;border:2px solid var(--ink);box-shadow:2px 2px 0 var(--ink);">Today {service_created_today}/{daily_limit}</span></div>
    </button>
  </a>
</div>"""
        )
    return "".join(cards)


def render_selected_server_note(change_href="/main", include_change=True, margin_style="margin:0 auto 1.35rem auto;"):
    current_backend = explicitly_selected_backend()
    if not current_backend:
        return ""
    backends = load_backends()
    backend_locations = backend_location_snapshots(backends)
    warm_backend_location_cache_async(backends)
    backend_geo = backend_locations.get(str(current_backend.get("id", "")).strip(), backend_location_snapshot(current_backend))
    location_bits = [bit for bit in [current_backend.get("city") or backend_geo.get("city", ""), current_backend.get("country") or backend_geo.get("country", "")] if bit]
    labels = build_backend_display_labels(backends=backends, backend_locations=backend_locations)
    display_label = str(labels.get(str(current_backend.get("id", "")).strip()) or _backend_base_display_label(current_backend, backend_geo) or "Unknown")
    change_link = ""
    if include_change:
        change_link = f'<a href="{html.escape(change_href)}" style="color:var(--accent-color);text-decoration:none;font-weight:700;">Change</a>'
    return (
        f'<div class="server-current-pill" style="{margin_style}max-width:1040px;">'
        '<span class="server-current-dot"></span>'
        '<span>Selected server</span>'
        f'<span class="server-current-name">{html.escape(display_label)}</span>'
        + (
            f'<span class="server-current-meta">{html.escape(", ".join(location_bits))}</span>'
            if location_bits
            else ""
        )
        + change_link
        + "</div>"
    )


def render_server_selector(redirect_to="/services", show_header=True):
    backends = load_backends()
    if not backends:
        return ""
    backend_locations = backend_location_snapshots(backends)
    warm_backend_location_cache_async(backends)
    display_labels = build_backend_display_labels(backends=backends, backend_locations=backend_locations)
    server_cards = []
    for backend in backends:
        backend_geo = backend_locations.get(backend["id"], {"country": "Unknown", "countryCode": "", "city": ""})
        display_label = display_labels.get(backend["id"]) or _backend_base_display_label(backend, backend_geo) or backend_host(backend)
        country = backend.get("country") or backend_geo.get("country") or backend.get("label") or "Unknown"
        city = backend.get("city") or backend_geo.get("city") or ""
        country_code = (backend.get("countryCode") or backend_geo.get("countryCode") or "").upper()
        flag_html = (
            f'<img class="server-flag" src="https://flagcdn.com/48x36/{country_code.lower()}.png" alt="{html.escape(country_code)} flag">'
            if country_code
            else '<span class="server-flag-fallback"><i class="fa-solid fa-globe"></i></span>'
        )
        active_class = ""
        badge_html = '<span class="server-badge"><i class="fa-solid fa-arrow-right"></i> Select</span>'
        location_bits = [bit for bit in [city, country] if bit]
        location_label = ", ".join(location_bits) if location_bits else backend_host(backend)
        health_html = (
            f'<div class="server-card-health is-checking" data-server-health data-backend-id="{html.escape(backend["id"])}">'
            '<span class="server-card-health-dot"></span>'
            '<span data-server-health-text>Checking ping...</span>'
            "</div>"
        )
        server_cards.append(
            f"""
      <form method="POST" action="/select-server" class="server-card-form">
        <input type="hidden" name="backend_id" value="{html.escape(backend['id'])}">
        <input type="hidden" name="redirect_to" value="{html.escape(redirect_to)}">
        <button type="submit" class="server-card-button{active_class}">
          <div class="server-card-main">
            {flag_html}
            <div class="server-copy">
              <div class="server-card-title">
                <span>{html.escape(display_label)}</span>
                {badge_html}
              </div>
              <div class="server-card-location"><i class="fa-solid fa-location-dot" style="color:var(--accent-color);margin-right:6px;"></i>{html.escape(location_label)}</div>
              {health_html}
            </div>
          </div>
          <div class="server-card-host"><i class="fa-solid fa-server" style="color:var(--accent-color);"></i><span>{html.escape(backend_host(backend))}</span></div>
        </button>
      </form>"""
        )
    header_html = ""
    if show_header:
        header_html = """
      <div class="server-selector-head">
        <div>
          <div class="server-selector-kicker"><i class="fa-solid fa-earth-asia"></i> Choose Country / Server</div>
        </div>
      </div>"""
    return f"""
    <div class="server-selector">
      {header_html}
      <div class="server-selector-grid">{''.join(server_cards)}</div>
    </div>"""

def render_home():
    bump_visit_count(async_remote=True)
    enabled = backend_configured()
    selector_html = render_server_selector("/services")
    page_error = (request.args.get("error", "") if has_request_context() else "").strip()
    return render_page(
        "FUJI VPN",
        render_template_string(
            """
<div class="container">
  <div class="neo-box" style="text-align:center;">
  <div style="display:flex;align-items:center;justify-content:center;gap:.8em;margin-bottom:1.5em;">
      <i class="fa-solid fa-earth-asia" style="font-size:1.8em;color:var(--accent-color);"></i>
      <h2 class="section-title" style="margin:0;">CHOOSE SERVER</h2>
    </div>
    {{ selector_html|safe }}
    {% if page_error %}
    <div class="success-msg" style="background:rgba(239,68,68,.1);border-left-color:var(--error);">
      <i class="fa-solid fa-circle-xmark" style="color:var(--error);"></i>
      <div>{{ page_error }}</div>
    </div>
    {% endif %}
    {% if not backend_ready %}
    <div class="success-msg" style="background:rgba(239,68,68,.1);border-left-color:var(--error);">
      <i class="fa-solid fa-plug-circle-xmark" style="color:var(--error);"></i>
      <div>Set <code>SERVER_BACKENDS_JSON</code>, numbered <code>SERVER_API_URL_1</code> / <code>SERVER_API_TOKEN_1</code> pairs, or <code>SERVER_API_URL</code> / <code>SERVER_API_TOKEN</code> in Vercel to enable account creation.</div>
    </div>
    {% endif %}
  </div>
</div>
<script>
function formatServerHealthText(data){if(!data)return'Ping unavailable';if(data.alive){const latency=Number(data.latency_ms);if(Number.isFinite(latency)&&latency>0)return'Ping '+Math.round(latency)+' ms';return data.text||'Alive';}return data.text||'Ping unavailable';}
function applyServerHealth(node,data){if(!node)return;const text=node.querySelector('[data-server-health-text]');node.classList.remove('is-checking','is-alive','is-dead');if(data&&data.alive){node.classList.add('is-alive');if(text)text.textContent=formatServerHealthText(data);return;}node.classList.add('is-dead');if(text)text.textContent=formatServerHealthText(data);}
function appendPingCandidate(list,url,mode){const value=String(url||'').trim();if(!value)return;if(window.location.protocol==='https:'&&/^http:\/\//i.test(value))return;if(list.some(item=>item.url===value))return;list.push({url:value,mode:mode||'cors'});}
function buildPingCandidates(status){const list=[];if(status&&status.health_url)appendPingCandidate(list,status.health_url,'cors');const rawHosts=[];if(Array.isArray(status&&status.probe_hosts))status.probe_hosts.forEach(host=>rawHosts.push(String(host||'')));rawHosts.push(String((status&&status.host)||''));const hosts=[];rawHosts.forEach(host=>{const clean=host.trim();if(clean&&!hosts.includes(clean))hosts.push(clean);});const protocol=window.location.protocol==='http:'?'http:':'https:';const port=Number((status&&status.port)||0);hosts.forEach(host=>{const portPart=port&&!(protocol==='https:'&&port===443)&&!(protocol==='http:'&&port===80)?':'+port:'';appendPingCandidate(list,protocol+'//'+host+'/favicon.ico','image');appendPingCandidate(list,protocol+'//'+host+portPart+'/healthz','no-cors');appendPingCandidate(list,protocol+'//'+host+'/healthz','no-cors');appendPingCandidate(list,protocol+'//'+host+'/favicon.ico','no-cors');appendPingCandidate(list,protocol+'//'+host+'/','no-cors');});return list;}
function pingWithImage(url){return new Promise(resolve=>{const img=new Image();const start=(window.performance&&typeof window.performance.now==='function')?window.performance.now():Date.now();let finished=false;const cleanup=()=>{finished=true;img.onload=null;img.onerror=null;img.src='';};const timer=setTimeout(()=>{if(finished)return;cleanup();resolve(null);},4000);img.onload=()=>{if(finished)return;clearTimeout(timer);const end=(window.performance&&typeof window.performance.now==='function')?window.performance.now():Date.now();cleanup();resolve({alive:true,latency_ms:Math.max(1,Math.round(end-start)),text:'',source:'client'});};img.onerror=()=>{if(finished)return;clearTimeout(timer);cleanup();resolve(null);};img.referrerPolicy='no-referrer';img.src=url+(url.includes('?')?'&':'?')+'_ping='+Date.now();});}
async function pingCandidate(candidate){if(!candidate||!candidate.url)return null;if((candidate.mode||'cors')==='image'){const imageResult=await pingWithImage(candidate.url);if(imageResult){imageResult.text='Ping '+imageResult.latency_ms+' ms';}return imageResult;}const controller=typeof AbortController==='function'?new AbortController():null;const timer=controller?setTimeout(()=>controller.abort(),4000):null;const start=(window.performance&&typeof window.performance.now==='function')?window.performance.now():Date.now();try{const target=candidate.url+(candidate.url.includes('?')?'&':'?')+'_ping='+Date.now();const response=await fetch(target,{method:'GET',mode:candidate.mode||'cors',cache:'no-store',credentials:'omit',signal:controller?controller.signal:void 0});if((candidate.mode||'cors')==='cors'&&!response.ok)throw new Error('HTTP '+response.status);if((candidate.mode||'cors')==='cors')await response.text();const end=(window.performance&&typeof window.performance.now==='function')?window.performance.now():Date.now();const latency=Math.max(1,Math.round(end-start));return {alive:true,latency_ms:latency,text:'Ping '+latency+' ms',source:'client'};}catch(_error){return null;}finally{if(timer)clearTimeout(timer);}}
async function measureBrowserPing(status){const candidates=buildPingCandidates(status);if(!candidates.length)return {alive:false,text:'Ping unavailable',source:'client'};for(const candidate of candidates){const result=await pingCandidate(candidate);if(result)return result;}return {alive:false,text:'Dead',source:'client'};}
function mergeServerHealth(browserStatus,fallback){if(browserStatus&&browserStatus.alive)return browserStatus;if(fallback&&fallback.alive)return {alive:true,text:'Alive',source:'panel'};return browserStatus||fallback||{alive:false,text:'Dead'};}
let serverHealthUpdating=false;
async function updateServerHealth(){if(serverHealthUpdating)return;serverHealthUpdating=true;try{const response=await fetch('/main/server-health?t='+Date.now(),{cache:'no-store'});const data=await response.json();const statuses=(data&&data.statuses)||{};const nodes=Array.from(document.querySelectorAll('[data-server-health]'));const grouped=new Map();nodes.forEach(node=>{const backendId=node.getAttribute('data-backend-id')||'';if(!grouped.has(backendId))grouped.set(backendId,[]);grouped.get(backendId).push(node);});await Promise.all(Array.from(grouped.entries()).map(async entry=>{const backendId=entry[0];const backendNodes=entry[1];const status=statuses[backendId]||null;const browserStatus=await measureBrowserPing(status);const merged=mergeServerHealth(browserStatus,status);backendNodes.forEach(node=>applyServerHealth(node,merged));}));}catch(_error){}finally{serverHealthUpdating=false;}}
updateServerHealth();setInterval(updateServerHealth,15000);
</script>
""",
            selector_html=Markup(selector_html),
            page_error=page_error,
            backend_ready=enabled,
        ),
    )


def render_services():
    if not backend_configured():
        return render_unavailable("Service")
    selection_redirect = require_backend_selection()
    if selection_redirect:
        return selection_redirect
    current_server_note = render_selected_server_note(change_href="/main", include_change=True)
    cards = build_service_cards()
    page_error = (request.args.get("error", "") if has_request_context() else "").strip()
    return render_page(
        "Service",
        render_template_string(
            """
<div class="container">
  <div class="neo-box" style="text-align:center;">
    <div style="display:flex;align-items:center;justify-content:center;gap:.8em;margin-bottom:1.5em;">
      <i class="fa-solid fa-layer-group" style="font-size:1.8em;color:var(--accent-color);"></i>
      <h2 class="section-title" style="margin:0;">SERVICE</h2>
    </div>
    <div style="font-size:1rem;color:var(--text-secondary);margin-bottom:1.6rem;">Choose a protocol or service for the selected server.</div>
    <style>.create-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px;margin:0 auto;max-width:980px}.create-cell a{text-decoration:none;display:block}@media (max-width:700px){.create-grid{grid-template-columns:1fr}}</style>
    {{ current_server_note|safe }}
    {% if page_error %}
    <div class="success-msg" style="background:rgba(239,68,68,.1);border-left-color:var(--error);">
      <i class="fa-solid fa-circle-xmark" style="color:var(--error);"></i>
      <div>{{ page_error }}</div>
    </div>
    {% endif %}
    <div style="margin:2rem 0;"><div class="create-grid">{{ cards|safe }}</div></div>
  </div>
</div>
""",
            current_server_note=Markup(current_server_note),
            cards=Markup(cards),
            page_error=page_error,
        ),
    )


def render_status():
    selection_redirect = require_backend_selection()
    if selection_redirect:
        return selection_redirect
    current_server_note = render_selected_server_note(change_href="/main", include_change=True)
    return render_page(
        "Server Status",
        render_template_string(
            """
<div class="container"><div class="neo-box">
  <div style="display:flex;align-items:center;justify-content:center;gap:.8em;margin-bottom:1.5em;"><i class="fa-solid fa-server" style="font-size:1.8em;color:var(--accent-color);"></i><h2 class="section-title" style="margin:0;">Server Status</h2></div>
  {{ current_server_note|safe }}
  <div id="status-source-note" class="success-msg" style="display:none;"></div>
  <div class="status-subtitle"><i class="fa-solid fa-network-wired"></i> Network Traffic</div><div class="status-grid-2" id="network-grid"></div>
  <div class="status-subtitle"><i class="fa-solid fa-microchip"></i> System Resources</div><div class="status-grid-2" id="status-grid"></div>
  <div class="status-subtitle"><i class="fa-solid fa-plug"></i> Services</div><div class="services-grid" id="services-container"></div>
</div></div>
<script>
function escapeHtml(v){return String(v??'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',\"'\":'&#39;'}[m]));}
function formatSpeed(v){if(v>1024*1024)return (v/1024/1024).toFixed(2)+' MB/s';if(v>1024)return (v/1024).toFixed(2)+' KB/s';return v.toFixed(0)+' B/s';}
function formatBytes(v){if(v>1024*1024*1024)return (v/1024/1024/1024).toFixed(2)+' GB';if(v>1024*1024)return (v/1024/1024).toFixed(2)+' MB';if(v>1024)return (v/1024).toFixed(2)+' KB';return v.toFixed(0)+' B';}
function updateStatus(){fetch('/status/full?t='+Date.now()).then(r=>r.json()).then(data=>{const note=document.getElementById('status-source-note');if(note){if(data.backend_error){note.style.display='flex';note.style.background='rgba(239,68,68,.1)';note.style.borderColor='var(--error)';note.innerHTML=`<i class="fa-solid fa-triangle-exclamation" style="color:var(--error);"></i><div>Could not read the selected server status right now. ${escapeHtml(data.backend_error||'')}</div>`;}else{note.style.display='none';note.innerHTML='';}}document.getElementById('network-grid').innerHTML=`<div class="status-card"><div class="status-label"><i class="fa-solid fa-arrow-down" style="color:var(--success)"></i> Download Speed</div><div class="status-value">${formatSpeed(Number(data.net?.rx_rate||0))}</div></div><div class="status-card"><div class="status-label"><i class="fa-solid fa-arrow-up" style="color:var(--accent-color)"></i> Upload Speed</div><div class="status-value">${formatSpeed(Number(data.net?.tx_rate||0))}</div></div><div class="status-card"><div class="status-label"><i class="fa-solid fa-database" style="color:var(--success)"></i> Total Downloaded</div><div class="status-value">${formatBytes(Number(data.net?.rx_bytes||0))}</div></div><div class="status-card"><div class="status-label"><i class="fa-solid fa-database" style="color:var(--accent-color)"></i> Total Uploaded</div><div class="status-value">${formatBytes(Number(data.net?.tx_bytes||0))}</div></div>`;document.getElementById('status-grid').innerHTML=`<div class="status-card"><div class="status-label"><i class="fa-solid fa-microchip" style="color:var(--primary-color)"></i> CPU Usage</div><div class="status-value">${Number(data.cpu||0)}%</div></div><div class="status-card"><div class="status-label"><i class="fa-solid fa-chart-line" style="color:var(--accent-color)"></i> Load Average</div><div class="status-value">${Array.isArray(data.load)?data.load.join(', '):'0.00, 0.00, 0.00'}</div></div><div class="status-card"><div class="status-label"><i class="fa-solid fa-memory" style="color:var(--success)"></i> Memory Used</div><div class="status-value">${Number(data.mem?.used||0)} / ${Number(data.mem?.total||0)} MB</div></div><div class="status-card"><div class="status-label"><i class="fa-solid fa-memory" style="color:var(--primary-color)"></i> Memory Available</div><div class="status-value">${Number(data.mem?.available||0)} MB</div></div><div class="status-card"><div class="status-label"><i class="fa-solid fa-hdd" style="color:var(--accent-color)"></i> Storage Used</div><div class="status-value">${Number(data.storage?.used||0)} / ${Number(data.storage?.total||0)} MB</div></div><div class="status-card"><div class="status-label"><i class="fa-solid fa-hdd" style="color:var(--success)"></i> Storage Free</div><div class="status-value">${Number(data.storage?.free||0)} MB</div></div>`;let s='';(data.services||[]).forEach(x=>{const name=escapeHtml(x[0]);let icon='',label='',color='var(--text-muted)';if(x[1]===true){icon='<i class="fa-solid fa-circle-check" style="color:var(--success)"></i>';label='ONLINE';color='var(--success)';}else if(x[1]===false){icon='<i class="fa-solid fa-circle-xmark" style="color:var(--error)"></i>';label='OFFLINE';color='var(--error)';}else{icon='<i class="fa-solid fa-circle-question" style="color:var(--warning)"></i>';label='UNKNOWN';color='var(--warning)';}s+=`<div class="service-item"><div style="display:flex;align-items:center;justify-content:space-between;gap:10px;"><div>${icon} ${name}</div><div style="font-weight:700;color:${color};">${label}</div></div></div>`;});document.getElementById('services-container').innerHTML=s;}).catch(()=>{});}
updateStatus();setInterval(updateStatus,2000);
</script>
""",
            current_server_note=Markup(current_server_note),
        ),
    )


def render_unavailable(service_name):
    return render_page(
        f"{service_name} Not Available",
        f"""
<div class="container"><div class="neo-box" style="max-width:500px;margin:0 auto;text-align:center;">
  <div style="color:var(--error);font-size:3rem;margin-bottom:1rem;"><i class="fa-solid fa-circle-exclamation"></i></div>
  <h2 class="section-title" style="color:var(--error);">{html.escape(service_name)} Not Available</h2>
  <div style="margin:1.5rem 0;color:var(--text-secondary);">This Vercel deployment keeps the design, but real account provisioning still needs a Linux VPS backend.</div>
  <a href="/main" style="text-decoration:none;"><button><i class="fa-solid fa-arrow-left"></i> Back to Main</button></a>
</div></div>""",
    )


def service_label(service):
    for slug, label, _icon in SERVICE_META:
        if slug == service:
            return label
    return service.upper()


def service_icon(service):
    for slug, _label, icon in SERVICE_META:
        if slug == service:
            return icon
    return ""


def render_service_form(service, error=None, values=None):
    if not backend_configured():
        return render_unavailable(service_label(service))
    selection_redirect = require_backend_selection()
    if selection_redirect:
        return selection_redirect
    values = values or {}
    label = service_label(service)
    icon = service_icon(service)
    days = get_create_account_expiry(service)
    current_backend_note = render_selected_server_note(change_href="/main", include_change=True, margin_style="margin:-.8rem auto 1.4rem auto;")
    username_value = html.escape(values.get("username", ""))
    password_value = html.escape(values.get("password", ""))
    bypass_value = values.get("bypass_option", "")
    turnstile_ready = turnstile_configured()
    turnstile_site = html.escape(turnstile_site_key())
    callback_prefix = f"turnstile_{service}"
    turnstile_help_id = f"{service}-turnstile-help"
    error_html = ""
    if error:
        error_html = f'<div class="success-msg" style="background:rgba(239,68,68,.1);border-left-color:var(--error);"><i class="fa-solid fa-circle-xmark" style="color:var(--error);"></i><div>{html.escape(error)}</div></div>'
    password_group = ""
    if service not in {"vless", "wireguard"}:
        password_group = f"""
      <div class="form-group">
        <label for="{service}-password" class="form-label"><i class="fa-solid fa-key"></i> Password</label>
        <div class="form-input-container">
          <input name="password" id="{service}-password" type="password" placeholder="Enter password" required minlength="4" maxlength="32" value="{password_value}">
        </div>
      </div>"""
    extra_group = ""
    if service == "vless":
        bypass_options = get_vless_bypass_options()
        bypass_choices = [f'<option value=""{" selected" if bypass_value == "" else ""}>Default</option>']
        for option in bypass_options:
            option_id = html.escape(str(option.get("id", "")))
            option_name = html.escape(str(option.get("name", "Custom Bypass")))
            selected = " selected" if bypass_value == option.get("id") else ""
            bypass_choices.append(f'<option value="{option_id}"{selected}>{option_name}</option>')
        extra_group = f"""
      <div class="form-group">
        <label for="vless-bypass" class="form-label"><i class="fa-solid fa-shield-alt"></i> BYPASS OPTIONS</label>
        <div class="form-input-container">
          <select name="bypass_option" id="vless-bypass">
            {''.join(bypass_choices)}
          </select>
        </div>
      </div>"""
    security_html = f"""
    <div class="success-msg turnstile-config-note" style="background:rgba(239,68,68,.08);border-left-color:var(--warning);margin-top:-.2rem;">
      <i class="fa-solid fa-shield-halved" style="color:var(--warning);"></i>
      <div>{html.escape(turnstile_setup_message())}</div>
    </div>"""
    if turnstile_ready:
        security_html = f"""
      <div class="form-group">
        <label class="form-label"><i class="fa-solid fa-shield-halved"></i> Security Check</label>
        <div class="turnstile-shell">
          <div class="cf-turnstile"
               data-sitekey="{turnstile_site}"
               data-theme="light"
               data-size="flexible"
               data-callback="{callback_prefix}_success"
               data-expired-callback="{callback_prefix}_expired"
               data-error-callback="{callback_prefix}_error"></div>
        </div>
        <div class="turnstile-help" id="{turnstile_help_id}">Complete the captcha before creating your account.</div>
      </div>"""
    submit_disabled_attr = ' disabled aria-disabled="true"'
    turnstile_script = '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>' if turnstile_ready else ""
    content = f"""
<div class="container"><div class="neo-box" style="max-width:500px;margin:0 auto;text-align:center;">
  <div style="display:flex;align-items:center;justify-content:center;gap:.8em;margin-bottom:1.5em;">
    <img src="{icon}" style="height:1.8em;vertical-align:middle;margin-right:.2em;">
    <h2 class="section-title" style="margin:0;">Create {label} Account</h2>
  </div>
  <div style="font-size:1rem;color:var(--text-secondary);margin-bottom:2rem;">Create {label} account ({days} days)</div>
  {current_backend_note}
  {error_html}
  <form method="POST" action="/{service}">
    <div class="form-group">
      <label for="{service}-username" class="form-label"><i class="fa-solid fa-user"></i> Username</label>
      <div class="form-input-container">
        <input name="username" id="{service}-username" type="text" placeholder="Enter username" required pattern="[a-zA-Z0-9_]+" maxlength="20" value="{username_value}">
      </div>
    </div>
    {password_group}
    {extra_group}
    {security_html}
    <button type="submit"{submit_disabled_attr} style="width:100%;max-width:400px;margin:0 auto;"><i class="fa-solid fa-user-plus"></i> Create Account</button>
  </form>
  <script>
  (function() {{
    var form = document.querySelector("form[action='/{service}']");
    if (!form) return;
    var submitButton = form.querySelector('button[type="submit"]');
    var help = document.getElementById('{turnstile_help_id}');
    var turnstileReady = {str(turnstile_ready).lower()};
    function setCaptchaState(ready, message) {{
      form.dataset.turnstileComplete = ready ? 'true' : 'false';
      if (submitButton) submitButton.disabled = !ready;
      if (help && message) help.textContent = message;
    }}
    if (turnstileReady) {{
      setCaptchaState(false, 'Complete the captcha before creating your account.');
      window.{callback_prefix}_success = function(token) {{
        setCaptchaState(!!token, 'Security check complete. You can create the account now.');
      }};
      window.{callback_prefix}_expired = function() {{
        setCaptchaState(false, 'Captcha expired. Please complete it again.');
      }};
      window.{callback_prefix}_error = function() {{
        setCaptchaState(false, 'Captcha failed to load. Refresh the page and try again.');
      }};
    }} else {{
      form.dataset.turnstileComplete = 'false';
      if (submitButton) submitButton.disabled = true;
    }}
    form.addEventListener('submit', function(e) {{
      if (!form.checkValidity()) return;
      if (form.dataset.turnstileComplete !== 'true') {{
        e.preventDefault();
        if (help) {{
          help.textContent = turnstileReady
            ? 'Complete the captcha before creating your account.'
            : 'Account creation is temporarily unavailable right now.';
        }}
        return;
      }}
      e.preventDefault();
      if (submitButton) submitButton.disabled = true;
      var overlay = document.getElementById('loadingOverlay');
      if (overlay) overlay.classList.add('active');
      setTimeout(function() {{ form.submit(); }}, 1000);
    }});
  }})();
  </script>
  {turnstile_script}
  <a href="/services" style="display:block;margin-top:1.5rem;text-decoration:none;">
    <button style="width:100%;max-width:400px;margin:0 auto;background:var(--surface);color:var(--text-primary);border:3px solid var(--card-border);box-shadow:5px 5px 0 rgba(93,9,25,.22);"><i class="fa-solid fa-arrow-left"></i> Back to Service</button>
  </a>
</div></div>"""
    return render_page(label, content)


def render_service_result(service, result):
    label = service_label(service)
    icon = service_icon(service)
    expiry = format_expiry(result.get("expires_at"))
    username = html.escape(str(result.get("username", "")))
    password = html.escape(str(result.get("password", "")))
    domain = html.escape(str(result.get("domain", current_host())))
    current_backend = selected_backend()
    backend_name = html.escape(backend_display_label(current_backend)) if current_backend else ""
    ssh_details_raw = ""
    if service == "ssh":
        for key in ("ssh_details", "server_info", "details", "output", "info", "message"):
            value = result.get(key)
            if isinstance(value, str) and value.strip():
                ssh_details_raw = value
                break
        noisy_sources = [ssh_details_raw]
        for key in ("ip", "domain", "nameserver", "public_key"):
            value = result.get(key)
            if isinstance(value, str) and value.strip():
                noisy_sources.append(value)
        combined_ssh_text = "\n".join(part for part in noisy_sources if part)
        clean_ip = str(result.get("ip", "")).strip()
        if not re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", clean_ip):
            clean_ip = extract_labeled_value(combined_ssh_text, ["IP"]) or extract_ipv4(combined_ssh_text) or backend_host(current_backend)
        clean_domain = str(result.get("domain", "")).strip()
        if not clean_domain or "PORTS INFORMATION" in clean_domain or "\x1b[" in clean_domain or len(clean_domain) > 120:
            clean_domain = extract_labeled_value(combined_ssh_text, ["A"]) or clean_domain or current_host()
        clean_nameserver = str(result.get("nameserver", "")).strip()
        if not clean_nameserver or "PORTS INFORMATION" in clean_nameserver or "\x1b[" in clean_nameserver or len(clean_nameserver) > 180:
            clean_nameserver = extract_labeled_value(combined_ssh_text, ["NS", "Nameserver"]) or "Not configured"
        clean_public_key = str(result.get("public_key", "")).strip()
        if not clean_public_key or "PORTS INFORMATION" in clean_public_key or "\x1b[" in clean_public_key or len(clean_public_key) > 200:
            clean_public_key = extract_labeled_value(combined_ssh_text, ["Public Key"]) or "Not configured"
        domain = html.escape(clean_domain)
    content = f"""
<div class="container"><div class="neo-box">
  <div class="success-msg"><i class="fa-solid fa-circle-check"></i><div>Success! Your {label} account has been created.</div></div>
  <div class="info-grid">
    {"<div>Server:</div><div>" + backend_name + "</div>" if current_backend else ""}
    <div>Service:</div><div>{html.escape(label)}</div>
    <div>Username:</div><div>{username}</div>
    {"<div>Password:</div><div>" + password + "</div>" if result.get("password") else ""}
    <div>Domain:</div><div>{domain}</div>
    <div>Expires:</div><div>{html.escape(expiry)}</div>
  </div>"""
    if service == "ssh":
        ports_html = """
  <div class="link-box">
    <div class="link-title tls"><img src="https://raw.githubusercontent.com/hahacrunchyrollls/logo-s/refs/heads/main/icon-ssh.png" style="height:1.05em;"> Ports Information</div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:.7rem 1rem;">
      <div>SSH</div><div>22, 80, 443</div>
      <div>SSH + WS</div><div>80, 443</div>
      <div>SSH + SSL</div><div>80, 443</div>
      <div>SSH + WS + SSL</div><div>80, 443</div>
      <div>XRAY + WS</div><div>80, 443</div>
      <div>XRAY + WS + TLS</div><div>80, 443</div>
      <div>OPENVPN TCP</div><div>80, 443, 1194</div>
      <div>SQUID</div><div>80, 443, 8080</div>
      <div>UDP HYSTERIA</div><div>10000-65000</div>
      <div>DNSTT</div><div>5300</div>
      <div>SLIPSTREAM</div><div>5300</div>
      <div>BADVPN-UDPGW</div><div>7300</div>
    </div>
  </div>"""
        services_html = render_service_status_summary()
        content += f"""
  <div class="info-grid">
    <div>IP:</div><div>{html.escape(clean_ip or "N/A")}</div>
    <div>Nameserver:</div><div>{html.escape(clean_nameserver or "Not configured")}</div>
    <div>Public Key:</div><div>{html.escape(clean_public_key or "Not configured")}</div>
  </div>
  {ports_html}
  {services_html}"""
        if ssh_details_raw:
            formatted_details = html.escape(format_ssh_details_text(ssh_details_raw))
            content += f"""
  <div class="link-box">
    <div class="link-title tls"><img src="https://raw.githubusercontent.com/hahacrunchyrollls/logo-s/refs/heads/main/icon-ssh.png" style="height:1.05em;"> SSH Server Details</div>
    <pre style="margin:0;white-space:pre-wrap;word-break:break-word;font-family:ui-monospace,'Cascadia Code','SF Mono',monospace;color:var(--text-primary);">{formatted_details}</pre>
  </div>"""
    elif service == "vless":
        tls_link = html.escape(str(result.get("tls_link", "")))
        nontls_link = html.escape(str(result.get("nontls_link", "")))
        content += f"""
  <div class="link-box"><div class="link-title tls"><img src="{icon}" style="height:1.05em;"> VLESS WS TLS</div><div style="display:flex;align-items:center;gap:.4em;"><input type="text" readonly value="{tls_link}"><sl-copy-button value="{tls_link}"></sl-copy-button></div></div>
  <div class="link-box"><div class="link-title tls"><img src="{icon}" style="height:1.05em;"> VLESS WS Non-TLS</div><div style="display:flex;align-items:center;gap:.4em;"><input type="text" readonly value="{nontls_link}"><sl-copy-button value="{nontls_link}"></sl-copy-button></div></div>"""
    elif service == "hysteria":
        link = html.escape(str(result.get("link", "")))
        legacy_link = html.escape(str(result.get("legacy_link", "")))
        obfs_value = str(result.get("obfs", "")).strip() or "Not configured"
        content += f"""
  <div class="info-grid"><div>Obfs:</div><div>{html.escape(obfs_value)}</div></div>
  <div class="link-box"><div class="link-title tls"><img src="{icon}" style="height:1.05em;"> Hysteria Link (HTTP Injector)</div><div style="display:flex;align-items:center;gap:.4em;"><input type="text" readonly value="{link}"><sl-copy-button value="{link}"></sl-copy-button></div></div>"""
        if legacy_link and legacy_link != link:
            content += f"""
  <div class="link-box"><div class="link-title tls"><img src="{icon}" style="height:1.05em;"> Legacy Hysteria URI</div><div style="display:flex;align-items:center;gap:.4em;"><input type="text" readonly value="{legacy_link}"><sl-copy-button value="{legacy_link}"></sl-copy-button></div></div>"""
    elif service == "wireguard":
        config_text = str(result.get("config_content", ""))
        config_json = json.dumps(config_text)
        filename = json.dumps(f"{result.get('username', 'wireguard')}.conf")
        endpoint = html.escape(str(result.get("endpoint", domain)))
        client_ip = html.escape(str(result.get("client_ip", "")).strip() or "N/A")
        qr_base64 = str(result.get("qr_png_base64", "") or "").strip()
        qr_data_uri = f"data:image/png;base64,{qr_base64}" if qr_base64 else ""
        qr_data_uri_attr = html.escape(qr_data_uri, quote=True)
        qr_download_name = json.dumps(f"{result.get('username', 'wireguard')}.png")
        qr_html = ""
        if qr_data_uri:
            qr_html = f"""
  <div class="link-box" style="text-align:center;">
    <div class="link-title tls"><img src="{icon}" style="height:1.05em;"> WireGuard QR Code</div>
    <img src="{qr_data_uri_attr}" alt="WireGuard QR Code" style="width:min(100%,320px);height:auto;margin:1rem auto 0 auto;display:block;border-radius:18px;border:3px solid var(--card-border);background:#fff;padding:12px;box-shadow:4px 4px 0 rgba(93,9,25,.16);">
    <button onclick="downloadWireGuardQr()" style="width:100%;margin-top:1rem;"><i class="fa-solid fa-qrcode"></i> Download QR Code</button>
  </div>"""
        else:
            qr_html = f"""
  <div class="link-box">
    <div class="link-title tls"><img src="{icon}" style="height:1.05em;"> WireGuard QR Code</div>
    <div style="color:var(--text-secondary);margin-top:.85rem;">QR code image is not available right now. The server may be missing <code>qrencode</code>, but the WireGuard config file is ready below.</div>
  </div>"""
        content += f"""
  <div class="info-grid">
    <div>Endpoint:</div><div>{endpoint}</div>
    <div>Client IP:</div><div>{client_ip}</div>
  </div>
  {qr_html}
  <div class="link-box">
    <div class="link-title tls"><img src="{icon}" style="height:1.05em;"> WireGuard Config</div>
    <textarea readonly style="width:100%;min-height:220px;padding:12px;border-radius:14px;border:3px solid var(--card-border);background:rgba(255,255,255,.9);color:var(--text-primary);font-family:ui-monospace,'Cascadia Code','SF Mono',monospace;resize:vertical;">{html.escape(config_text)}</textarea>
  </div>
  <button onclick="downloadWireGuardConfig()" style="width:100%;margin-top:1rem;"><i class="fa-solid fa-download"></i> Download WireGuard Config</button>
  <script>
  function downloadWireGuardConfig() {{
    const content = {config_json};
    const blob = new Blob([content], {{ type: 'text/plain;charset=utf-8' }});
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = {filename};
    document.body.appendChild(anchor);
    anchor.click();
    document.body.removeChild(anchor);
    setTimeout(function() {{ URL.revokeObjectURL(url); }}, 1000);
  }}
  function downloadWireGuardQr() {{
    const source = {json.dumps(qr_data_uri)};
    if (!source) return;
    const anchor = document.createElement('a');
    anchor.href = source;
    anchor.download = {qr_download_name};
    document.body.appendChild(anchor);
    anchor.click();
    document.body.removeChild(anchor);
  }}
  </script>"""
    elif service == "openvpn":
        ovpn_content = json.dumps(str(result.get("ovpn_content", "")))
        filename = json.dumps(f"{result.get('username', 'openvpn')}.ovpn")
        content += f"""
  <button onclick="downloadOvpn()" style="width:100%;margin-top:1rem;"><i class="fa-solid fa-download"></i> Download OVPN File</button>
  <script>
  function downloadOvpn() {{
    const content = {ovpn_content};
    const blob = new Blob([content], {{ type: 'application/x-openvpn-profile' }});
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = {filename};
    document.body.appendChild(anchor);
    anchor.click();
    document.body.removeChild(anchor);
    setTimeout(function() {{ URL.revokeObjectURL(url); }}, 1000);
  }}
  </script>"""
    content += """
  <a href="/services" style="display:block;margin-top:1rem;text-decoration:none;">
    <button style="width:100%;background:var(--surface);color:var(--text-primary);border:3px solid var(--card-border);box-shadow:5px 5px 0 rgba(93,9,25,.22);"><i class="fa-solid fa-arrow-left"></i> Back to Service</button>
  </a>
</div></div>"""
    return render_page(label, content)


def render_lookup_pages():
    hostname_page = """
<div class="container"><div class="neo-box" style="max-width:500px;margin:0 auto;text-align:center;">
  <div style="display:flex;align-items:center;justify-content:center;gap:.8em;margin-bottom:1.5em;"><i class="fa-solid fa-globe" style="font-size:1.8em;color:var(--accent-color);"></i><h2 class="section-title" style="margin:0;">Hostname to IP</h2></div>
  <form id="hostname-form" method="POST" action="/hostname-to-ip" style="margin-bottom:2em;">
    <div class="form-group"><label for="hostname" class="form-label"><i class="fa-solid fa-globe"></i> Hostname</label><div class="form-input-container"><input name="hostname" id="hostname" type="text" placeholder="Enter hostname (e.g. google.com)" required maxlength="255"></div></div>
    <button type="submit" style="width:100%;max-width:400px;margin:0 auto;"><i class="fa-solid fa-magnifying-glass"></i> Check IP Address</button>
  </form><div id="hostname-result"></div>
</div></div>
<script>
document.getElementById('hostname-form').addEventListener('submit',function(e){e.preventDefault();const hostname=document.getElementById('hostname').value.trim();const resultDiv=document.getElementById('hostname-result');resultDiv.innerHTML='<div style="color:var(--text-muted);margin-top:1em;"><i class="fa-solid fa-spinner fa-spin"></i> Checking...</div>';fetch('/hostname-to-ip',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'hostname='+encodeURIComponent(hostname)}).then(r=>r.text()).then(html=>{resultDiv.innerHTML=html;}).catch(()=>{resultDiv.innerHTML='<div style="color:var(--error);margin-top:1em;">Error checking hostname.</div>';});});
</script>"""
    ip_page = """
<div class="container"><div class="neo-box" style="max-width:600px;margin:0 auto;text-align:center;">
  <div style="display:flex;align-items:center;justify-content:center;gap:.8em;margin-bottom:1.5em;"><i class="fa-solid fa-location-dot" style="font-size:1.8em;color:var(--accent-color);"></i><h2 class="section-title" style="margin:0;">IP Lookup</h2></div>
  <form id="ip-form" method="POST" action="/ip-lookup" style="margin-bottom:2em;">
    <div class="form-group"><label for="ip" class="form-label"><i class="fa-solid fa-network-wired"></i> IP Address</label><div class="form-input-container"><input name="ip" id="ip" type="text" placeholder="Enter IP (leave blank for your IP)" maxlength="255"></div></div>
    <button type="submit" style="width:100%;max-width:400px;margin:0 auto;"><i class="fa-solid fa-magnifying-glass"></i> Lookup</button>
  </form><div id="ip-result"></div>
</div></div>
<script>
document.getElementById('ip-form').addEventListener('submit',function(e){e.preventDefault();const ip=document.getElementById('ip').value.trim();const resultDiv=document.getElementById('ip-result');resultDiv.innerHTML='<div style="color:var(--text-muted);margin-top:1em;"><i class="fa-solid fa-spinner fa-spin"></i> Looking up...</div>';fetch('/ip-lookup',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'ip='+encodeURIComponent(ip)}).then(r=>r.text()).then(html=>{resultDiv.innerHTML=html;}).catch(()=>{resultDiv.innerHTML='<div style="color:var(--error);margin-top:1em;">Error performing lookup.</div>';});});
</script>"""
    return hostname_page, ip_page


def render_donate():
    return render_page(
        "Donate",
        """
<div class="container"><div class="neo-box" style="max-width:720px;margin:0 auto;text-align:center;">
  <div style="display:flex;align-items:center;justify-content:center;gap:.8em;margin-bottom:1rem;"><i class="fa-solid fa-donate" style="font-size:1.6em;color:var(--primary-color);"></i><h2 class="section-title" style="margin:0;">Gcash Donation</h2></div>
  <div style="margin-top:.6rem;"><img src="https://raw.githubusercontent.com/hahacrunchyrollls/logo-s/refs/heads/main/Donate.png" alt="Donate" style="max-width:100%;height:auto;border-radius:12px;border:1px solid var(--card-border);"></div>
  <div style="margin-top:1rem;color:var(--text-secondary);">Thank you for supporting all donation will be appreciated.</div>
  <a href="/main" style="display:block;margin-top:1.2rem;text-decoration:none;"><button style="width:100%;max-width:320px;margin:.8rem auto 0;display:block;"><i class="fa-solid fa-arrow-left"></i> Back to Main</button></a>
</div></div>""",
    )


def render_legal_page(page_title, heading, icon_class, intro_html, sections_html):
    updated_label = html.escape(legal_last_updated_label())
    return render_page(
        page_title,
        f"""
<div class="container legal-card">
  <div class="neo-box">
    <div style="display:flex;align-items:center;justify-content:center;gap:.8em;margin-bottom:1rem;flex-wrap:wrap;">
      <i class="{icon_class}" style="font-size:1.8em;color:var(--accent-color);"></i>
      <h2 class="section-title" style="margin:0;">{heading}</h2>
    </div>
    <div class="legal-intro">{intro_html}</div>
    <div class="server-current-pill" style="max-width:1040px;margin:0 auto 1.25rem auto;">
      <span class="server-current-dot"></span>
      <span>Last updated</span>
      <span class="server-current-name">{updated_label}</span>
      <span class="server-current-meta">Applies to all panel visits and account creation requests.</span>
    </div>
    <div class="legal-sections">
      {sections_html}
    </div>
    <div style="display:flex;justify-content:center;gap:12px;flex-wrap:wrap;margin-top:1.3rem;">
      <a href="/main" style="text-decoration:none;"><button><i class="fa-solid fa-arrow-left"></i> Back to Main</button></a>
      <a href="/guide" style="text-decoration:none;"><button style="background:var(--surface);color:var(--text-primary);border:3px solid var(--card-border);box-shadow:5px 5px 0 rgba(93,9,25,.22);"><i class="fa-solid fa-book-open"></i> Open Guide</button></a>
    </div>
  </div>
</div>""",
    )


def render_terms_of_service():
    sections_html = """
<div class="link-box">
  <div class="link-title"><i class="fa-solid fa-circle-check"></i> Using This Service</div>
  <div style="color:var(--text-secondary);">By accessing this panel, creating accounts, or using any tool on the site, you agree to these terms. If you do not agree, please stop using the service.</div>
</div>
<div class="link-box">
  <div class="link-title"><i class="fa-solid fa-user-lock"></i> Accounts and Credentials</div>
  <div style="color:var(--text-secondary);">You are responsible for the usernames, passwords, and connection details you create or use through this panel. Keep credentials private and do not share them in a way that could harm the service or other users.</div>
</div>
<div class="link-box">
  <div class="link-title"><i class="fa-solid fa-ban"></i> Acceptable Use</div>
  <div style="color:var(--text-secondary);">Do not use the service for abuse, spam, unauthorized access, illegal activity, attacks on other systems, or anything that may overload, damage, or disrupt the panel or connected servers.</div>
</div>
<div class="link-box">
  <div class="link-title"><i class="fa-solid fa-clock-rotate-left"></i> Availability and Changes</div>
  <div style="color:var(--text-secondary);">Servers, features, limits, and account durations may change at any time without prior notice. Accounts may expire automatically, and access may be suspended or removed when necessary for safety, maintenance, or abuse prevention.</div>
</div>
<div class="link-box">
  <div class="link-title"><i class="fa-solid fa-triangle-exclamation"></i> Disclaimer</div>
  <div style="color:var(--text-secondary);">This service is provided on an "as is" and "as available" basis. No warranty is made that the site or any VPN account will always be available, uninterrupted, secure, or suitable for a specific purpose. You are responsible for using the service in a lawful manner and under your own risk.</div>
</div>
"""
    return render_legal_page(
        "Terms of Service",
        "TERMS OF SERVICE",
        "fa-solid fa-file-signature",
        "This page sets the basic rules for using the FUJI VPN panel, account creation tools, and related server features.",
        sections_html,
    )


def render_privacy_policy():
    host = html.escape(current_host())
    sections_html = f"""
<div class="link-box">
  <div class="link-title"><i class="fa-solid fa-database"></i> Information We Collect</div>
  <div style="color:var(--text-secondary);">This panel may collect technical request data such as IP address, browser session data, cookies needed for login/session handling, selected server, visit counters, admin audit entries, and form inputs you submit such as usernames and passwords required to generate accounts.</div>
</div>
<div class="link-box">
  <div class="link-title"><i class="fa-solid fa-gears"></i> How Information Is Used</div>
  <div style="color:var(--text-secondary);">We use collected data to create VPN accounts, rate-limit requests, keep admin sessions working, show panel statistics, troubleshoot errors, enforce limits, and help protect the service from misuse.</div>
</div>
<div class="link-box">
  <div class="link-title"><i class="fa-solid fa-share-nodes"></i> Third-Party Services</div>
  <div style="color:var(--text-secondary);">Data may be sent to connected backend servers to complete account creation requests. If you use the IP Lookup tool, requests are sent to <code>ip-api.com</code>. The site also loads fonts, icons, images, and scripts from third-party CDNs or hosts, and when ads are enabled, advertising providers may receive browser/device information in line with their own policies.</div>
</div>
<div class="link-box">
  <div class="link-title"><i class="fa-solid fa-shield-halved"></i> Retention and Security</div>
  <div style="color:var(--text-secondary);">Reasonable steps may be taken to protect stored data, but no online service can guarantee absolute security. Data may be retained as long as needed for panel operation, security review, backend sync, or account management.</div>
</div>
<div class="link-box">
  <div class="link-title"><i class="fa-solid fa-sliders"></i> Your Choices</div>
  <div style="color:var(--text-secondary);">If you do not want this information processed, do not use the affected features on {host}. Only submit details that are necessary to create or manage your account, and avoid entering unrelated sensitive information.</div>
</div>
<div class="link-box">
  <div class="link-title"><i class="fa-solid fa-pen-to-square"></i> Policy Updates</div>
  <div style="color:var(--text-secondary);">This policy may be updated from time to time. When it changes, the last updated date on this page will also change. Continued use of the site after an update means you accept the revised policy.</div>
</div>
"""
    return render_legal_page(
        "Privacy Policy",
        "PRIVACY POLICY",
        "fa-solid fa-user-shield",
        f"This page explains how the FUJI VPN panel at <strong>{host}</strong> handles visitor, account, and session-related information.",
        sections_html,
    )


def render_guide_page():
    ssh_icon = service_icon("ssh")
    vless_icon = service_icon("vless")
    hysteria_icon = service_icon("hysteria")
    wireguard_icon = service_icon("wireguard")
    openvpn_icon = service_icon("openvpn")
    current_server_note = render_selected_server_note(change_href="/main", include_change=True, margin_style="margin:0 auto 1.2rem auto;")
    primary_href = "/services" if has_explicit_backend_selection() else "/main"
    primary_label = "Open Services" if has_explicit_backend_selection() else "Choose Server First"
    return render_page(
        "Guide",
        f"""
<div class="container" style="max-width:1120px;">
  <div class="neo-box">
    <div style="display:flex;align-items:center;justify-content:center;gap:.8em;margin-bottom:1rem;flex-wrap:wrap;">
      <i class="fa-solid fa-book-open" style="font-size:1.8em;color:var(--accent-color);"></i>
      <h2 class="section-title" style="margin:0;">GUIDE & FAQ</h2>
    </div>
    <div style="text-align:center;color:var(--text-secondary);max-width:920px;margin:0 auto 1.2rem auto;">This page explains the full flow for creating and using SSH, VLESS, Hysteria, WireGuard, and OpenVPN accounts, plus the most common fixes when a connection does not work.</div>
    {current_server_note}
    <div class="services-grid" style="margin-bottom:1.2rem;">
      <a href="#quick-start" style="text-decoration:none;color:inherit;"><div class="service-item" style="scroll-margin-top:110px;"><div class="link-title"><i class="fa-solid fa-rocket"></i> Quick Start</div><div style="color:var(--text-secondary);">The fastest path from server selection to a working account.</div></div></a>
      <a href="#ssh-guide" style="text-decoration:none;color:inherit;"><div class="service-item"><div class="link-title"><img src="{ssh_icon}" style="height:1.05em;"> How To Use SSH</div><div style="color:var(--text-secondary);">What details to copy and where to place them in an SSH tunnel app.</div></div></a>
      <a href="#vless-guide" style="text-decoration:none;color:inherit;"><div class="service-item"><div class="link-title"><img src="{vless_icon}" style="height:1.05em;"> How To Use VLESS</div><div style="color:var(--text-secondary);">When to use TLS or Non-TLS and how to import your VLESS link.</div></div></a>
      <a href="#hysteria-guide" style="text-decoration:none;color:inherit;"><div class="service-item"><div class="link-title"><img src="{hysteria_icon}" style="height:1.05em;"> How To Use Hysteria</div><div style="color:var(--text-secondary);">How to use the generated Hysteria link and what to do with obfs or legacy URI output.</div></div></a>
      <a href="#wireguard-guide" style="text-decoration:none;color:inherit;"><div class="service-item"><div class="link-title"><img src="{wireguard_icon}" style="height:1.05em;"> How To Use WireGuard</div><div style="color:var(--text-secondary);">Import the config, scan the QR code, and start the tunnel correctly.</div></div></a>
      <a href="#openvpn-guide" style="text-decoration:none;color:inherit;"><div class="service-item"><div class="link-title"><img src="{openvpn_icon}" style="height:1.05em;"> How To Use OpenVPN</div><div style="color:var(--text-secondary);">Download the OVPN file, import it, and connect using the right credentials.</div></div></a>
      <a href="#faq" style="text-decoration:none;color:inherit;"><div class="service-item"><div class="link-title"><i class="fa-solid fa-circle-question"></i> FAQ</div><div style="color:var(--text-secondary);">Simple answers for limits, errors, expired accounts, and failed connections.</div></div></a>
    </div>
    <div id="quick-start" class="link-box" style="scroll-margin-top:110px;">
      <div class="link-title"><i class="fa-solid fa-rocket"></i> Quick Start</div>
      <div class="status-grid-2">
        <div class="status-card" style="padding:.95rem;"><div class="status-label">1. Choose a Server</div><div style="font-weight:700;">Pick the country or server you want on the Home page, then open Services.</div></div>
        <div class="status-card" style="padding:.95rem;"><div class="status-label">2. Create an Account</div><div style="font-weight:700;">Choose the protocol you need, then create the account using your preferred username.</div></div>
        <div class="status-card" style="padding:.95rem;"><div class="status-label">3. Copy the Details</div><div style="font-weight:700;">Use the result page as your source of truth for host, username, password, links, QR code, or config files.</div></div>
        <div class="status-card" style="padding:.95rem;"><div class="status-label">4. Import or Fill Your App</div><div style="font-weight:700;">Paste the generated link, scan the QR code, or import the downloaded config depending on the protocol you selected.</div></div>
      </div>
      <div class="info-grid" style="margin-top:1rem;">
        <div>SSH:</div><div>Best for apps that ask for host, username, password, and manual transport settings.</div>
        <div>VLESS:</div><div>Best when your app supports VLESS or Xray link import and you want a fast copy-paste setup.</div>
        <div>Hysteria:</div><div>Best when your client supports Hysteria links and your setup expects the generated URI format.</div>
        <div>WireGuard:</div><div>Best when you want to import a config file or scan a QR code directly into the WireGuard app.</div>
        <div>OpenVPN:</div><div>Best when your app imports `.ovpn` files and you prefer the standard OpenVPN client flow.</div>
      </div>
      <div style="display:flex;justify-content:center;gap:12px;flex-wrap:wrap;margin-top:1rem;">
        <a href="{primary_href}" style="text-decoration:none;"><button><i class="fa-solid fa-arrow-right"></i> {primary_label}</button></a>
        <a href="/main" style="text-decoration:none;"><button style="background:var(--surface);color:var(--text-primary);border:3px solid var(--card-border);box-shadow:5px 5px 0 rgba(93,9,25,.22);"><i class="fa-solid fa-earth-asia"></i> Server List</button></a>
      </div>
    </div>
    <div id="ssh-guide" class="link-box" style="margin-top:1.2rem;scroll-margin-top:110px;">
      <div class="link-title"><img src="{ssh_icon}" style="height:1.05em;"> How To Use SSH</div>
      <div style="color:var(--text-secondary);margin-bottom:1rem;">Use SSH if your app expects classic SSH login details such as host, username, password, and port.</div>
      <div class="status-grid-2">
        <div class="status-card" style="padding:.95rem;">
          <div class="status-label">What You Need</div>
          <div style="font-weight:700;">Host or domain, username, password, and the correct port from the result page.</div>
        </div>
        <div class="status-card" style="padding:.95rem;">
          <div class="status-label">Recommended Ports</div>
          <div style="font-weight:700;">Use `443` for SSL or TLS style setups, `80` for WS or HTTP style setups, and `22` for direct SSH when supported.</div>
        </div>
      </div>
      <div class="services-grid" style="margin-top:1rem;">
        <div class="service-item"><div class="link-title"><i class="fa-solid fa-list-ol"></i> Step 1</div><div>Create an SSH account from the Services page and keep the result page open.</div></div>
        <div class="service-item"><div class="link-title"><i class="fa-solid fa-list-ol"></i> Step 2</div><div>Open your SSH-capable tunnel app and create a new profile or account entry.</div></div>
        <div class="service-item"><div class="link-title"><i class="fa-solid fa-list-ol"></i> Step 3</div><div>Fill in the host or domain, then add your username and password exactly as shown.</div></div>
        <div class="service-item"><div class="link-title"><i class="fa-solid fa-list-ol"></i> Step 4</div><div>Choose the transport your app expects. If it asks for SSL, TLS, WS, or proxy fields, match them to the SSH details page.</div></div>
        <div class="service-item"><div class="link-title"><i class="fa-solid fa-list-ol"></i> Step 5</div><div>Save the profile and connect. If the app shows authentication failed, re-check username, password, and selected port.</div></div>
        <div class="service-item"><div class="link-title"><i class="fa-solid fa-list-ol"></i> Step 6</div><div>If connection still fails, open the Status page to confirm the selected server is online before trying again.</div></div>
      </div>
      <div class="success-msg" style="margin-top:1rem;background:rgba(124,16,39,.06);border-left-color:var(--warning);">
        <i class="fa-solid fa-circle-info" style="color:var(--warning);"></i>
        <div>Exact menu names depend on the app you use, but the important SSH values are always the same: host, username, password, and the correct port.</div>
      </div>
    </div>
    <div id="vless-guide" class="link-box" style="margin-top:1.2rem;scroll-margin-top:110px;">
      <div class="link-title"><img src="{vless_icon}" style="height:1.05em;"> How To Use VLESS</div>
      <div style="color:var(--text-secondary);margin-bottom:1rem;">VLESS is usually easier because the panel gives you a ready-to-import link. Most VLESS apps can import it directly.</div>
      <div class="status-grid-2">
        <div class="status-card" style="padding:.95rem;">
          <div class="status-label">TLS Link</div>
          <div style="font-weight:700;">Best default choice when your app supports VLESS over TLS. Start with this unless you specifically need Non-TLS.</div>
        </div>
        <div class="status-card" style="padding:.95rem;">
          <div class="status-label">Non-TLS Link</div>
          <div style="font-weight:700;">Use this only when your network, server setup, or client app requires the non-TLS profile.</div>
        </div>
      </div>
      <div class="services-grid" style="margin-top:1rem;">
        <div class="service-item"><div class="link-title"><i class="fa-solid fa-list-ol"></i> Step 1</div><div>Create a VLESS account and copy either the TLS link or the Non-TLS link from the result page.</div></div>
        <div class="service-item"><div class="link-title"><i class="fa-solid fa-list-ol"></i> Step 2</div><div>Open your VLESS or Xray client and use its import feature if it supports importing a URI or clipboard link.</div></div>
        <div class="service-item"><div class="link-title"><i class="fa-solid fa-list-ol"></i> Step 3</div><div>If your app does not import automatically, create a profile manually using the values stored inside the generated VLESS link.</div></div>
        <div class="service-item"><div class="link-title"><i class="fa-solid fa-list-ol"></i> Step 4</div><div>Keep the transport as WebSocket when the profile expects it, and make sure host, path, SNI, and port match the imported config.</div></div>
        <div class="service-item"><div class="link-title"><i class="fa-solid fa-list-ol"></i> Step 5</div><div>Leave the bypass option on Default unless you already know your network needs a specific host or routing setup.</div></div>
        <div class="service-item"><div class="link-title"><i class="fa-solid fa-list-ol"></i> Step 6</div><div>Save, connect, and switch between TLS and Non-TLS only if one profile fails and the other is recommended for your setup.</div></div>
      </div>
      <div class="info-grid" style="margin-top:1rem;">
        <div>If import fails:</div><div>Copy the full VLESS link again and make sure there are no extra spaces before or after it.</div>
        <div>If connection fails:</div><div>Check the selected server status, verify the account is not expired, and confirm your device date and time are correct.</div>
      </div>
    </div>
    <div id="hysteria-guide" class="link-box" style="margin-top:1.2rem;scroll-margin-top:110px;">
      <div class="link-title"><img src="{hysteria_icon}" style="height:1.05em;"> How To Use Hysteria</div>
      <div style="color:var(--text-secondary);margin-bottom:1rem;">The panel gives you a Hysteria link, and sometimes also a legacy URI. Use the main link first unless your client specifically needs the legacy format.</div>
      <div class="status-grid-2">
        <div class="status-card" style="padding:.95rem;">
          <div class="status-label">What You Get</div>
          <div style="font-weight:700;">A ready-to-use Hysteria link and the obfs value when the backend provides one.</div>
        </div>
        <div class="status-card" style="padding:.95rem;">
          <div class="status-label">Best Practice</div>
          <div style="font-weight:700;">Import the generated link directly instead of rebuilding the profile by hand whenever your app allows it.</div>
        </div>
      </div>
      <div class="services-grid" style="margin-top:1rem;">
        <div class="service-item"><div class="link-title"><i class="fa-solid fa-list-ol"></i> Step 1</div><div>Create a Hysteria account and copy the main Hysteria link from the result page.</div></div>
        <div class="service-item"><div class="link-title"><i class="fa-solid fa-list-ol"></i> Step 2</div><div>Open your Hysteria-compatible app and use its import feature if it can accept a URI or clipboard link.</div></div>
        <div class="service-item"><div class="link-title"><i class="fa-solid fa-list-ol"></i> Step 3</div><div>If the app asks for obfs, keep the exact value provided by the panel and do not replace it with a random string.</div></div>
        <div class="service-item"><div class="link-title"><i class="fa-solid fa-list-ol"></i> Step 4</div><div>Use the legacy Hysteria URI only when your chosen app clearly says it needs the older format.</div></div>
        <div class="service-item"><div class="link-title"><i class="fa-solid fa-list-ol"></i> Step 5</div><div>Save the profile, connect, and switch servers or recreate the account only if the client still rejects the imported configuration.</div></div>
        <div class="service-item"><div class="link-title"><i class="fa-solid fa-list-ol"></i> Step 6</div><div>If it still fails, check server status first, then verify that your client really supports the Hysteria version used by the generated link.</div></div>
      </div>
    </div>
    <div id="wireguard-guide" class="link-box" style="margin-top:1.2rem;scroll-margin-top:110px;">
      <div class="link-title"><img src="{wireguard_icon}" style="height:1.05em;"> How To Use WireGuard</div>
      <div style="color:var(--text-secondary);margin-bottom:1rem;">WireGuard is the easiest to deploy when your app accepts a `.conf` file or QR code. The panel already prepares both when available.</div>
      <div class="status-grid-2">
        <div class="status-card" style="padding:.95rem;">
          <div class="status-label">What You Get</div>
          <div style="font-weight:700;">A downloadable WireGuard config, endpoint information, client IP, and usually a QR code.</div>
        </div>
        <div class="status-card" style="padding:.95rem;">
          <div class="status-label">Best Practice</div>
          <div style="font-weight:700;">Prefer importing the generated config or scanning the QR code instead of manually typing keys and tunnel settings.</div>
        </div>
      </div>
      <div class="services-grid" style="margin-top:1rem;">
        <div class="service-item"><div class="link-title"><i class="fa-solid fa-list-ol"></i> Step 1</div><div>Create a WireGuard account and keep the result page open.</div></div>
        <div class="service-item"><div class="link-title"><i class="fa-solid fa-list-ol"></i> Step 2</div><div>If your device supports QR import, scan the QR code directly using the WireGuard app.</div></div>
        <div class="service-item"><div class="link-title"><i class="fa-solid fa-list-ol"></i> Step 3</div><div>If QR import is not available, download the `.conf` file and import it into your WireGuard client.</div></div>
        <div class="service-item"><div class="link-title"><i class="fa-solid fa-list-ol"></i> Step 4</div><div>Check that the endpoint and client IP shown by the app match the imported profile.</div></div>
        <div class="service-item"><div class="link-title"><i class="fa-solid fa-list-ol"></i> Step 5</div><div>Turn the tunnel on and allow VPN permission if your device asks for it.</div></div>
        <div class="service-item"><div class="link-title"><i class="fa-solid fa-list-ol"></i> Step 6</div><div>If the QR code is missing, use the config file instead. That is a normal fallback and should still work.</div></div>
      </div>
    </div>
    <div id="openvpn-guide" class="link-box" style="margin-top:1.2rem;scroll-margin-top:110px;">
      <div class="link-title"><img src="{openvpn_icon}" style="height:1.05em;"> How To Use OpenVPN</div>
      <div style="color:var(--text-secondary);margin-bottom:1rem;">OpenVPN uses the downloaded `.ovpn` file from the result page. Some clients also ask for username and password after import, so keep those details ready.</div>
      <div class="status-grid-2">
        <div class="status-card" style="padding:.95rem;">
          <div class="status-label">What You Get</div>
          <div style="font-weight:700;">A downloadable OVPN profile plus your account username, password, and server domain on the result page.</div>
        </div>
        <div class="status-card" style="padding:.95rem;">
          <div class="status-label">Best Practice</div>
          <div style="font-weight:700;">Import the generated file first, then only enter username and password if the client prompts for them.</div>
        </div>
      </div>
      <div class="services-grid" style="margin-top:1rem;">
        <div class="service-item"><div class="link-title"><i class="fa-solid fa-list-ol"></i> Step 1</div><div>Create an OpenVPN account and download the `.ovpn` file from the result page.</div></div>
        <div class="service-item"><div class="link-title"><i class="fa-solid fa-list-ol"></i> Step 2</div><div>Open your OpenVPN app and import the downloaded file instead of creating the connection manually.</div></div>
        <div class="service-item"><div class="link-title"><i class="fa-solid fa-list-ol"></i> Step 3</div><div>If the app asks for login credentials, enter the username and password shown by the panel.</div></div>
        <div class="service-item"><div class="link-title"><i class="fa-solid fa-list-ol"></i> Step 4</div><div>Save the profile, allow VPN permission if prompted, and start the connection.</div></div>
        <div class="service-item"><div class="link-title"><i class="fa-solid fa-list-ol"></i> Step 5</div><div>If import succeeds but connection fails, verify the server is online and confirm you are using the latest file generated for that account.</div></div>
        <div class="service-item"><div class="link-title"><i class="fa-solid fa-list-ol"></i> Step 6</div><div>Do not edit the `.ovpn` file unless you fully understand the setting you are changing.</div></div>
      </div>
    </div>
    <div id="faq" class="link-box" style="margin-top:1.2rem;scroll-margin-top:110px;">
      <div class="link-title"><i class="fa-solid fa-circle-question"></i> FAQ</div>
      <div class="services-grid">
        <div class="service-item"><div class="link-title"><i class="fa-solid fa-circle-question"></i> Which server should I choose?</div><div>Choose the server with the best location for you, then prefer one that shows healthy status and low ping when available.</div></div>
        <div class="service-item"><div class="link-title"><i class="fa-solid fa-circle-question"></i> Which protocol should I use?</div><div>Use SSH for manual SSH-style apps, VLESS for Xray clients, Hysteria for Hysteria-compatible apps, WireGuard for QR or config import, and OpenVPN for `.ovpn` clients.</div></div>
        <div class="service-item"><div class="link-title"><i class="fa-solid fa-circle-question"></i> Why do I see a wait message?</div><div>The panel has a cooldown between account creations, so you may need to wait a few minutes before creating another account.</div></div>
        <div class="service-item"><div class="link-title"><i class="fa-solid fa-circle-question"></i> Why can't I create more accounts today?</div><div>The selected server has a daily creation limit per service. Try again the next day or switch to another available server.</div></div>
        <div class="service-item"><div class="link-title"><i class="fa-solid fa-circle-question"></i> What does expired mean?</div><div>Your account has passed its validity period. Create a new account or ask an admin to extend the expiration.</div></div>
        <div class="service-item"><div class="link-title"><i class="fa-solid fa-circle-question"></i> Why is login rejected?</div><div>Most failed logins come from wrong username, wrong password, wrong port, or importing the wrong profile for the selected protocol.</div></div>
        <div class="service-item"><div class="link-title"><i class="fa-solid fa-circle-question"></i> Why does my app ask for Host or SNI?</div><div>Some TLS, SSL, and WebSocket clients require these fields. If you imported the generated profile, they should already be filled correctly.</div></div>
        <div class="service-item"><div class="link-title"><i class="fa-solid fa-circle-question"></i> What if WireGuard has no QR code?</div><div>That is okay. Import the generated config file manually and use it as the main profile.</div></div>
        <div class="service-item"><div class="link-title"><i class="fa-solid fa-circle-question"></i> What if OpenVPN asks for login after import?</div><div>Use the username and password shown on the panel result page for that OpenVPN account.</div></div>
        <div class="service-item"><div class="link-title"><i class="fa-solid fa-circle-question"></i> What if Hysteria shows both link types?</div><div>Start with the main Hysteria link. Use the legacy URI only when your app clearly needs the older format.</div></div>
        <div class="service-item"><div class="link-title"><i class="fa-solid fa-circle-question"></i> Where do I check if the server is alive?</div><div>Open the Status page after selecting a server. If the backend is down, wait for it to recover before retrying.</div></div>
      </div>
    </div>
  </div>
</div>""",
        show_ads=True,
    )


def render_readme():
    return render_page(
        "Announcement",
        f"""
<div class="container"><div class="neo-box" style="max-width:800px;margin:0 auto;">
  <div style="display:flex;align-items:center;justify-content:center;gap:.8em;margin-bottom:1.5em;"><i class="fa-solid fa-bullhorn" style="font-size:1.8em;color:var(--accent-color);"></i><h2 class="section-title" style="margin:0;">ANNOUNCEMENT!</h2></div>
  <div class="announcement-content" style="font-size:1.1em;color:var(--text-primary);padding:1em 0;">{announcement_html()}</div>
  <div style="display:flex;justify-content:center;margin-top:1.5rem;"><a href="/main" style="text-decoration:none;display:inline-block;width:100%;"><button style="width:100%;max-width:400px;min-width:220px;font-size:1.15em;padding:16px 0;margin:0 auto;background:var(--surface);color:var(--text-primary);border:3px solid var(--card-border);border-radius:16px;font-weight:700;box-shadow:5px 5px 0 rgba(93,9,25,.22);"><i class="fa-solid fa-arrow-left"></i> Back to Main</button></a></div>
</div></div>""",
        show_ads=announcement_exists(),
    )


def render_vless_bypass_option_row(option=None):
    option = option or {}
    tls = option.get("tls") if isinstance(option.get("tls"), dict) else {}
    nontls = option.get("nontls") if isinstance(option.get("nontls"), dict) else {}
    option_id = html.escape(str(option.get("id", "")))
    option_name = html.escape(str(option.get("name", "")))
    tls_address = html.escape(str(tls.get("address", "")))
    tls_host = html.escape(str(tls.get("host", "")))
    tls_sni = html.escape(str(tls.get("sni", "")))
    nontls_address = html.escape(str(nontls.get("address", "")))
    nontls_host = html.escape(str(nontls.get("host", "")))
    return f"""
<div class="bypass-option-row" style="background:linear-gradient(180deg,#ffffff 0%,#fff7f8 100%);border-radius:16px;padding:1rem;border:3px solid var(--card-border);box-shadow:4px 4px 0 rgba(93,9,25,.16);margin-bottom:1rem;">
  <input type="hidden" data-field="id" value="{option_id}">
  <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:.8rem;">
    <div style="font-weight:700;color:var(--primary-color);font-family:'Bangers','Comic Neue',cursive;letter-spacing:.05em;">Bypass Option</div>
    <button type="button" data-remove-bypass style="background:var(--surface);color:var(--text-primary);border:3px solid var(--card-border);box-shadow:4px 4px 0 rgba(93,9,25,.16);padding:10px 18px;">Remove</button>
  </div>
  <div class="status-grid-2" style="margin-bottom:.8rem;">
    <div>
      <label style="display:block;font-weight:700;color:var(--text-secondary);margin-bottom:.35rem;">Option Name</label>
      <div class="form-input-container" style="max-width:none;"><input type="text" data-field="name" placeholder="Enter bypass name" maxlength="80" value="{option_name}"></div>
    </div>
    <div>
      <label style="display:block;font-weight:700;color:var(--text-secondary);margin-bottom:.35rem;">TLS Address</label>
      <div class="form-input-container" style="max-width:none;"><input type="text" data-field="tls_address" placeholder="Blank = server host" maxlength="255" value="{tls_address}"></div>
    </div>
    <div>
      <label style="display:block;font-weight:700;color:var(--text-secondary);margin-bottom:.35rem;">TLS Host</label>
      <div class="form-input-container" style="max-width:none;"><input type="text" data-field="tls_host" placeholder="Blank = server host" maxlength="255" value="{tls_host}"></div>
    </div>
    <div>
      <label style="display:block;font-weight:700;color:var(--text-secondary);margin-bottom:.35rem;">TLS SNI</label>
      <div class="form-input-container" style="max-width:none;"><input type="text" data-field="tls_sni" placeholder="Blank = server host" maxlength="255" value="{tls_sni}"></div>
    </div>
    <div>
      <label style="display:block;font-weight:700;color:var(--text-secondary);margin-bottom:.35rem;">Non-TLS Address</label>
      <div class="form-input-container" style="max-width:none;"><input type="text" data-field="nontls_address" placeholder="Blank = server host" maxlength="255" value="{nontls_address}"></div>
    </div>
    <div>
      <label style="display:block;font-weight:700;color:var(--text-secondary);margin-bottom:.35rem;">Non-TLS Host</label>
      <div class="form-input-container" style="max-width:none;"><input type="text" data-field="nontls_host" placeholder="Blank = server host" maxlength="255" value="{nontls_host}"></div>
    </div>
  </div>
</div>"""


def render_vless_bypass_admin():
    rows_html = "".join(render_vless_bypass_option_row(option) for option in get_vless_bypass_options())
    empty_display = "none" if rows_html else "flex"
    template_row = render_vless_bypass_option_row()
    return f"""
<div class="link-box" style="margin-top:1.2rem;">
  <div style="font-weight:700;margin-bottom:.45rem;">VLESS Bypass Options</div>
  <div style="color:var(--text-secondary);margin-bottom:1rem;">These apply to all servers. Leave any TLS or Non-TLS field blank to use the selected server host automatically.</div>
  <form method="POST" action="/admin" id="bypass-options-form" style="margin-bottom:0;align-items:stretch;">
    <input type="hidden" name="action" value="save_bypass_options">
    <input type="hidden" name="bypass_options_json" id="bypass-options-json">
    <div id="bypass-options-empty" class="success-msg" style="display:{empty_display};margin-bottom:1rem;background:rgba(124,16,39,.06);border-left-color:var(--warning);"><i class="fa-solid fa-circle-info" style="color:var(--warning);"></i><div>No bypass options added yet.</div></div>
    <div id="bypass-options-editor">{rows_html}</div>
    <div style="display:flex;gap:12px;flex-wrap:wrap;justify-content:center;margin-top:.8rem;">
      <button type="button" id="add-bypass-option" style="background:var(--surface);color:var(--text-primary);border:3px solid var(--card-border);box-shadow:5px 5px 0 rgba(93,9,25,.22);"><i class="fa-solid fa-plus"></i> Add Bypass Option</button>
      <button type="submit"><i class="fa-solid fa-save"></i> Save Bypass Options</button>
    </div>
  </form>
  <template id="bypass-option-template">{template_row}</template>
  <script>
  (function(){{
    const form = document.getElementById('bypass-options-form');
    if (!form) return;
    const editor = document.getElementById('bypass-options-editor');
    const empty = document.getElementById('bypass-options-empty');
    const template = document.getElementById('bypass-option-template');
    const hidden = document.getElementById('bypass-options-json');
    const addButton = document.getElementById('add-bypass-option');
    function syncEmpty() {{
      if (!empty || !editor) return;
      empty.style.display = editor.querySelector('.bypass-option-row') ? 'none' : 'flex';
    }}
    function bindRow(row) {{
      const remove = row.querySelector('[data-remove-bypass]');
      if (remove) {{
        remove.addEventListener('click', function() {{
          row.remove();
          syncEmpty();
        }});
      }}
    }}
    editor.querySelectorAll('.bypass-option-row').forEach(bindRow);
    syncEmpty();
    if (addButton && template) {{
      addButton.addEventListener('click', function() {{
        const row = template.content.firstElementChild.cloneNode(true);
        editor.appendChild(row);
        bindRow(row);
        syncEmpty();
        const nameInput = row.querySelector('[data-field=\"name\"]');
        if (nameInput) nameInput.focus();
      }});
    }}
    form.addEventListener('submit', function() {{
      const options = [];
      editor.querySelectorAll('.bypass-option-row').forEach(function(row) {{
        const get = function(field) {{
          const element = row.querySelector('[data-field=\"' + field + '\"]');
          return element ? element.value.trim() : '';
        }};
        const name = get('name');
        if (!name) return;
        options.push({{
          id: get('id'),
          name: name,
          tls: {{
            address: get('tls_address'),
            host: get('tls_host'),
            sni: get('tls_sni')
          }},
          nontls: {{
            address: get('nontls_address'),
            host: get('nontls_host')
          }}
        }});
      }});
      hidden.value = JSON.stringify(options);
    }});
  }})();
  </script>
</div>"""


def render_admin_stats_panel():
    visits = load_visits(force_remote=False)
    counters = get_cached_backend_summary_counters() if backend_configured() else _empty_backend_summary()
    if not counters:
        counters = _empty_backend_summary()
    total_accounts = get_display_total_accounts(visits=visits, counters=counters, force_remote=False)
    return render_template_string(
        """
<div style="margin-top:1.2rem;">
  <div style="font-weight:700;margin-bottom:.6rem;">Panel Stats</div>
  <div class="stats-container" style="margin:0;">
    <div class="stat-item"><i class="fa-regular fa-eye stat-icon"></i><div><div class="stat-value" id="admin-total-visits">{{ visits }}</div><div class="stat-label">Total Visits</div></div></div>
    <div class="stat-item"><i class="fa-solid fa-users stat-icon"></i><div><div class="stat-value" id="admin-total-accounts">{{ total_accounts }}</div><div class="stat-label">Accounts Created</div></div></div>
  </div>
</div>
<script>
const adminStatsState={visits:parseInt((document.getElementById('admin-total-visits')||{}).textContent||'0',10)||0,accounts:parseInt((document.getElementById('admin-total-accounts')||{}).textContent||'0',10)||0};
function updateAdminStats(){fetch('/main/stats?scope=all&t='+Date.now(),{cache:'no-store'}).then(r=>r.json()).then(data=>{const visits=Number(data&&data.total_visits);const accounts=Number(data&&data.total_accounts);if(Number.isFinite(visits))adminStatsState.visits=Math.max(adminStatsState.visits, visits);if(Number.isFinite(accounts))adminStatsState.accounts=Math.max(adminStatsState.accounts, accounts);document.getElementById('admin-total-visits').textContent=adminStatsState.visits;document.getElementById('admin-total-accounts').textContent=adminStatsState.accounts;}).catch(()=>{});}
updateAdminStats();setInterval(updateAdminStats,5000);
</script>
""",
        visits=visits.get("total_visits", 0),
        total_accounts=total_accounts,
    )


def render_admin_online_breakdown_panel():
    def build_card(backend_id, label, host_text, ssh_online, openvpn_online, error_text=""):
        total_online = max(int(ssh_online or 0), 0) + max(int(openvpn_online or 0), 0)
        error_text = str(error_text or "").strip()
        error_html = ""
        if error_text:
            error_html = (
                '<div data-admin-online-error style="margin-top:.2rem;color:var(--error);font-size:.86rem;font-weight:700;">'
                + html.escape(error_text)
                + "</div>"
            )
        return f"""
<div class="link-box" data-admin-online-card data-backend-id="{html.escape(str(backend_id), quote=True)}" style="display:flex;flex-direction:column;gap:.85rem;">
  <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:12px;flex-wrap:wrap;">
    <div style="min-width:0;">
      <div data-admin-online-label style="font-weight:800;font-size:1.02rem;">{html.escape(str(label or 'Unknown'))}</div>
      <div data-admin-online-host style="color:var(--text-muted);font-size:.92rem;">{html.escape(str(host_text or ''))}</div>
    </div>
    <div class="server-badge" style="background:rgba(124,16,39,.08);">Total <span data-admin-online-total>{total_online}</span></div>
  </div>
  <div class="status-grid-2" style="gap:10px;">
    <div class="status-card" style="padding:.8rem;">
      <div class="status-label"><i class="fa-solid fa-user-shield" style="color:var(--primary-color)"></i> SSH Online</div>
      <div class="status-value" data-admin-online-ssh>{max(int(ssh_online or 0), 0)}</div>
    </div>
    <div class="status-card" style="padding:.8rem;">
      <div class="status-label"><i class="fa-solid fa-network-wired" style="color:var(--accent-color)"></i> OpenVPN Online</div>
      <div class="status-value" data-admin-online-openvpn>{max(int(openvpn_online or 0), 0)}</div>
    </div>
  </div>
  {error_html}
</div>"""

    cards = [
        build_card(
            "__total__",
            "Total Online",
            "All connected servers",
            0,
            0,
            "",
        )
    ]
    for backend in load_backends():
        cards.append(
            build_card(
                backend.get("id", ""),
                admin_backend_label(backend),
                backend_host(backend),
                0,
                0,
                "",
            )
        )
    return """
<div style="margin-top:1.2rem;">
  <div style="font-weight:700;margin-bottom:.45rem;">Online by Server</div>
  <div style="color:var(--text-secondary);margin-bottom:.45rem;">Each card shows live SSH and OpenVPN users for that server. The first card is the total across all connected servers.</div>
  <div class="admin-account-grid" id="admin-online-breakdown-grid">""" + "".join(cards) + """</div>
</div>
<script>
(function(){
  const cards = Array.from(document.querySelectorAll('[data-admin-online-card]'));
  if(!cards.length)return;
  const cardMap = new Map(cards.map(card=>[String(card.getAttribute('data-backend-id')||''), card]));
  function setCard(card, payload){
    if(!card || !payload)return;
    const ssh = Math.max(0, Number(payload.ssh_online_users||0) || 0);
    const openvpn = Math.max(0, Number(payload.openvpn_online_users||0) || 0);
    const total = Math.max(0, Number(payload.online_users||0) || (ssh + openvpn));
    const sshNode = card.querySelector('[data-admin-online-ssh]');
    const openvpnNode = card.querySelector('[data-admin-online-openvpn]');
    const totalNode = card.querySelector('[data-admin-online-total]');
    const errorNode = card.querySelector('[data-admin-online-error]');
    if(sshNode)sshNode.textContent=String(ssh);
    if(openvpnNode)openvpnNode.textContent=String(openvpn);
    if(totalNode)totalNode.textContent=String(total);
    if(errorNode){
      const errorText = String(payload.error||'').trim();
      errorNode.textContent=errorText;
      errorNode.style.display=errorText?'':'none';
    }
  }
  function updateAdminOnlineBreakdown(){
    fetch('/admin/online-breakdown?t='+Date.now(),{cache:'no-store'})
      .then(r=>r.ok?r.json():Promise.reject(new Error('request failed')))
      .then(data=>{
        const totals = data&&data.totals ? data.totals : {};
        setCard(cardMap.get('__total__'), totals);
        const servers = Array.isArray(data&&data.servers) ? data.servers : [];
        servers.forEach(server=>{
          setCard(cardMap.get(String(server.backend_id||'')), server);
        });
      })
      .catch(()=>{});
  }
  updateAdminOnlineBreakdown();
  setInterval(updateAdminOnlineBreakdown,5000);
})();
</script>"""


def render_admin(success=None, error=None):
    if not session.get("admin_authenticated"):
        hint = "" if os.environ.get("ADMIN_PASSWORD") else '<div class="success-msg" style="background:rgba(239,68,68,.1);border-left-color:var(--error);"><i class="fa-solid fa-circle-info" style="color:var(--error);"></i><div>Set <code>ADMIN_PASSWORD</code> in Vercel to enable admin login.</div></div>'
        message = ""
        if error:
            message = f'<div class="success-msg" style="background:rgba(239,68,68,.1);border-left-color:var(--error);"><i class="fa-solid fa-circle-xmark" style="color:var(--error);"></i><div>{html.escape(error)}</div></div>'
        return render_page("Admin Login", f"""
<div class="container"><div class="neo-box" style="max-width:620px;margin:0 auto;">
  <div style="display:flex;align-items:center;gap:12px;margin-bottom:1rem;"><div style="height:46px;width:46px;border-radius:14px;background:rgba(6,182,212,.16);border:1px solid rgba(6,182,212,.28);display:flex;align-items:center;justify-content:center;"><i class="fa-solid fa-lock" style="color:var(--accent-color);"></i></div><div><h2 class="section-title" style="margin:0;font-size:1.6rem;">Admin Login</h2><div style="color:var(--text-muted);font-size:.95rem;">Use environment-based credentials for this Vercel deployment.</div></div></div>
  {hint}{message}
  <form method="POST" action="/admin"><input type="hidden" name="action" value="login">
    <div class="form-group"><label class="form-label" for="admin-username"><i class="fa-solid fa-user-shield"></i> Username</label><div class="form-input-container"><input id="admin-username" name="username" type="text" required placeholder="root"></div></div>
    <div class="form-group"><label class="form-label" for="admin-password"><i class="fa-solid fa-key"></i> Password</label><div class="form-input-container"><input id="admin-password" name="password" type="password" required placeholder="Admin password"></div></div>
    <button type="submit" style="width:100%;max-width:400px;"><i class="fa-solid fa-right-to-bracket"></i> Sign In</button>
  </form>
</div></div>""")
    expiry = get_create_account_expiry()
    bypass_editor_html = render_vless_bypass_admin()
    admin_stats_html = render_admin_stats_panel()
    admin_online_breakdown_html = render_admin_online_breakdown_panel()
    account_manager_html = """
<div id="admin-account-manager-shell" style="margin-top:1.2rem;">
  <div class="link-box">
    <div style="font-weight:700;margin-bottom:.45rem;">Account Manager</div>
    <div style="color:var(--text-secondary);">Loading accounts from connected servers...</div>
  </div>
</div>
<script>
window.initAdminAccountManager = window.initAdminAccountManager || function(root){
  root = root || document.querySelector('[data-admin-account-manager-root]');
  if(!root)return;
  const select = root.querySelector('[data-admin-protocol-filter]');
  if(!select || select.dataset.bound === '1')return;
  select.dataset.bound = '1';
  const sections = Array.from(root.querySelectorAll('[data-admin-account-section]'));
  function applyProtocolFilter(){
    const wanted = String(select.value || 'all').toLowerCase();
    sections.forEach(section => {
      const cards = Array.from(section.querySelectorAll('[data-admin-account-card]'));
      const summaries = Array.from(section.querySelectorAll('[data-admin-service-summary]'));
      let visibleCount = 0;
      cards.forEach(card => {
        const service = String(card.getAttribute('data-service') || '').toLowerCase();
        const show = wanted === 'all' || service === wanted;
        card.style.display = show ? 'flex' : 'none';
        if(show)visibleCount += 1;
      });
      summaries.forEach(summary => {
        const service = String(summary.getAttribute('data-service') || '').toLowerCase();
        summary.style.display = (wanted === 'all' || service === wanted) ? '' : 'none';
      });
      const grid = section.querySelector('[data-admin-account-grid]');
      if(grid)grid.style.display = visibleCount > 0 ? 'grid' : 'none';
      const emptyState = section.querySelector('[data-admin-account-filter-empty]');
      if(emptyState)emptyState.style.display = wanted !== 'all' && cards.length > 0 && visibleCount === 0 ? '' : 'none';
      const totalNode = section.querySelector('[data-admin-account-visible-total]');
      if(totalNode)totalNode.textContent = String(wanted === 'all' ? cards.length : visibleCount);
      const labelNode = section.querySelector('[data-admin-account-count-label]');
      if(labelNode)labelNode.textContent = wanted === 'all' ? 'total' : 'shown';
      if(cards.length > 0){
        section.style.display = (wanted === 'all' || visibleCount > 0) ? '' : 'none';
      }else{
        section.style.display = wanted === 'all' ? '' : 'none';
      }
    });
  }
  select.addEventListener('change', applyProtocolFilter);
  applyProtocolFilter();
};
(function(){
  const shell = document.getElementById('admin-account-manager-shell');
  if(!shell)return;
  function showError(){
    shell.innerHTML = '<div class="link-box"><div style="font-weight:700;margin-bottom:.45rem;">Account Manager</div><div style="color:var(--error);">Failed to load account manager right now.</div></div>';
  }
  function loadAccountManager(){
    fetch('/admin/account-manager-fragment?t=' + Date.now(), {cache:'no-store'})
      .then(r => r.ok ? r.text() : Promise.reject(new Error('request failed')))
      .then(html => {
        shell.innerHTML = html;
        window.initAdminAccountManager(shell.querySelector('[data-admin-account-manager-root]'));
      })
      .catch(() => showError());
  }
  setTimeout(loadAccountManager, 0);
})();
</script>"""
    events = recent_admin_events(8)
    event_cards = "".join(
        f'<div class="link-box"><div style="font-weight:700">{html.escape(e["action"].replace("_"," ").title())}</div><div style="color:var(--text-muted);font-size:.9rem">{html.escape(e["time"])} | {html.escape(e["status"])}</div><div style="margin-top:.5rem">{html.escape(json.dumps(e.get("details", {})))}</div></div>'
        for e in events
    ) or '<div class="link-box" style="color:var(--text-muted);">No admin actions logged yet.</div>'
    banner = ""
    if success:
        banner = f'<div class="success-msg"><i class="fa-solid fa-circle-check"></i><div>{html.escape(success)}</div></div>'
    elif error:
        banner = f'<div class="success-msg" style="background:rgba(239,68,68,.1);border-left-color:var(--error);"><i class="fa-solid fa-circle-xmark" style="color:var(--error);"></i><div>{html.escape(error)}</div></div>'
    expiry_json = json.dumps(expiry).replace("</", "<\\/")
    return render_page("Admin", f"""
<div class="container" style="max-width:1120px;">
  <div class="neo-box">{banner}
    <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:16px;flex-wrap:wrap;">
      <div><h2 class="section-title" style="margin:0;">Admin Dashboard</h2><div style="color:var(--text-secondary);max-width:620px;">Serverless-safe controls for limits, defaults, audit history, and live account management across your connected backends.</div></div>
      <a href="/admin/logout" style="text-decoration:none;"><button style="background:var(--surface);color:var(--text-primary);border:3px solid var(--card-border);box-shadow:5px 5px 0 rgba(93,9,25,.22);"><i class="fa-solid fa-arrow-right-from-bracket"></i> Logout</button></a>
    </div>
    {admin_stats_html}
    {admin_online_breakdown_html}
    <div class="status-grid-2" style="margin-top:1.2rem;">
      <div class="link-box"><div style="font-weight:700;margin-bottom:.6rem;">Daily Account Limit</div><div style="color:var(--text-secondary);margin-bottom:.75rem;">This max is tracked separately for each server and each service every day, and resets at {html.escape(DAILY_RESET_TIME_LABEL)}.</div><form method="POST" action="/admin" style="margin-bottom:0;"><input type="hidden" name="action" value="update_limit"><div class="form-input-container" style="max-width:none;"><input type="number" name="limit" min="1" max="999" value="{get_daily_account_limit()}"></div><button type="submit" style="width:100%;max-width:400px;margin-top:1rem;"><i class="fa-solid fa-save"></i> Save Limit</button></form></div>
      <div class="link-box"><div style="font-weight:700;margin-bottom:.6rem;">Create Account Expiration</div><div style="color:var(--text-secondary);margin-bottom:.75rem;">This expiration setting is used for the chosen service on every server.</div><form method="POST" action="/admin" style="margin-bottom:0;"><input type="hidden" name="action" value="update_create_expiry"><div class="form-group"><label class="form-label">Service</label><div class="form-input-container"><select name="service" id="expiry-service-select"><option value="ssh">SSH</option><option value="vless">VLESS</option><option value="hysteria">Hysteria</option><option value="wireguard">WireGuard</option><option value="openvpn">OpenVPN</option></select></div></div><div class="form-group"><label class="form-label">Days</label><div class="form-input-container"><input type="number" name="days" id="expiry-days-input" min="1" max="3650" value="{expiry.get("ssh", 5)}"></div></div><button type="submit" style="width:100%;max-width:400px;"><i class="fa-solid fa-calendar-plus"></i> Save Default</button></form><script>(function(){{const serviceSelect=document.getElementById('expiry-service-select');const daysInput=document.getElementById('expiry-days-input');const expiryMap={expiry_json};if(!serviceSelect||!daysInput)return;function syncDays(){{const key=serviceSelect.value||'ssh';if(Object.prototype.hasOwnProperty.call(expiryMap,key))daysInput.value=expiryMap[key];}}serviceSelect.addEventListener('change',syncDays);syncDays();}})();</script></div>
    </div>
    {account_manager_html}
    {bypass_editor_html}
    <div style="margin-top:1.2rem;"><div style="font-weight:700;margin-bottom:.8rem;">Recent Audit</div>{event_cards}</div>
  </div>
</div>""")


hostname_page_html, ip_page_html = render_lookup_pages()


@app.get("/site-icon.svg")
def site_icon():
    source = favicon_data_uri()
    if source:
        source = html.escape(source, quote=True)
        svg = f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
  <defs>
    <clipPath id="siteIconClip">
      <circle cx="32" cy="32" r="30"/>
    </clipPath>
  </defs>
  <rect width="64" height="64" rx="32" fill="#ffffff"/>
  <image href="{source}" width="64" height="64" preserveAspectRatio="xMidYMid slice" clip-path="url(#siteIconClip)"/>
  <circle cx="32" cy="32" r="30" fill="none" stroke="#5d0919" stroke-width="2"/>
</svg>"""
    else:
        svg = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
  <defs>
    <linearGradient id="siteIconBg" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0%" stop-color="#fff6f8"/>
      <stop offset="100%" stop-color="#f7d7de"/>
    </linearGradient>
  </defs>
  <circle cx="32" cy="32" r="30" fill="url(#siteIconBg)" stroke="#5d0919" stroke-width="2"/>
  <text x="32" y="39" text-anchor="middle" font-size="26" font-weight="700" font-family="Arial, sans-serif" fill="#7c1027">F</text>
</svg>"""
    response = Response(svg, mimetype="image/svg+xml")
    response.headers["Cache-Control"] = "public, max-age=3600"
    return response


@app.get("/site-logo")
def site_logo():
    payload, mime = image_source_asset(NAVBAR_LOGO_URL)
    if payload and mime in SUPPORTED_IMAGE_MIMES:
        response = Response(payload, mimetype=mime)
        response.headers["Cache-Control"] = "public, max-age=3600"
        return response
    if (NAVBAR_LOGO_URL or "").strip():
        return redirect(NAVBAR_LOGO_URL, code=302)
    return redirect("/site-icon.svg", code=302)


@app.get("/favicon.ico")
def favicon_legacy():
    return redirect("/site-icon.svg", code=302)


@app.get("/")
@app.get("/main")
def main_page():
    clear_selected_backend()
    return render_home()


@app.get("/service")
@app.get("/services")
def services_page():
    return render_services()


@app.get("/status")
def status_page():
    return render_status()


@app.get("/status/full")
def status_full():
    response = jsonify(get_status_payload())
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    return response


@app.get("/main/stats")
def main_stats():
    visits = load_visits(force_remote=True)
    requested_scope = str(request.args.get("scope", "") or "").strip().lower()
    if requested_scope == "all":
        online_stats = load_backend_summary_counters(force=False)
        online_stats["scope"] = "all"
        online_stats["scope_label"] = "All Servers"
        online_stats["scope_note"] = "All connected servers" if backend_configured() else "No backend connected"
    else:
        online_stats = load_main_online_stats(force=False)
    counters = load_backend_summary_counters(force=False)
    total_accounts = get_display_total_accounts(visits=visits, counters=counters, force_remote=True)
    ssh_online_users = max(int(online_stats.get("ssh_online_users", 0) or 0), 0)
    openvpn_online_users = max(int(online_stats.get("openvpn_online_users", 0) or 0), 0)
    online_users = ssh_online_users + openvpn_online_users
    response = jsonify(
        {
            "online_users": online_users,
            "ssh_online_users": ssh_online_users,
            "openvpn_online_users": openvpn_online_users,
            "online_entries": online_stats.get("online_entries", []),
            "online_scope": online_stats.get("scope", "all"),
            "online_scope_label": online_stats.get("scope_label", "All Servers"),
            "online_scope_note": online_stats.get("scope_note", "All connected servers"),
            "total_visits": visits.get("total_visits", 0),
            "total_accounts": total_accounts,
        }
    )
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    return response


@app.get("/main/server-health")
def main_server_health():
    response = jsonify({"statuses": get_all_backend_health_statuses()})
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    return response

@app.get("/hostname-to-ip")
def hostname_lookup_page():
    return render_page("Hostname to IP", hostname_page_html)


@app.post("/hostname-to-ip")
def hostname_lookup_action():
    hostname = (request.form.get("hostname") or "").strip()
    if not hostname:
        return '<div style="color:var(--error);margin-top:1em;">Please enter a hostname.</div>'
    try:
        resolved = socket.gethostbyname(hostname)
        return f'<div style="margin-top:1em;"><div style="color:var(--success);font-weight:600;"><i class="fa-solid fa-circle-check"></i> Hostname: <span style="color:var(--accent-color);">{html.escape(hostname)}</span></div><div style="margin-top:.7em;"><span style="font-weight:600;">IP Address:</span> <span style="color:var(--primary-color);font-size:1.1em;">{html.escape(resolved)}</span></div></div>'
    except Exception:
        return f'<div style="color:var(--error);margin-top:1em;"><i class="fa-solid fa-circle-xmark"></i> Could not resolve hostname: {html.escape(hostname)}</div>'


@app.get("/ip-lookup")
def ip_lookup_page():
    return render_page("IP Lookup", ip_page_html)


@app.post("/ip-lookup")
def ip_lookup_action():
    ip = (request.form.get("ip") or "").strip() or get_request_ip()
    try:
        api = f"http://ip-api.com/json/{urllib.parse.quote(ip)}?fields=status,message,country,regionName,city,zip,lat,lon,isp,org,as,query,timezone,mobile,proxy,hosting"
        with urllib.request.urlopen(api, timeout=6) as response:
            data = json.load(response)
    except Exception:
        return f'<div style="color:var(--error);margin-top:1em;">Error contacting geolocation service for {html.escape(ip)}.</div>'
    if data.get("status") != "success":
        return f'<div style="color:var(--error);margin-top:1em;"><i class="fa-solid fa-circle-xmark"></i> Lookup failed for {html.escape(ip)}: {html.escape(data.get("message", "Lookup failed"))}</div>'
    return f"""
<div style="margin-top:1em;">
  <div style="color:var(--success);font-weight:600;"><i class="fa-solid fa-circle-check"></i> IP: <span style="color:var(--accent-color);">{html.escape(data.get('query', ip))}</span></div>
  <div style="margin-top:.8em;display:grid;grid-template-columns:1fr 1fr;gap:.6rem;">
    <div class="link-box"><strong>Country:</strong> {html.escape(str(data.get('country', '-')))}</div>
    <div class="link-box"><strong>Region:</strong> {html.escape(str(data.get('regionName', '-')))}</div>
    <div class="link-box"><strong>City:</strong> {html.escape(str(data.get('city', '-')))}</div>
    <div class="link-box"><strong>ZIP:</strong> {html.escape(str(data.get('zip', '-')))}</div>
    <div class="link-box"><strong>Latitude:</strong> {html.escape(str(data.get('lat', '-')))}</div>
    <div class="link-box"><strong>Longitude:</strong> {html.escape(str(data.get('lon', '-')))}</div>
    <div class="link-box"><strong>ISP:</strong> {html.escape(str(data.get('isp', '-')))}</div>
    <div class="link-box"><strong>Org:</strong> {html.escape(str(data.get('org', '-')))}</div>
    <div class="link-box"><strong>ASN:</strong> {html.escape(str(data.get('as', '-')))}</div>
    <div class="link-box"><strong>Timezone:</strong> {html.escape(str(data.get('timezone', '-')))}</div>
    <div class="link-box"><strong>Mobile:</strong> {html.escape(str(bool(data.get('mobile', False))))}</div>
    <div class="link-box"><strong>Proxy:</strong> {html.escape(str(bool(data.get('proxy', False))))}</div>
    <div class="link-box"><strong>Hosting:</strong> {html.escape(str(bool(data.get('hosting', False))))}</div>
  </div>
</div>"""


@app.get("/donate")
def donate_page():
    return render_donate()


@app.get("/guide")
def guide_page():
    return render_guide_page()


@app.get("/terms")
@app.get("/terms-of-service")
def terms_page():
    return render_terms_of_service()


@app.get("/privacy")
@app.get("/privacy-policy")
def privacy_page():
    return render_privacy_policy()


@app.get("/readme")
def readme_page():
    return render_readme()


@app.post("/select-server")
def select_server():
    backend_id = (request.form.get("backend_id") or "").strip()
    redirect_to = (request.form.get("redirect_to") or "/services").strip()
    if not redirect_to.startswith("/") or redirect_to.startswith("//"):
        redirect_to = "/services"
    if set_selected_backend(backend_id):
        return redirect(redirect_to, code=303)
    return redirect("/main?error=" + urllib.parse.quote("Invalid server selection."), code=303)


def submit_service_request(service):
    values = {key: request.form.get(key, "") for key in ("username", "password", "bypass_option")}
    if not backend_configured():
        return render_unavailable(service_label(service))
    selection_redirect = require_backend_selection()
    if selection_redirect:
        return selection_redirect
    client_ip = get_request_ip()
    if not turnstile_configured():
        return render_service_form(service, error=turnstile_setup_message(), values=values)
    turnstile_ok, turnstile_error = verify_turnstile_response(request.form.get("cf-turnstile-response", ""), remote_ip=client_ip)
    if not turnstile_ok:
        return render_service_form(service, error=turnstile_error, values=values)
    cooldown_remaining = get_create_cooldown_remaining(client_ip, service)
    if cooldown_remaining > 0:
        return render_service_form(
            service,
            error=f"Please wait {format_cooldown_label(cooldown_remaining)} before creating another account.",
            values=values,
        )
    backend = selected_backend()
    backend_id = selected_backend_id() or "default"
    if get_scoped_daily_created_count(service=service, backend_id=backend_id) >= get_daily_account_limit():
        backend_name = backend_display_label(backend) if backend else "the selected server"
        return render_service_form(
            service,
            error=f"Daily {service_label(service)} account creation limit reached for {backend_name} today. It resets at {DAILY_RESET_TIME_LABEL}.",
            values=values,
        )
    payload = {"username": values.get("username", "").strip(), "days": get_create_account_expiry(service)}
    if service not in {"vless", "wireguard"}:
        payload["password"] = values.get("password", "")
    if service == "vless":
        bypass_option_id = values.get("bypass_option", "").strip()
        payload["bypass_option"] = bypass_option_id
        if bypass_option_id:
            selected_bypass = find_vless_bypass_option(bypass_option_id)
            if not selected_bypass:
                return render_service_form(service, error="Selected bypass option is no longer available.", values=values)
            payload["bypass_config"] = {
                "name": selected_bypass.get("name", ""),
                "tls": dict(selected_bypass.get("tls", {})),
                "nontls": dict(selected_bypass.get("nontls", {})),
            }
    try:
        data = backend_request(f"/create/{service}", payload=payload, method="POST")
        result = data.get("result", {}) if isinstance(data, dict) else {}
        set_create_cooldown(client_ip, service)
        increment_daily_created_count(service, backend_id=backend_id)
        increment_total_accounts()
        return render_service_result(service, result)
    except Exception as exc:
        return render_service_form(service, error=backend_error_message(exc), values=values)


@app.get("/ssh")
def ssh_page():
    return render_service_form("ssh")


@app.post("/ssh")
def ssh_create():
    return submit_service_request("ssh")


@app.get("/vless")
def vless_page():
    return render_service_form("vless")


@app.post("/vless")
def vless_create():
    return submit_service_request("vless")


@app.get("/hysteria")
def hysteria_page():
    return render_service_form("hysteria")


@app.post("/hysteria")
def hysteria_create():
    return submit_service_request("hysteria")


@app.get("/wireguard")
def wireguard_page():
    return render_service_form("wireguard")


@app.post("/wireguard")
def wireguard_create():
    return submit_service_request("wireguard")


@app.get("/openvpn")
def openvpn_page():
    return render_service_form("openvpn")


@app.post("/openvpn")
def openvpn_create():
    return submit_service_request("openvpn")


@app.get("/admin")
def admin_page():
    return render_admin(request.args.get("success"), request.args.get("error"))


@app.get("/admin/account-manager-fragment")
def admin_account_manager_fragment():
    if not session.get("admin_authenticated"):
        return Response("unauthorized", status=401, mimetype="text/plain")
    response = Response(render_admin_account_manager(force=False), mimetype="text/html")
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    return response


@app.get("/admin/online-breakdown")
def admin_online_breakdown():
    if not session.get("admin_authenticated"):
        response = jsonify({"ok": False, "error": "unauthorized"})
        response.status_code = 401
        return response
    response = jsonify(load_admin_backend_online_breakdown(force=False))
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    return response


@app.post("/admin")
def admin_post():
    action = request.form.get("action", "")
    if action == "login":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if admin_credentials_valid(username, password):
            session["admin_authenticated"] = True
            log_admin_event("login", "success", {"username": username})
            return redirect("/admin")
        log_admin_event("login", "failed", {"username": username})
        return render_admin(error="Invalid admin credentials.")
    if not session.get("admin_authenticated"):
        log_admin_event("unauthorized_admin_action", "failed", {"action": action})
        return redirect("/admin")
    if action == "update_limit":
        if set_daily_account_limit(request.form.get("limit", "")):
            log_admin_event("update_limit", "success", {"limit": request.form.get("limit", "")})
            return redirect("/admin?success=" + urllib.parse.quote("Daily account limit updated."), code=303)
        return redirect("/admin?error=" + urllib.parse.quote("Failed to update limit."), code=303)
    if action == "update_create_expiry":
        service = request.form.get("service", "")
        days = request.form.get("days", "")
        if set_create_account_expiry(service, days):
            log_admin_event("update_create_expiry", "success", {"service": service, "days": days})
            return redirect("/admin?success=" + urllib.parse.quote(f"New account expiration updated for {service.upper()}."), code=303)
        return redirect("/admin?error=" + urllib.parse.quote("Failed to update new account expiration."), code=303)
    if action == "update_account_expiry":
        backend_id = request.form.get("backend_id", "")
        service = request.form.get("service", "")
        username = request.form.get("username", "")
        days = request.form.get("days", "")
        backend = find_backend_config(backend_id)
        if not backend:
            log_admin_event("update_account_expiry", "failed", {"backend_id": backend_id, "service": service, "username": username, "days": days})
            return redirect("/admin?error=" + urllib.parse.quote("Selected backend was not found."), code=303)
        try:
            day_value = max(1, min(int(days), 3650))
        except Exception:
            log_admin_event("update_account_expiry", "failed", {"backend_id": backend_id, "service": service, "username": username, "days": days})
            return redirect("/admin?error=" + urllib.parse.quote("Expiration must be between 1 and 3650 days."), code=303)
        try:
            backend_request_for(
                backend,
                "/accounts/update-expiry",
                payload={"service": service, "username": username, "days": day_value},
                method="POST",
            )
            clear_admin_account_groups_cache()
            log_admin_event("update_account_expiry", "success", {"backend_id": backend_id, "service": service, "username": username, "days": day_value})
            return redirect("/admin?success=" + urllib.parse.quote(f"Expiration updated for {username}."), code=303)
        except Exception as exc:
            log_admin_event("update_account_expiry", "failed", {"backend_id": backend_id, "service": service, "username": username, "days": day_value})
            return redirect("/admin?error=" + urllib.parse.quote(backend_error_message(exc)), code=303)
    if action == "delete_account":
        backend_id = request.form.get("backend_id", "")
        service = request.form.get("service", "")
        username = request.form.get("username", "")
        backend = find_backend_config(backend_id)
        if not backend:
            log_admin_event("delete_account", "failed", {"backend_id": backend_id, "service": service, "username": username})
            return redirect("/admin?error=" + urllib.parse.quote("Selected backend was not found."), code=303)
        try:
            backend_request_for(
                backend,
                "/accounts/delete",
                payload={"service": service, "username": username},
                method="POST",
            )
            clear_admin_account_groups_cache()
            log_admin_event("delete_account", "success", {"backend_id": backend_id, "service": service, "username": username})
            return redirect("/admin?success=" + urllib.parse.quote(f"Removed {username} from {service.upper()}."), code=303)
        except Exception as exc:
            log_admin_event("delete_account", "failed", {"backend_id": backend_id, "service": service, "username": username})
            return redirect("/admin?error=" + urllib.parse.quote(backend_error_message(exc)), code=303)
    if action == "save_bypass_options":
        ok, saved_options = set_vless_bypass_options_from_json(request.form.get("bypass_options_json", "[]"))
        if ok:
            log_admin_event("save_bypass_options", "success", {"count": len(saved_options)})
            return redirect("/admin?success=" + urllib.parse.quote("VLESS bypass options updated."), code=303)
        log_admin_event("save_bypass_options", "failed", {})
        return redirect("/admin?error=" + urllib.parse.quote("Failed to update VLESS bypass options."), code=303)
    return redirect("/admin?error=" + urllib.parse.quote("Unknown admin action."), code=303)


@app.get("/admin/logout")
def admin_logout():
    session.pop("admin_authenticated", None)
    log_admin_event("logout", "success", {})
    return redirect("/admin")


@app.errorhandler(404)
def not_found(_error):
    return render_page("Not Found", '<div class="container"><div class="neo-box" style="max-width:500px;margin:0 auto;text-align:center;"><div style="color:var(--warning);font-size:3rem;margin-bottom:1rem;"><i class="fa-solid fa-compass-drafting"></i></div><h2 class="section-title">Page Not Found</h2><div style="margin:1.5rem 0;color:var(--text-secondary);">That route does not exist in this deployment.</div><a href="/main" style="text-decoration:none;"><button><i class="fa-solid fa-arrow-left"></i> Back to Main</button></a></div></div>'), 404


if __name__ == "__main__":
    ensure_state_dir()
    app.run(host="0.0.0.0", port=PORT, debug=False)
