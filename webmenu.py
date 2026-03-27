import base64
import copy
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
from datetime import datetime, timedelta
from functools import lru_cache
from pathlib import Path

from flask import Flask, Response, jsonify, has_request_context, redirect, render_template_string, request, session
from markupsafe import Markup


IS_VERCEL = bool(os.environ.get("VERCEL"))
PORT = int(os.environ.get("PORT", "8000"))
STATE_DIR = Path("/tmp/webmenu_state") if IS_VERCEL else Path.cwd() / ".webmenu_state"
VISITS_FILE = STATE_DIR / "visits.json"
CONFIG_FILE = STATE_DIR / "config.json"
COUNTS_FILE = STATE_DIR / "counts.json"
CHAT_FILE = STATE_DIR / "chat.json"
AUDIT_FILE = STATE_DIR / "audit.json"
COOLDOWN_FILE = STATE_DIR / "cooldowns.json"
README_FILE = Path.cwd() / "README.md"
FAVICON_SOURCE_URL = "https://raw.githubusercontent.com/hahacrunchyrollls/logo-s/refs/heads/main/aika.jpg"
NAVBAR_LOGO_URL = "https://raw.githubusercontent.com/hahacrunchyrollls/logo-s/refs/heads/main/aika.jpg"

CREATE_EXPIRY_DEFAULTS = {"ssh": 5, "vless": 3, "hysteria": 5, "openvpn": 3}
DAILY_ACCOUNT_LIMIT_DEFAULT = 30
MAX_CHAT_MESSAGES = 200
CREATE_COOLDOWN_SECONDS = 600

SERVICE_META = [
    ("ssh", "SSH", "https://raw.githubusercontent.com/hahacrunchyrollls/logo-s/refs/heads/main/icon-ssh.png"),
    ("vless", "VLESS", "https://raw.githubusercontent.com/hahacrunchyrollls/logo-s/refs/heads/main/icon-v2ray.png"),
    ("hysteria", "HYSTERIA", "https://raw.githubusercontent.com/hahacrunchyrollls/logo-s/refs/heads/main/icon-hysteria.png"),
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
chat_lock = threading.Lock()
traffic_lock = threading.Lock()
last_traffic_snapshot = {"time": None, "rx": 0, "tx": 0, "source": None}

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or os.environ.get("SESSION_SECRET") or secrets.token_hex(32)


def _clone(value):
    return copy.deepcopy(value)


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


def _ph_date():
    return (datetime.utcnow() + timedelta(hours=8)).strftime("%Y-%m-%d")


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


def env_first(*names):
    for name in names:
        value = os.environ.get(name, "").strip()
        if value:
            return value
    return ""


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


def load_config():
    config = load_json(
        CONFIG_FILE,
        {"daily_limit": DAILY_ACCOUNT_LIMIT_DEFAULT, "create_expiry": dict(CREATE_EXPIRY_DEFAULTS)},
    )
    config.setdefault("daily_limit", DAILY_ACCOUNT_LIMIT_DEFAULT)
    config.setdefault("create_expiry", dict(CREATE_EXPIRY_DEFAULTS))
    for service, default in CREATE_EXPIRY_DEFAULTS.items():
        try:
            config["create_expiry"][service] = max(1, min(int(config["create_expiry"].get(service, default)), 3650))
        except Exception:
            config["create_expiry"][service] = default
    try:
        config["daily_limit"] = max(1, min(int(config["daily_limit"]), 999))
    except Exception:
        config["daily_limit"] = DAILY_ACCOUNT_LIMIT_DEFAULT
    return config


def load_backends():
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


def backend_configured():
    return bool(load_backends())


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
    options = load_backends()
    if not options:
        return None
    valid_ids = {backend["id"] for backend in options}
    if has_request_context():
        selected = session.get("selected_backend_id")
        if selected in valid_ids:
            return selected
    return default_backend_id()


def selected_backend():
    current_id = selected_backend_id()
    for backend in load_backends():
        if backend["id"] == current_id:
            return backend
    return None


def set_selected_backend(backend_id):
    valid_ids = {backend["id"] for backend in load_backends()}
    if backend_id in valid_ids and has_request_context():
        session["selected_backend_id"] = backend_id
        return True
    return False


def backend_host(backend=None):
    backend = backend or selected_backend()
    if backend:
        api_url = backend.get("api_url", "")
        if api_url:
            parsed = urllib.parse.urlsplit(api_url)
            if parsed.hostname:
                return parsed.hostname
    return current_host()


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
        return {
            "country": data.get("country", "Unknown"),
            "countryCode": data.get("countryCode", ""),
            "city": data.get("city", ""),
        }
    except Exception:
        return {"country": "Unknown", "countryCode": "", "city": ""}


def backend_request(path, payload=None, method="POST"):
    backend = selected_backend()
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
        return save_json(CONFIG_FILE, config)


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
        return save_json(CONFIG_FILE, config)


def load_counts():
    data = load_json(COUNTS_FILE, {"date": _ph_date(), "counts": {}})
    if data.get("date") != _ph_date():
        data = {"date": _ph_date(), "counts": {}}
        save_json(COUNTS_FILE, data)
    data.setdefault("counts", {})
    counts = data["counts"]
    if counts and all(isinstance(value, int) for value in counts.values()):
        data["counts"] = {"default": counts}
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


def get_daily_created_count(service=None, backend_id=None):
    data = load_counts()
    backend_id = backend_id or selected_backend_id() or "default"
    counts = data.get("counts", {}).get(backend_id, {})
    if service:
        try:
            return int(counts.get(service, 0))
        except Exception:
            return 0
    return _sum_service_counts(counts)


def get_total_daily_created_count():
    data = load_counts()
    total = 0
    for counts in data.get("counts", {}).values():
        total += _sum_service_counts(counts)
    return total


def increment_daily_created_count(service, backend_id=None):
    with state_lock:
        data = load_counts()
        backend_id = backend_id or selected_backend_id() or "default"
        data["counts"].setdefault(backend_id, {})
        data["counts"][backend_id][service] = int(data["counts"][backend_id].get(service, 0)) + 1
        save_json(COUNTS_FILE, data)
        return data["counts"][backend_id][service]


def load_visits():
    data = load_json(VISITS_FILE, {"total_visits": 0, "total_accounts": 0, "daily": {}})
    data.setdefault("total_visits", 0)
    data.setdefault("total_accounts", 0)
    data.setdefault("daily", {})
    return data


def bump_visit_count():
    with state_lock:
        data = load_visits()
        today = _ph_date()
        data["total_visits"] += 1
        day_bucket = data["daily"].setdefault(today, {"visits": 0})
        day_bucket["visits"] += 1
        keys = sorted(data["daily"].keys())[-14:]
        data["daily"] = {key: data["daily"][key] for key in keys}
        save_json(VISITS_FILE, data)
        return data


def increment_total_accounts():
    with state_lock:
        data = load_visits()
        current_total = int(data.get("total_accounts", 0) or 0)
        data["total_accounts"] = max(current_total + 1, get_total_daily_created_count())
        save_json(VISITS_FILE, data)
        return data["total_accounts"]


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


def load_chat_messages():
    data = load_json(CHAT_FILE, {"messages": []})
    messages = data.get("messages", [])
    return messages if isinstance(messages, list) else []


def add_chat_message(name, message):
    clean_name = re.sub(r"[^A-Za-z]", "", name or "").strip()[:10] or "Anonymous"
    clean_message = (message or "").strip()[:500]
    if not clean_message:
        return
    entry = {
        "name": html.escape(clean_name),
        "message": html.escape(clean_message),
        "time": (datetime.utcnow() + timedelta(hours=8)).strftime("%Y-%m-%d %H:%M:%S"),
    }
    with chat_lock:
        messages = load_chat_messages()
        messages.append(entry)
        save_json(CHAT_FILE, {"messages": messages[-MAX_CHAT_MESSAGES:]})


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


def announcement_exists():
    try:
        return README_FILE.exists() and README_FILE.read_text(encoding="utf-8").strip() != ""
    except Exception:
        return False


def announcement_html():
    try:
        raw = README_FILE.read_text(encoding="utf-8").strip()
    except Exception:
        raw = ""
    if not raw:
        return "<div style='color:var(--error);font-weight:600;text-align:center;'>NO ANNOUNCEMENT!</div>"
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
    return text.replace("\n", "<br>")


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


def guess_image_mime(url):
    lower = (url or "").lower()
    if lower.endswith(".png"):
        return "image/png"
    if lower.endswith(".jpg") or lower.endswith(".jpeg"):
        return "image/jpeg"
    if lower.endswith(".webp"):
        return "image/webp"
    if lower.endswith(".gif"):
        return "image/gif"
    return "application/octet-stream"


@lru_cache(maxsize=1)
def favicon_data_uri():
    try:
        req = urllib.request.Request(FAVICON_SOURCE_URL, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=10) as response:
            payload = response.read()
            mime = response.headers.get_content_type() or guess_image_mime(FAVICON_SOURCE_URL)
        encoded = base64.b64encode(payload).decode("ascii")
        return f"data:{mime};base64,{encoded}"
    except Exception:
        return ""


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
body{background:var(--bg-gradient);color:var(--text-primary);font-family:'Comic Neue','Trebuchet MS',sans-serif;margin:0;min-height:100vh;line-height:1.6;overflow-x:hidden;position:relative;}
body::before{content:"";position:fixed;inset:0;z-index:-2;background:radial-gradient(circle,rgba(124,16,39,.13) 0 1.6px,transparent 1.8px 100%) 0 0/24px 24px,radial-gradient(circle,rgba(124,16,39,.08) 0 1.4px,transparent 1.7px 100%) 12px 12px/24px 24px,linear-gradient(135deg,rgba(124,16,39,.06) 0%,transparent 35%,rgba(124,16,39,.04) 100%);}
a{color:var(--primary-color);}
button{background:linear-gradient(180deg,var(--primary-color) 0%,var(--accent-color) 100%);color:#fff;border:3px solid var(--ink);border-radius:16px;font-weight:700;font-size:1rem;padding:14px 28px;cursor:pointer;transition:var(--transition);display:inline-flex;align-items:center;justify-content:center;gap:8px;box-shadow:5px 5px 0 var(--ink);font-family:'Bangers','Comic Neue',cursive;letter-spacing:.08em;text-transform:uppercase;}
button:hover,button:focus{transform:translate(3px,3px);box-shadow:2px 2px 0 var(--ink);background:linear-gradient(180deg,var(--accent-hover) 0%,var(--primary-color) 100%);outline:none;}
.container{width:95%;max-width:720px;margin:2rem auto;padding:0 1rem;}
.neo-box{background:var(--card-bg);border-radius:var(--border-radius);box-shadow:var(--card-shadow),var(--soft-shadow);padding:1.8rem 1.5rem;margin-bottom:2rem;border:3px solid var(--card-border);position:relative;overflow:hidden;}
.neo-box::before{content:"";position:absolute;top:14px;right:-48px;width:160px;height:34px;background:rgba(124,16,39,.08);transform:rotate(28deg);}
.section-title{font-family:'Bangers','Comic Neue',cursive;font-size:clamp(2rem,5vw,3rem);letter-spacing:.08em;margin-bottom:1rem;color:var(--primary-color);background:none;-webkit-text-fill-color:initial;text-shadow:2px 2px 0 rgba(31,6,12,.14);}
.success-msg{display:flex;align-items:center;background:linear-gradient(180deg,#ffffff 0%,#fff6f8 100%);border:3px solid var(--success);border-radius:var(--border-radius);padding:1rem;margin-bottom:1.5rem;font-weight:700;font-size:1.05em;color:var(--text-primary);box-shadow:4px 4px 0 rgba(93,9,25,.24);}
.info-grid,.status-grid-2,.services-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px;}
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
.server-selector{max-width:760px;margin:0 auto 1.35rem auto;padding:1.1rem;background:linear-gradient(180deg,#ffffff 0%,#fff2f5 100%);border:3px solid var(--card-border);border-radius:22px;box-shadow:6px 6px 0 rgba(93,9,25,.24);}
.server-selector-head{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:1rem;text-align:left;}
.server-selector-kicker{display:inline-flex;align-items:center;gap:8px;color:var(--primary-color);font-family:'Bangers','Comic Neue',cursive;font-weight:700;font-size:1rem;letter-spacing:.08em;text-transform:uppercase;}
.server-selector-title{font-family:'Bangers','Comic Neue',cursive;font-size:1.35rem;font-weight:700;color:var(--primary-color);margin-top:.35rem;letter-spacing:.04em;}
.server-selector-note{color:var(--text-muted);font-size:.95rem;max-width:420px;font-weight:700;}
.server-selector-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px;}
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
.server-card-host{display:flex;align-items:center;gap:8px;padding:10px 15px 14px 15px;border-top:2px dashed rgba(93,9,25,.25);color:var(--text-muted);font-size:.86rem;background:rgba(124,16,39,.04);}
.server-badge{display:inline-flex;align-items:center;gap:6px;padding:6px 10px;border-radius:999px;border:2px solid rgba(93,9,25,.18);font-size:.78rem;font-weight:800;letter-spacing:.04em;text-transform:uppercase;color:var(--text-secondary);background:rgba(124,16,39,.05);}
.server-badge.active{background:#fff;color:var(--primary-color);border-color:var(--ink);}
.server-current-pill{display:flex;align-items:center;justify-content:center;gap:10px;flex-wrap:wrap;max-width:760px;margin:0 auto 1.35rem auto;padding:.9rem 1rem;border-radius:999px;background:var(--surface);border:3px solid var(--card-border);box-shadow:4px 4px 0 rgba(93,9,25,.18);color:var(--text-secondary);font-size:.95rem;font-weight:700;}
.server-current-dot{height:10px;width:10px;border-radius:50%;background:var(--success);box-shadow:0 0 0 6px rgba(143,23,48,.12);}
.server-current-name{color:var(--primary-color);font-weight:800;font-family:'Bangers','Comic Neue',cursive;letter-spacing:.04em;}
.server-current-meta{color:var(--text-muted);}
.global-ad-wrap{width:min(100% - 2rem,960px);margin:1.25rem auto 0 auto;padding:0 1rem;box-sizing:border-box;}
.global-ad-shell{background:linear-gradient(180deg,#ffffff 0%,#fff2f5 100%);border:3px solid var(--card-border);border-radius:18px;box-shadow:4px 4px 0 rgba(93,9,25,.16);padding:12px;overflow:hidden;}
.public-chat{margin-top:1.5rem;display:flex;flex-direction:column;gap:8px;align-items:center}.chat-box{width:100%;max-width:400px;background:linear-gradient(180deg,#ffffff 0%,#fff5f7 100%);border-radius:16px;padding:10px;border:3px solid var(--card-border);box-shadow:4px 4px 0 rgba(93,9,25,.16);max-height:320px;overflow:auto;font-size:.98rem}.chat-message{padding:8px;border-radius:12px;margin-bottom:8px;background:rgba(124,16,39,.05);border:2px dashed rgba(124,16,39,.24);display:block}.chat-meta{display:flex;align-items:center;gap:8px}.chat-name{font-weight:700;color:var(--primary-color)}.chat-time{color:var(--text-muted);font-size:.8rem;margin-left:auto}.chat-text{margin-top:6px;white-space:pre-wrap;overflow-wrap:anywhere;word-break:break-word}.chat-form{width:100%;max-width:400px;display:flex;gap:8px;align-items:center;flex-direction:column}.chat-form input[type="text"]{width:100%}
.loading-overlay{display:none;position:fixed;inset:0;z-index:9999;background:rgba(93,9,25,.78);backdrop-filter:blur(4px);justify-content:center;align-items:center;flex-direction:column;gap:1.5rem}.loading-overlay.active{display:flex}.loading-spinner{width:56px;height:56px;border:4px solid rgba(255,255,255,.24);border-top-color:#fff;border-radius:50%;animation:spin .7s linear infinite}.loading-text{font-family:'Bangers','Comic Neue',cursive;font-size:1.2rem;letter-spacing:.06em;color:#fff}
@keyframes spin{to{transform:rotate(360deg);}}
@media (max-width:880px){.navbar-nav{display:none}.burger-btn{display:inline-flex;align-items:center;justify-content:center;}.navbar{padding:.6rem .8rem}}
@media (max-width:576px){.container{width:95%;padding:0}.neo-box{padding:1.2rem 1rem}.info-grid,.status-grid-2,.services-grid,.server-selector-grid{grid-template-columns:1fr}.stats-container{flex-direction:column;align-items:center}.server-selector{padding:1rem}.server-current-pill{border-radius:18px}.navbar-brand{flex-wrap:wrap;justify-content:flex-start}.section-title{font-size:2.2rem}}
</style>
</head>
<body>
<div class="loading-overlay" id="loadingOverlay"><div class="loading-spinner"></div><div class="loading-text">Creating your account...</div></div>
{{ navbar|safe }}
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
{{ content|safe }}
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
<script>
document.addEventListener('DOMContentLoaded',function(){const p=window.location.pathname;document.querySelectorAll('.nav-link').forEach(a=>{const h=a.getAttribute('href');if(p===h||(p==='/'&&h==='/main/'))a.classList.add('active');});const b=document.getElementById('navbar-burger');const m=document.getElementById('mobile-menu');if(b&&m){b.addEventListener('click',function(e){e.stopPropagation();const open=m.style.display==='flex';m.style.display=open?'none':'flex';});document.addEventListener('click',function(e){if(!m.contains(e.target)&&!b.contains(e.target))m.style.display='none';});}});
</script>
</body>
</html>
"""


def navbar_html():
    announcement_link = '<a href="/readme/" class="nav-link"><i class="fa-solid fa-bullhorn"></i> Announcement</a>' if announcement_exists() else ""
    mobile_announcement = '<a href="/readme/"><i class="fa-solid fa-bullhorn"></i> Announcement</a>' if announcement_exists() else ""
    visitor_ip = html.escape(get_request_ip())
    return f"""
<nav class="navbar">
  <a href="/main/" class="navbar-brand">
    <img src="{NAVBAR_LOGO_URL}" alt="FUJI PANEL" class="brand-icon">
    <span>FUJI PANEL</span>
    <span style="display:inline-flex;align-items:center;font-size:.78rem;font-weight:700;color:var(--text-secondary);margin-left:.55rem;padding:.24rem .55rem;background:var(--surface);border-radius:999px;border:2px solid var(--card-border);box-shadow:3px 3px 0 rgba(93,9,25,.18);white-space:nowrap;">IP: {visitor_ip}</span>
  </a>
  <div class="navbar-nav">
    <a href="/main/" class="nav-link"><i class="fa-solid fa-house"></i> Home</a>
    <a href="/services/" class="nav-link"><i class="fa-solid fa-layer-group"></i> Service</a>
    <a href="/status/" class="nav-link"><i class="fa-solid fa-server"></i> Status</a>
    <a href="/hostname-to-ip/" class="nav-link"><i class="fa-solid fa-globe"></i> Hostname to IP</a>
    <a href="/ip-lookup/" class="nav-link"><i class="fa-solid fa-location-dot"></i> IP Lookup</a>
    {announcement_link}
    <a href="/donate/" class="nav-link"><i class="fa-solid fa-donate"></i> Donate</a>
  </div>
  <button class="burger-btn" id="navbar-burger" type="button"><i class="fa-solid fa-bars"></i></button>
  <div class="mobile-menu" id="mobile-menu">
    <a href="/main/"><i class="fa-solid fa-house"></i> Home</a>
    <a href="/services/"><i class="fa-solid fa-layer-group"></i> Service</a>
    <a href="/status/"><i class="fa-solid fa-server"></i> Status</a>
    <a href="/hostname-to-ip/"><i class="fa-solid fa-globe"></i> Hostname to IP</a>
    <a href="/ip-lookup/"><i class="fa-solid fa-location-dot"></i> IP Lookup</a>
    {mobile_announcement}
    <a href="/donate/"><i class="fa-solid fa-donate"></i> Donate</a>
  </div>
</nav>
"""


def render_page(title, content):
    return render_template_string(BASE_TEMPLATE, title=title, navbar=Markup(navbar_html()), content=Markup(content))


def build_service_cards():
    cards = []
    daily_limit = get_daily_account_limit()
    enabled = backend_configured()
    for service, label, icon in SERVICE_META:
        created = get_daily_created_count(service)
        anchor_attr = "" if enabled else 'onclick="return false;"'
        button_attr = "" if enabled else "disabled"
        style_attr = "width:100%;display:flex;align-items:center;justify-content:space-between;gap:10px;padding:12px 14px;"
        if not enabled:
            style_attr += "opacity:.55;cursor:not-allowed;"
        cards.append(
            f"""
<div class="create-cell">
  <a href="/{service}/" {anchor_attr}>
    <button class="create-btn" {button_attr} style="{style_attr}">
      <div style="display:flex;align-items:center;gap:10px;font-weight:700;color:var(--text-primary);"><img src="{icon}" style="height:1.1em;"> CREATE {label}</div>
      <div><span style="background:var(--primary-color);padding:4px 8px;border-radius:999px;font-weight:700;color:#fff;border:2px solid var(--ink);box-shadow:2px 2px 0 var(--ink);">{created}/{daily_limit}</span></div>
    </button>
  </a>
</div>"""
        )
    return "".join(cards)


def render_selected_server_note(change_href="/main/", include_change=True, margin_style="margin:0 auto 1.35rem auto;"):
    current_backend = selected_backend()
    if not current_backend:
        return ""
    backend_geo = backend_location(current_backend)
    location_bits = [bit for bit in [current_backend.get("city") or backend_geo.get("city", ""), current_backend.get("country") or backend_geo.get("country", "")] if bit]
    change_link = ""
    if include_change:
        change_link = f'<a href="{html.escape(change_href)}" style="color:var(--accent-color);text-decoration:none;font-weight:700;">Change</a>'
    return (
        f'<div class="server-current-pill" style="{margin_style}max-width:760px;">'
        '<span class="server-current-dot"></span>'
        '<span>Selected server</span>'
        f'<span class="server-current-name">{html.escape(current_backend["label"])}</span>'
        + (
            f'<span class="server-current-meta">{html.escape(", ".join(location_bits))}</span>'
            if location_bits
            else ""
        )
        + change_link
        + "</div>"
    )


def render_server_selector(redirect_to="/services/"):
    backends = load_backends()
    if not backends:
        return ""
    current_id = selected_backend_id()
    server_cards = []
    for backend in backends:
        backend_geo = backend_location(backend)
        country = backend.get("country") or backend_geo.get("country") or backend.get("label") or "Unknown"
        city = backend.get("city") or backend_geo.get("city") or ""
        country_code = (backend.get("countryCode") or backend_geo.get("countryCode") or "").upper()
        flag_html = (
            f'<img class="server-flag" src="https://flagcdn.com/48x36/{country_code.lower()}.png" alt="{html.escape(country_code)} flag">'
            if country_code
            else '<span class="server-flag-fallback"><i class="fa-solid fa-globe"></i></span>'
        )
        is_active = backend["id"] == current_id
        active_class = " is-active" if is_active else ""
        badge_html = (
            '<span class="server-badge active"><i class="fa-solid fa-circle-check"></i> Active</span>'
            if is_active
            else '<span class="server-badge"><i class="fa-solid fa-arrow-right"></i> Select</span>'
        )
        location_bits = [bit for bit in [city, country] if bit]
        location_label = ", ".join(location_bits) if location_bits else backend["label"]
        server_cards.append(
            f"""
      <form method="POST" action="/select-server/" class="server-card-form">
        <input type="hidden" name="backend_id" value="{html.escape(backend['id'])}">
        <input type="hidden" name="redirect_to" value="{html.escape(redirect_to)}">
        <button type="submit" class="server-card-button{active_class}">
          <div class="server-card-main">
            {flag_html}
            <div class="server-copy">
              <div class="server-card-title">
                <span>{html.escape(backend["label"])}</span>
                {badge_html}
              </div>
              <div class="server-card-location"><i class="fa-solid fa-location-dot" style="color:var(--accent-color);margin-right:6px;"></i>{html.escape(location_label)}</div>
            </div>
          </div>
          <div class="server-card-host"><i class="fa-solid fa-server" style="color:var(--accent-color);"></i><span>{html.escape(backend_host(backend))}</span></div>
        </button>
      </form>"""
        )
    return f"""
    <div class="server-selector">
      <div class="server-selector-head">
        <div>
          <div class="server-selector-kicker"><i class="fa-solid fa-earth-asia"></i> Choose Country / Server</div>
          <div class="server-selector-title">Pick a server first</div>
          <div class="server-selector-note">After you choose a server, we will take you to the Service page to pick a protocol.</div>
        </div>
      </div>
      <div class="server-selector-grid">{''.join(server_cards)}</div>
    </div>"""


def render_home():
    visits = bump_visit_count()
    enabled = backend_configured()
    selector_html = render_server_selector("/services/")
    current_server_note = render_selected_server_note(include_change=False)
    continue_html = ""
    if enabled and selected_backend():
        continue_html = """
    <div style="margin:1.5rem auto 0 auto;max-width:420px;">
      <a href="/services/" style="text-decoration:none;display:block;">
        <button style="width:100%;"><i class="fa-solid fa-layer-group"></i> Continue to Service</button>
      </a>
    </div>"""
    page_error = (request.args.get("error", "") if has_request_context() else "").strip()
    return render_page(
        "FUJI PANEL",
        render_template_string(
            """
<div class="container">
  <div class="neo-box" style="text-align:center;">
    <div style="display:flex;align-items:center;justify-content:center;gap:.8em;margin-bottom:1.5em;">
      <i class="fa-solid fa-earth-asia" style="font-size:1.8em;color:var(--accent-color);"></i>
      <h2 class="section-title" style="margin:0;">CHOOSE SERVER</h2>
    </div>
    <div style="font-size:1rem;color:var(--text-secondary);margin-bottom:1.6rem;">Select your server first. Protocol selection now lives on the Service page.</div>
    {{ selector_html|safe }}
    {{ current_server_note|safe }}
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
    {{ continue_html|safe }}
  </div>
</div>
<div class="public-chat">
  <div class="chat-box" id="public-chat-box"></div>
  <form id="public-chat-form" onsubmit="sendPublicChat(event)" class="chat-form">
    <input name="name" id="chat-name" type="text" placeholder="Name (max 10 letters)" maxlength="10" autocomplete="off">
    <input name="message" id="chat-message" type="text" placeholder="Message" required>
    <button type="submit">Send</button>
  </form>
</div>
<div class="stats-container">
  <div class="stat-item"><i class="fa-regular fa-eye stat-icon"></i><div><div class="stat-value" id="total-visits">{{ visits }}</div><div class="stat-label">Total Visits</div></div></div>
  <div class="stat-item"><i class="fa-solid fa-user-check stat-icon"></i><div><div class="stat-value" id="online-users">0</div><div class="stat-label">Online Users</div></div></div>
  <div class="stat-item"><i class="fa-solid fa-users stat-icon"></i><div><div class="stat-value" id="total-accounts">0</div><div class="stat-label">Accounts Created</div></div></div>
</div>
<script>
function renderChat(messages){const box=document.getElementById('public-chat-box');if(!box)return;box.innerHTML='';messages.forEach(m=>{const item=document.createElement('div');item.className='chat-message';item.innerHTML='<div class="chat-meta"><div class="chat-name">'+(m.name||'Anonymous')+'</div><div class="chat-time">'+(m.time||'')+'</div></div><div class="chat-text">'+(m.message||'')+'</div>';box.appendChild(item);});box.scrollTop=box.scrollHeight;}
function fetchChat(){fetch('/chat/messages?t='+Date.now(),{cache:'no-store'}).then(r=>r.json()).then(j=>{if(j&&j.messages)renderChat(j.messages);}).catch(()=>{});}
function sendPublicChat(e){e.preventDefault();let name=document.getElementById('chat-name').value||'';const message=document.getElementById('chat-message').value||'';name=name.replace(/[^A-Za-z]/g,'').slice(0,10);if(!message.trim())return;const body=new URLSearchParams();body.append('name',name);body.append('message',message);fetch('/chat/send',{method:'POST',body}).then(()=>{document.getElementById('chat-message').value='';fetchChat();}).catch(()=>{});}
function updateMainStats(){fetch('/main/stats?t='+Date.now(),{cache:'no-store'}).then(r=>r.json()).then(data=>{document.getElementById('online-users').textContent=data.online_users;document.getElementById('total-visits').textContent=data.total_visits;document.getElementById('total-accounts').textContent=data.total_accounts;}).catch(()=>{});}
fetchChat();updateMainStats();setInterval(fetchChat,3000);setInterval(updateMainStats,1000);
</script>
""",
            visits=visits["total_visits"],
            selector_html=Markup(selector_html),
            current_server_note=Markup(current_server_note),
            continue_html=Markup(continue_html),
            page_error=page_error,
            backend_ready=enabled,
        ),
    )


def render_services():
    if not backend_configured():
        return render_unavailable("Service")
    current_server_note = render_selected_server_note(change_href="/main/", include_change=True)
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
    <style>.create-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px;margin:0 auto;max-width:640px}.create-cell a{text-decoration:none;display:block}@media (max-width:480px){.create-grid{grid-template-columns:1fr}}</style>
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
    return render_page(
        "Server Status",
        """
<div class="container"><div class="neo-box">
  <div style="display:flex;align-items:center;justify-content:center;gap:.8em;margin-bottom:1.5em;"><i class="fa-solid fa-server" style="font-size:1.8em;color:var(--accent-color);"></i><h2 class="section-title" style="margin:0;">Server Status</h2></div>
  <div id="status-source-note" class="success-msg" style="display:none;"></div>
  <div class="status-subtitle"><i class="fa-solid fa-network-wired"></i> Network Traffic</div><div class="status-grid-2" id="network-grid"></div>
  <div class="status-subtitle"><i class="fa-solid fa-microchip"></i> System Resources</div><div class="status-grid-2" id="status-grid"></div>
  <div class="status-subtitle"><i class="fa-solid fa-plug"></i> Services</div><div class="services-grid" id="services-container"></div>
</div></div>
<script>
function escapeHtml(v){return String(v??'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',\"'\":'&#39;'}[m]));}
function formatSpeed(v){if(v>1024*1024)return (v/1024/1024).toFixed(2)+' MB/s';if(v>1024)return (v/1024).toFixed(2)+' KB/s';return v.toFixed(0)+' B/s';}
function formatBytes(v){if(v>1024*1024*1024)return (v/1024/1024/1024).toFixed(2)+' GB';if(v>1024*1024)return (v/1024/1024).toFixed(2)+' MB';if(v>1024)return (v/1024).toFixed(2)+' KB';return v.toFixed(0)+' B';}
function updateStatus(){fetch('/status/full?t='+Date.now()).then(r=>r.json()).then(data=>{const note=document.getElementById('status-source-note');const sourceName=escapeHtml(data.backend_label||data.backend_host||'configured server');if(note){if(data.status_source==='backend'){note.style.display='flex';note.style.background='linear-gradient(180deg,#ffffff 0%,#fff6f8 100%)';note.style.borderColor='var(--success)';note.innerHTML=`<i class="fa-solid fa-circle-check" style="color:var(--success);"></i><div>Live server status source: ${sourceName}</div>`;}else if(data.backend_error){note.style.display='flex';note.style.background='rgba(239,68,68,.1)';note.style.borderColor='var(--error)';note.innerHTML=`<i class="fa-solid fa-triangle-exclamation" style="color:var(--error);"></i><div>Could not read VPS status from ${sourceName}: ${escapeHtml(data.backend_error)}. Showing fallback stats from this web host instead.</div>`;}else{note.style.display='none';note.innerHTML='';}}document.getElementById('network-grid').innerHTML=`<div class="status-card"><div class="status-label"><i class="fa-solid fa-arrow-down" style="color:var(--success)"></i> Download Speed</div><div class="status-value">${formatSpeed(Number(data.net?.rx_rate||0))}</div></div><div class="status-card"><div class="status-label"><i class="fa-solid fa-arrow-up" style="color:var(--accent-color)"></i> Upload Speed</div><div class="status-value">${formatSpeed(Number(data.net?.tx_rate||0))}</div></div><div class="status-card"><div class="status-label"><i class="fa-solid fa-database" style="color:var(--success)"></i> Total Downloaded</div><div class="status-value">${formatBytes(Number(data.net?.rx_bytes||0))}</div></div><div class="status-card"><div class="status-label"><i class="fa-solid fa-database" style="color:var(--accent-color)"></i> Total Uploaded</div><div class="status-value">${formatBytes(Number(data.net?.tx_bytes||0))}</div></div>`;document.getElementById('status-grid').innerHTML=`<div class="status-card"><div class="status-label"><i class="fa-solid fa-microchip" style="color:var(--primary-color)"></i> CPU Usage</div><div class="status-value">${Number(data.cpu||0)}%</div></div><div class="status-card"><div class="status-label"><i class="fa-solid fa-chart-line" style="color:var(--accent-color)"></i> Load Average</div><div class="status-value">${Array.isArray(data.load)?data.load.join(', '):'0.00, 0.00, 0.00'}</div></div><div class="status-card"><div class="status-label"><i class="fa-solid fa-memory" style="color:var(--success)"></i> Memory Used</div><div class="status-value">${Number(data.mem?.used||0)} / ${Number(data.mem?.total||0)} MB</div></div><div class="status-card"><div class="status-label"><i class="fa-solid fa-memory" style="color:var(--primary-color)"></i> Memory Available</div><div class="status-value">${Number(data.mem?.available||0)} MB</div></div><div class="status-card"><div class="status-label"><i class="fa-solid fa-hdd" style="color:var(--accent-color)"></i> Storage Used</div><div class="status-value">${Number(data.storage?.used||0)} / ${Number(data.storage?.total||0)} MB</div></div><div class="status-card"><div class="status-label"><i class="fa-solid fa-hdd" style="color:var(--success)"></i> Storage Free</div><div class="status-value">${Number(data.storage?.free||0)} MB</div></div>`;let s='';(data.services||[]).forEach(x=>{const name=escapeHtml(x[0]);let icon='',label='',color='var(--text-muted)';if(x[1]===true){icon='<i class="fa-solid fa-circle-check" style="color:var(--success)"></i>';label='ONLINE';color='var(--success)';}else if(x[1]===false){icon='<i class="fa-solid fa-circle-xmark" style="color:var(--error)"></i>';label='OFFLINE';color='var(--error)';}else{icon='<i class="fa-solid fa-circle-question" style="color:var(--warning)"></i>';label='UNKNOWN';color='var(--warning)';}s+=`<div class="service-item"><div style="display:flex;align-items:center;justify-content:space-between;gap:10px;"><div>${icon} ${name}</div><div style="font-weight:700;color:${color};">${label}</div></div></div>`;});document.getElementById('services-container').innerHTML=s;}).catch(()=>{});}
updateStatus();setInterval(updateStatus,2000);
</script>
""",
    )


def render_unavailable(service_name):
    return render_page(
        f"{service_name} Not Available",
        f"""
<div class="container"><div class="neo-box" style="max-width:500px;margin:0 auto;text-align:center;">
  <div style="color:var(--error);font-size:3rem;margin-bottom:1rem;"><i class="fa-solid fa-circle-exclamation"></i></div>
  <h2 class="section-title" style="color:var(--error);">{html.escape(service_name)} Not Available</h2>
  <div style="margin:1.5rem 0;color:var(--text-secondary);">This Vercel deployment keeps the design, but real account provisioning still needs a Linux VPS backend.</div>
  <a href="/main/" style="text-decoration:none;"><button><i class="fa-solid fa-arrow-left"></i> Back to Main</button></a>
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
    values = values or {}
    label = service_label(service)
    icon = service_icon(service)
    days = get_create_account_expiry(service)
    current_backend_note = render_selected_server_note(change_href="/main/", include_change=True, margin_style="margin:-.8rem auto 1.4rem auto;")
    username_value = html.escape(values.get("username", ""))
    password_value = html.escape(values.get("password", ""))
    bypass_value = values.get("bypass_option", "")
    error_html = ""
    if error:
        error_html = f'<div class="success-msg" style="background:rgba(239,68,68,.1);border-left-color:var(--error);"><i class="fa-solid fa-circle-xmark" style="color:var(--error);"></i><div>{html.escape(error)}</div></div>'
    password_group = ""
    if service != "vless":
        password_group = f"""
      <div class="form-group">
        <label for="{service}-password" class="form-label"><i class="fa-solid fa-key"></i> Password</label>
        <div class="form-input-container">
          <input name="password" id="{service}-password" type="password" placeholder="Enter password" required minlength="4" maxlength="32" value="{password_value}">
        </div>
      </div>"""
    extra_group = ""
    if service == "vless":
        extra_group = f"""
      <div class="form-group">
        <label for="vless-bypass" class="form-label"><i class="fa-solid fa-shield-alt"></i> BYPASS OPTIONS</label>
        <div class="form-input-container">
          <select name="bypass_option" id="vless-bypass">
            <option value=""{" selected" if bypass_value == "" else ""}>Default</option>
            <option value="DITO_UNLI_SOCIAL"{" selected" if bypass_value == "DITO_UNLI_SOCIAL" else ""}>DITO UNLI SOCIAL | USE TLS</option>
            <option value="SMART_POWER_ALL"{" selected" if bypass_value == "SMART_POWER_ALL" else ""}>SMART POWER ALL | USE Non-TLS</option>
            <option value="GLOBE_GOSHARE"{" selected" if bypass_value == "GLOBE_GOSHARE" else ""}>GLOBE GOSHARE | USE Non-TLS</option>
          </select>
        </div>
      </div>"""
    content = f"""
<div class="container"><div class="neo-box" style="max-width:500px;margin:0 auto;text-align:center;">
  <div style="display:flex;align-items:center;justify-content:center;gap:.8em;margin-bottom:1.5em;">
    <img src="{icon}" style="height:1.8em;vertical-align:middle;margin-right:.2em;">
    <h2 class="section-title" style="margin:0;">Create {label} Account</h2>
  </div>
  <div style="font-size:1rem;color:var(--text-secondary);margin-bottom:2rem;">Create {label} account ({days} days)</div>
  {current_backend_note}
  {error_html}
  <form method="POST" action="/{service}/">
    <div class="form-group">
      <label for="{service}-username" class="form-label"><i class="fa-solid fa-user"></i> Username</label>
      <div class="form-input-container">
        <input name="username" id="{service}-username" type="text" placeholder="Enter username" required pattern="[a-zA-Z0-9_]+" maxlength="20" value="{username_value}">
      </div>
    </div>
    {password_group}
    {extra_group}
    <button type="submit" style="width:100%;max-width:400px;margin:0 auto;"><i class="fa-solid fa-user-plus"></i> Create Account</button>
  </form>
  <script>
  (function() {{
    var form = document.querySelector("form[action='/{service}/']");
    if (form) {{
      form.addEventListener('submit', function(e) {{
        if (!form.checkValidity()) return;
        e.preventDefault();
        var overlay = document.getElementById('loadingOverlay');
        if (overlay) overlay.classList.add('active');
        setTimeout(function() {{ form.submit(); }}, 1000);
      }});
    }}
  }})();
  </script>
  <a href="/services/" style="display:block;margin-top:1.5rem;text-decoration:none;">
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
    {"<div>Server:</div><div>" + html.escape(current_backend["label"]) + "</div>" if current_backend else ""}
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
        content += f"""
  <div class="info-grid"><div>Obfs:</div><div>{html.escape(str(result.get("obfs", "N/A")))}</div></div>
  <div class="link-box"><div class="link-title tls"><img src="{icon}" style="height:1.05em;"> Hysteria Link</div><div style="display:flex;align-items:center;gap:.4em;"><input type="text" readonly value="{link}"><sl-copy-button value="{link}"></sl-copy-button></div></div>"""
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
  <a href="/services/" style="display:block;margin-top:1rem;text-decoration:none;">
    <button style="width:100%;background:var(--surface);color:var(--text-primary);border:3px solid var(--card-border);box-shadow:5px 5px 0 rgba(93,9,25,.22);"><i class="fa-solid fa-arrow-left"></i> Back to Service</button>
  </a>
</div></div>"""
    return render_page(label, content)


def render_lookup_pages():
    hostname_page = """
<div class="container"><div class="neo-box" style="max-width:500px;margin:0 auto;text-align:center;">
  <div style="display:flex;align-items:center;justify-content:center;gap:.8em;margin-bottom:1.5em;"><i class="fa-solid fa-globe" style="font-size:1.8em;color:var(--accent-color);"></i><h2 class="section-title" style="margin:0;">Hostname to IP</h2></div>
  <form id="hostname-form" method="POST" action="/hostname-to-ip/" style="margin-bottom:2em;">
    <div class="form-group"><label for="hostname" class="form-label"><i class="fa-solid fa-globe"></i> Hostname</label><div class="form-input-container"><input name="hostname" id="hostname" type="text" placeholder="Enter hostname (e.g. google.com)" required maxlength="255"></div></div>
    <button type="submit" style="width:100%;max-width:400px;margin:0 auto;"><i class="fa-solid fa-magnifying-glass"></i> Check IP Address</button>
  </form><div id="hostname-result"></div>
</div></div>
<script>
document.getElementById('hostname-form').addEventListener('submit',function(e){e.preventDefault();const hostname=document.getElementById('hostname').value.trim();const resultDiv=document.getElementById('hostname-result');resultDiv.innerHTML='<div style="color:var(--text-muted);margin-top:1em;"><i class="fa-solid fa-spinner fa-spin"></i> Checking...</div>';fetch('/hostname-to-ip/',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'hostname='+encodeURIComponent(hostname)}).then(r=>r.text()).then(html=>{resultDiv.innerHTML=html;}).catch(()=>{resultDiv.innerHTML='<div style="color:var(--error);margin-top:1em;">Error checking hostname.</div>';});});
</script>"""
    ip_page = """
<div class="container"><div class="neo-box" style="max-width:600px;margin:0 auto;text-align:center;">
  <div style="display:flex;align-items:center;justify-content:center;gap:.8em;margin-bottom:1.5em;"><i class="fa-solid fa-location-dot" style="font-size:1.8em;color:var(--accent-color);"></i><h2 class="section-title" style="margin:0;">IP Lookup</h2></div>
  <form id="ip-form" method="POST" action="/ip-lookup/" style="margin-bottom:2em;">
    <div class="form-group"><label for="ip" class="form-label"><i class="fa-solid fa-network-wired"></i> IP Address</label><div class="form-input-container"><input name="ip" id="ip" type="text" placeholder="Enter IP (leave blank for your IP)" maxlength="255"></div></div>
    <button type="submit" style="width:100%;max-width:400px;margin:0 auto;"><i class="fa-solid fa-magnifying-glass"></i> Lookup</button>
  </form><div id="ip-result"></div>
</div></div>
<script>
document.getElementById('ip-form').addEventListener('submit',function(e){e.preventDefault();const ip=document.getElementById('ip').value.trim();const resultDiv=document.getElementById('ip-result');resultDiv.innerHTML='<div style="color:var(--text-muted);margin-top:1em;"><i class="fa-solid fa-spinner fa-spin"></i> Looking up...</div>';fetch('/ip-lookup/',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'ip='+encodeURIComponent(ip)}).then(r=>r.text()).then(html=>{resultDiv.innerHTML=html;}).catch(()=>{resultDiv.innerHTML='<div style="color:var(--error);margin-top:1em;">Error performing lookup.</div>';});});
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
  <a href="/main/" style="display:block;margin-top:1.2rem;text-decoration:none;"><button style="width:100%;max-width:320px;margin:.8rem auto 0;display:block;"><i class="fa-solid fa-arrow-left"></i> Back to Main</button></a>
</div></div>""",
    )


def render_readme():
    return render_page(
        "Announcement",
        f"""
<div class="container"><div class="neo-box" style="max-width:800px;margin:0 auto;">
  <div style="display:flex;align-items:center;justify-content:center;gap:.8em;margin-bottom:1.5em;"><i class="fa-solid fa-bullhorn" style="font-size:1.8em;color:var(--accent-color);"></i><h2 class="section-title" style="margin:0;">ANNOUNCEMENT!</h2></div>
  <div class="announcement-content" style="font-size:1.1em;color:var(--text-primary);padding:1em 0;">{announcement_html()}</div>
  <div style="display:flex;justify-content:center;margin-top:1.5rem;"><a href="/main/" style="text-decoration:none;display:inline-block;width:100%;"><button style="width:100%;max-width:400px;min-width:220px;font-size:1.15em;padding:16px 0;margin:0 auto;background:var(--surface);color:var(--text-primary);border:3px solid var(--card-border);border-radius:16px;font-weight:700;box-shadow:5px 5px 0 rgba(93,9,25,.22);"><i class="fa-solid fa-arrow-left"></i> Back to Main</button></a></div>
</div></div>""",
    )


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
  <form method="POST" action="/admin/"><input type="hidden" name="action" value="login">
    <div class="form-group"><label class="form-label" for="admin-username"><i class="fa-solid fa-user-shield"></i> Username</label><div class="form-input-container"><input id="admin-username" name="username" type="text" required placeholder="root"></div></div>
    <div class="form-group"><label class="form-label" for="admin-password"><i class="fa-solid fa-key"></i> Password</label><div class="form-input-container"><input id="admin-password" name="password" type="password" required placeholder="Admin password"></div></div>
    <button type="submit" style="width:100%;max-width:400px;"><i class="fa-solid fa-right-to-bracket"></i> Sign In</button>
  </form>
</div></div>""")
    expiry = get_create_account_expiry()
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
    return render_page("Admin", f"""
<div class="container" style="max-width:1120px;">
  <div class="neo-box">{banner}
    <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:16px;flex-wrap:wrap;">
      <div><h2 class="section-title" style="margin:0;">Admin Dashboard</h2><div style="color:var(--text-secondary);max-width:620px;">Serverless-safe controls for daily limits, default expiry, and audit history. Real VPN account management still needs a VPS backend.</div></div>
      <a href="/admin/logout" style="text-decoration:none;"><button style="background:var(--surface);color:var(--text-primary);border:3px solid var(--card-border);box-shadow:5px 5px 0 rgba(93,9,25,.22);"><i class="fa-solid fa-arrow-right-from-bracket"></i> Logout</button></a>
    </div>
    <div class="status-grid-2" style="margin-top:1.2rem;">
      <div class="link-box"><div style="font-weight:700;margin-bottom:.6rem;">Daily Account Limit</div><form method="POST" action="/admin/" style="margin-bottom:0;"><input type="hidden" name="action" value="update_limit"><div class="form-input-container" style="max-width:none;"><input type="number" name="limit" min="1" max="999" value="{get_daily_account_limit()}"></div><button type="submit" style="width:100%;max-width:400px;margin-top:1rem;"><i class="fa-solid fa-save"></i> Save Limit</button></form></div>
      <div class="link-box"><div style="font-weight:700;margin-bottom:.6rem;">Create Account Expiration</div><form method="POST" action="/admin/" style="margin-bottom:0;"><input type="hidden" name="action" value="update_create_expiry"><div class="form-group"><label class="form-label">Service</label><div class="form-input-container"><select name="service"><option value="ssh">SSH</option><option value="vless">VLESS</option><option value="hysteria">Hysteria</option><option value="openvpn">OpenVPN</option></select></div></div><div class="form-group"><label class="form-label">Days</label><div class="form-input-container"><input type="number" name="days" min="1" max="3650" value="{expiry.get("ssh", 5)}"></div></div><button type="submit" style="width:100%;max-width:400px;"><i class="fa-solid fa-calendar-plus"></i> Save Default</button></form></div>
    </div>
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


@app.get("/favicon.ico")
def favicon_legacy():
    return redirect("/site-icon.svg", code=302)


@app.get("/")
@app.get("/main/")
def main_page():
    return render_home()


@app.get("/service/")
@app.get("/services/")
def services_page():
    return render_services()


@app.get("/status/")
def status_page():
    return render_status()


@app.get("/status/full")
def status_full():
    response = jsonify(get_status_payload())
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    return response


@app.get("/main/stats")
def main_stats():
    visits = load_visits()
    online_users = 0
    total_accounts = max(int(visits.get("total_accounts", 0) or 0), get_total_daily_created_count())
    if backend_configured():
        try:
            data = backend_request("/status", payload=None, method="GET")
            online_users = int(data.get("online_users", 0) or 0)
        except Exception:
            pass
    response = jsonify({"online_users": online_users, "total_visits": visits.get("total_visits", 0), "total_accounts": total_accounts})
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    return response


@app.get("/chat/messages")
def chat_messages_route():
    response = jsonify({"messages": load_chat_messages()[-MAX_CHAT_MESSAGES:]})
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    return response


@app.post("/chat/send")
def chat_send_route():
    add_chat_message(request.form.get("name", ""), request.form.get("message", ""))
    return jsonify({"ok": True})


@app.get("/hostname-to-ip/")
def hostname_lookup_page():
    return render_page("Hostname to IP", hostname_page_html)


@app.post("/hostname-to-ip/")
def hostname_lookup_action():
    hostname = (request.form.get("hostname") or "").strip()
    if not hostname:
        return '<div style="color:var(--error);margin-top:1em;">Please enter a hostname.</div>'
    try:
        resolved = socket.gethostbyname(hostname)
        return f'<div style="margin-top:1em;"><div style="color:var(--success);font-weight:600;"><i class="fa-solid fa-circle-check"></i> Hostname: <span style="color:var(--accent-color);">{html.escape(hostname)}</span></div><div style="margin-top:.7em;"><span style="font-weight:600;">IP Address:</span> <span style="color:var(--primary-color);font-size:1.1em;">{html.escape(resolved)}</span></div></div>'
    except Exception:
        return f'<div style="color:var(--error);margin-top:1em;"><i class="fa-solid fa-circle-xmark"></i> Could not resolve hostname: {html.escape(hostname)}</div>'


@app.get("/ip-lookup/")
def ip_lookup_page():
    return render_page("IP Lookup", ip_page_html)


@app.post("/ip-lookup/")
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


@app.get("/donate/")
def donate_page():
    return render_donate()


@app.get("/readme/")
def readme_page():
    return render_readme()


@app.post("/select-server/")
def select_server():
    backend_id = (request.form.get("backend_id") or "").strip()
    redirect_to = (request.form.get("redirect_to") or "/services/").strip()
    if not redirect_to.startswith("/") or redirect_to.startswith("//"):
        redirect_to = "/services/"
    if set_selected_backend(backend_id):
        return redirect(redirect_to, code=303)
    return redirect("/main/?error=" + urllib.parse.quote("Invalid server selection."), code=303)


def submit_service_request(service):
    values = {key: request.form.get(key, "") for key in ("username", "password", "bypass_option")}
    if not backend_configured():
        return render_unavailable(service_label(service))
    client_ip = get_request_ip()
    cooldown_remaining = get_create_cooldown_remaining(client_ip, service)
    if cooldown_remaining > 0:
        return render_service_form(
            service,
            error=f"Please wait {format_cooldown_label(cooldown_remaining)} before creating another account.",
            values=values,
        )
    if get_daily_created_count(service) >= get_daily_account_limit():
        return render_service_form(service, error="Daily account creation limit reached for this service.", values=values)
    payload = {"username": values.get("username", "").strip(), "days": get_create_account_expiry(service)}
    if service != "vless":
        payload["password"] = values.get("password", "")
    if service == "vless":
        payload["bypass_option"] = values.get("bypass_option", "")
    try:
        data = backend_request(f"/create/{service}", payload=payload, method="POST")
        result = data.get("result", {}) if isinstance(data, dict) else {}
        set_create_cooldown(client_ip, service)
        increment_daily_created_count(service)
        increment_total_accounts()
        return render_service_result(service, result)
    except Exception as exc:
        return render_service_form(service, error=backend_error_message(exc), values=values)


@app.get("/ssh/")
def ssh_page():
    return render_service_form("ssh")


@app.post("/ssh/")
def ssh_create():
    return submit_service_request("ssh")


@app.get("/vless/")
def vless_page():
    return render_service_form("vless")


@app.post("/vless/")
def vless_create():
    return submit_service_request("vless")


@app.get("/hysteria/")
def hysteria_page():
    return render_service_form("hysteria")


@app.post("/hysteria/")
def hysteria_create():
    return submit_service_request("hysteria")


@app.get("/openvpn/")
def openvpn_page():
    return render_service_form("openvpn")


@app.post("/openvpn/")
def openvpn_create():
    return submit_service_request("openvpn")


@app.get("/admin/")
def admin_page():
    return render_admin(request.args.get("success"), request.args.get("error"))


@app.post("/admin/")
def admin_post():
    action = request.form.get("action", "")
    if action == "login":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if admin_credentials_valid(username, password):
            session["admin_authenticated"] = True
            log_admin_event("login", "success", {"username": username})
            return redirect("/admin/")
        log_admin_event("login", "failed", {"username": username})
        return render_admin(error="Invalid admin credentials.")
    if not session.get("admin_authenticated"):
        log_admin_event("unauthorized_admin_action", "failed", {"action": action})
        return redirect("/admin/")
    if action == "update_limit":
        if set_daily_account_limit(request.form.get("limit", "")):
            log_admin_event("update_limit", "success", {"limit": request.form.get("limit", "")})
            return redirect("/admin/?success=" + urllib.parse.quote("Daily account limit updated."), code=303)
        return redirect("/admin/?error=" + urllib.parse.quote("Failed to update limit."), code=303)
    if action == "update_create_expiry":
        service = request.form.get("service", "")
        days = request.form.get("days", "")
        if set_create_account_expiry(service, days):
            log_admin_event("update_create_expiry", "success", {"service": service, "days": days})
            return redirect("/admin/?success=" + urllib.parse.quote(f"New account expiration updated for {service.upper()}."), code=303)
        return redirect("/admin/?error=" + urllib.parse.quote("Failed to update new account expiration."), code=303)
    return redirect("/admin/?error=" + urllib.parse.quote("Unknown admin action."), code=303)


@app.get("/admin/logout")
def admin_logout():
    session.pop("admin_authenticated", None)
    log_admin_event("logout", "success", {})
    return redirect("/admin/")


@app.errorhandler(404)
def not_found(_error):
    return render_page("Not Found", '<div class="container"><div class="neo-box" style="max-width:500px;margin:0 auto;text-align:center;"><div style="color:var(--warning);font-size:3rem;margin-bottom:1rem;"><i class="fa-solid fa-compass-drafting"></i></div><h2 class="section-title">Page Not Found</h2><div style="margin:1.5rem 0;color:var(--text-secondary);">That route does not exist in this deployment.</div><a href="/main/" style="text-decoration:none;"><button><i class="fa-solid fa-arrow-left"></i> Back to Main</button></a></div></div>'), 404


if __name__ == "__main__":
    ensure_state_dir()
    app.run(host="0.0.0.0", port=PORT, debug=False)
