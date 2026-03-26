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
from pathlib import Path

from flask import Flask, jsonify, has_request_context, redirect, render_template_string, request, session
from markupsafe import Markup


IS_VERCEL = bool(os.environ.get("VERCEL"))
PORT = int(os.environ.get("PORT", "8000"))
STATE_DIR = Path("/tmp/webmenu_state") if IS_VERCEL else Path.cwd() / ".webmenu_state"
VISITS_FILE = STATE_DIR / "visits.json"
CONFIG_FILE = STATE_DIR / "config.json"
COUNTS_FILE = STATE_DIR / "counts.json"
CHAT_FILE = STATE_DIR / "chat.json"
AUDIT_FILE = STATE_DIR / "audit.json"
README_FILE = Path.cwd() / "README.md"

CREATE_EXPIRY_DEFAULTS = {"ssh": 5, "vless": 3, "hysteria": 5, "openvpn": 3}
DAILY_ACCOUNT_LIMIT_DEFAULT = 30
MAX_CHAT_MESSAGES = 200

SERVICE_META = [
    ("ssh", "SSH", "https://raw.githubusercontent.com/hahacrunchyrollls/logo-s/refs/heads/main/icon-ssh.png"),
    ("vless", "VLESS", "https://raw.githubusercontent.com/hahacrunchyrollls/logo-s/refs/heads/main/icon-v2ray.png"),
    ("hysteria", "HYSTERIA", "https://raw.githubusercontent.com/hahacrunchyrollls/logo-s/refs/heads/main/icon-hysteria.png"),
    ("openvpn", "OPENVPN", "https://raw.githubusercontent.com/hahacrunchyrollls/logo-s/refs/heads/main/icon-openvpn.png"),
]

state_lock = threading.Lock()
chat_lock = threading.Lock()
traffic_lock = threading.Lock()
last_traffic_snapshot = {"time": None, "rx": 0, "tx": 0}

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
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except Exception:
        return _clone(default)


def save_json(path: Path, payload):
    ensure_state_dir()
    tmp = path.with_suffix(path.suffix + ".tmp")
    try:
        with tmp.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle)
        tmp.replace(path)
        return True
    except Exception:
        try:
            if tmp.exists():
                tmp.unlink()
        except Exception:
            pass
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


def configured_server_api_url():
    return os.environ.get("SERVER_API_URL", "").strip().rstrip("/")


def configured_server_api_token():
    return os.environ.get("SERVER_API_TOKEN", "").strip()


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
        raise RuntimeError("SERVER_API_URL or SERVER_API_TOKEN is not configured.")
    body = None
    headers = {"Authorization": "Bearer " + backend.get("api_token", "")}
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


def get_daily_created_count(service=None, backend_id=None):
    data = load_counts()
    backend_id = backend_id or selected_backend_id() or "default"
    counts = data.get("counts", {}).get(backend_id, {})
    if service:
        return int(counts.get(service, 0))
    return sum(int(value) for value in counts.values())


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
        data["total_accounts"] += 1
        save_json(VISITS_FILE, data)
        return data["total_accounts"]


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
        services = payload.get("services", [])
    except Exception:
        services = []
    if not services:
        return ""
    items = []
    for entry in services:
        if not isinstance(entry, (list, tuple)) or len(entry) < 2:
            continue
        name = html.escape(str(entry[0]))
        ok = bool(entry[1])
        items.append(
            f'<div>{name}</div><div style="color:{"var(--success)" if ok else "var(--error)"};font-weight:700;">{"ONLINE" if ok else "OFFLINE"}</div>'
        )
    if not items:
        return ""
    return """
  <div class="link-box">
    <div class="link-title tls"><img src="https://raw.githubusercontent.com/hahacrunchyrollls/logo-s/refs/heads/main/icon-ssh.png" style="height:1.05em;"> Services Status</div>
    <div style="display:grid;grid-template-columns:1fr auto;gap:.7rem 1rem;">""" + "".join(items) + "</div></div>"


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


def get_status_payload():
    if backend_configured():
        try:
            data = backend_request("/status", payload=None, method="GET")
            if isinstance(data, dict) and data.get("ok") is True:
                return data
        except Exception:
            pass
    now = time.time()
    rx_total, tx_total = get_total_network_bytes()
    with traffic_lock:
        previous = dict(last_traffic_snapshot)
        if previous["time"] is None:
            rx_rate = tx_rate = 0
        else:
            delta = max(now - previous["time"], 0.001)
            rx_rate = max((rx_total - previous["rx"]) / delta, 0)
            tx_rate = max((tx_total - previous["tx"]) / delta, 0)
        last_traffic_snapshot["time"] = now
        last_traffic_snapshot["rx"] = rx_total
        last_traffic_snapshot["tx"] = tx_total
    services = [
        ["SSH", False],
        ["DNSTT", False],
        ["SQUID", False],
        ["WEBSOCKET", False],
        ["SSL", False],
        ["XRAY", False],
        ["BADVPN-UDPGW", False],
        ["HYSTERIA-SERVER", False],
        ["MULTIPLEXER", False],
        ["OPENVPN", False],
    ]
    return {
        "cpu": get_cpu_percent(),
        "load": get_load_average(),
        "mem": get_memory_stats(),
        "storage": get_storage_stats(),
        "net": {"rx_bytes": rx_total, "tx_bytes": tx_total, "rx_rate": rx_rate, "tx_rate": tx_rate},
        "services": services,
    }


BASE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
<title>{{ title }}</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="icon" type="image/png" href="https://raw.githubusercontent.com/hahacrunchyrollls/logo-s/refs/heads/main/icon_fuji.png">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@shoelace-style/shoelace@2.13.0/cdn/themes/light.css" />
<script type="module" src="https://cdn.jsdelivr.net/npm/@shoelace-style/shoelace@2.13.0/cdn/shoelace.js"></script>
<style>
:root{--primary-color:#00aaff;--primary-hover:#33bbff;--accent-color:#06b6d4;--accent-hover:#22d3ee;--bg-gradient:linear-gradient(135deg,#0f172a 0%,#1e293b 50%,#0f172a 100%);--card-bg:linear-gradient(145deg,#1e1e2e 0%,#1a1b26 100%);--card-border:#2f3255;--card-shadow:0 10px 30px rgba(0,0,0,.5);--success:#22c55e;--error:#ef4444;--warning:#f59e0b;--text-primary:#f8fafc;--text-secondary:#cbd5e1;--text-muted:#94a3b8;--border-radius:16px;--transition:all .25s ease;}
body{background:var(--bg-gradient);color:var(--text-primary);font-family:'Segoe UI',system-ui,-apple-system,sans-serif;margin:0;min-height:100vh;line-height:1.6;overflow-x:hidden;position:relative;}
body::before{content:"";position:fixed;inset:0;z-index:-1;background:radial-gradient(ellipse at 20% 20%,rgba(0,170,255,.05),transparent 60%),radial-gradient(ellipse at 80% 80%,rgba(34,197,94,.03),transparent 60%);}
button{background:linear-gradient(145deg,var(--primary-color) 0%,var(--accent-color) 100%);color:#fff;border:none;border-radius:var(--border-radius);font-weight:600;font-size:1rem;padding:14px 28px;cursor:pointer;transition:var(--transition);display:inline-flex;align-items:center;justify-content:center;gap:8px;}
button:hover,button:focus{transform:translateY(-1px);box-shadow:0 6px 16px rgba(0,170,255,.25);background:linear-gradient(145deg,var(--primary-hover) 0%,var(--accent-hover) 100%);outline:none;}
.container{width:95%;max-width:650px;margin:2rem auto;padding:0 1rem;}
.neo-box{background:var(--card-bg);border-radius:var(--border-radius);box-shadow:var(--card-shadow);padding:1.8rem 1.5rem;margin-bottom:2rem;border:1px solid var(--card-border);backdrop-filter:blur(10px);}
.section-title{font-size:2rem;font-weight:700;margin-bottom:1rem;background:linear-gradient(to right,var(--text-primary),var(--text-secondary));-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent;}
.success-msg{display:flex;align-items:center;background:rgba(34,197,94,.1);border-left:5px solid var(--success);border-radius:var(--border-radius);padding:1rem;margin-bottom:1.5rem;font-weight:500;font-size:1.05em;}
.info-grid,.status-grid-2,.services-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px;}
.info-grid{gap:.8rem 1.2rem;font-family:ui-monospace,'Cascadia Code','SF Mono',monospace;background:rgba(15,23,42,.6);border-radius:var(--border-radius);padding:1.2rem;margin-bottom:1.5rem;border:1px solid var(--card-border);}
.info-grid div:nth-child(2n){font-weight:600;color:var(--accent-color);word-break:break-all;}
.link-box,.status-card,.service-item{background:rgba(15,23,42,.6);border-radius:var(--border-radius);padding:1rem;border:1px solid var(--card-border);}
.link-title{font-weight:600;margin-bottom:.8rem;display:flex;align-items:center;gap:8px}.link-title.tls{color:var(--success)}
input[type="text"],input[type="password"],input[type="search"],input[type="number"],select{background:rgba(15,23,42,.6);border:1px solid var(--card-border);border-radius:var(--border-radius);color:var(--text-primary);font-size:.95rem;padding:12px 16px;width:100%;box-sizing:border-box;max-width:400px;display:block;outline:none;}
.form-group{margin-bottom:1.8rem;text-align:center;width:100%;display:flex;flex-direction:column;align-items:center;}
.form-label{display:block;font-weight:600;margin-bottom:.8rem;width:100%;max-width:400px;text-align:center;}
.form-input-container{width:100%;display:flex;justify-content:center;max-width:400px;}
form{display:flex;flex-direction:column;align-items:center;width:100%;margin-bottom:1.5rem;}
.navbar{width:100%;background:rgba(15,23,42,.9);backdrop-filter:blur(10px);border-bottom:1px solid var(--card-border);display:flex;align-items:center;justify-content:space-between;padding:1rem max(1.5rem,5%);position:sticky;top:0;z-index:100;box-sizing:border-box;}
.navbar-brand{display:flex;align-items:center;gap:10px;font-weight:700;font-size:clamp(.95rem,3vw,1.4rem);color:var(--text-primary);text-decoration:none;line-height:1.1;}
.navbar-nav{display:flex;align-items:center;gap:10px;margin-left:auto;}
.nav-link{color:var(--text-secondary);text-decoration:none;font-weight:500;padding:8px 16px;border-radius:var(--border-radius);transition:var(--transition);font-size:.95rem;}
.nav-link:hover,.nav-link.active{color:var(--text-primary);background:rgba(255,255,255,.1);}
.burger-btn{display:none;background:transparent;border:1px solid rgba(255,255,255,.06);color:var(--text-secondary);padding:0;border-radius:10px;height:44px;width:44px;}
.mobile-menu{display:none;position:absolute;top:calc(100% + 8px);right:12px;min-width:220px;max-width:92vw;background:rgba(15,23,42,.98);border:1px solid var(--card-border);border-radius:12px;box-shadow:0 12px 40px rgba(0,0,0,.6);padding:8px;z-index:1000;flex-direction:column;gap:6px;}
.mobile-menu a{display:block;text-decoration:none;color:var(--text-primary);padding:10px 12px;border-radius:8px;font-weight:600;}
.mobile-menu a:hover{background:rgba(255,255,255,.03);color:var(--accent-color);}
.status-label{color:var(--text-muted);font-size:.9rem;display:flex;align-items:center;gap:6px;}.status-value{font-size:1.2rem;font-weight:600}
.status-subtitle{font-size:1rem;font-weight:600;margin:1.2rem 0 .8rem 0;color:var(--text-secondary);display:flex;align-items:center;gap:8px;}
.stats-container{display:flex;justify-content:center;gap:1rem;margin:1.5rem 0;flex-wrap:wrap;}
.stat-item{background:rgba(15,23,42,.5);border-radius:var(--border-radius);padding:.8rem 1.5rem;display:flex;align-items:center;gap:10px;border:1px solid var(--card-border);flex:1;min-width:200px;max-width:300px;}
.stat-icon{color:var(--accent-color);font-size:1.2rem}.stat-value{font-weight:600;font-size:1.1rem}.stat-label{font-size:.9rem;color:var(--text-secondary)}
.public-chat{margin-top:1.5rem;display:flex;flex-direction:column;gap:8px;align-items:center}.chat-box{width:100%;max-width:400px;background:rgba(15,23,42,.6);border-radius:12px;padding:10px;border:1px solid var(--card-border);max-height:320px;overflow:auto;font-size:.98rem}.chat-message{padding:6px;border-radius:8px;margin-bottom:6px;background:rgba(255,255,255,.02);display:block}.chat-meta{display:flex;align-items:center;gap:8px}.chat-name{font-weight:700;color:var(--accent-color)}.chat-time{color:var(--text-muted);font-size:.8rem;margin-left:auto}.chat-text{margin-top:6px;white-space:pre-wrap;overflow-wrap:anywhere;word-break:break-word}.chat-form{width:100%;max-width:400px;display:flex;gap:8px;align-items:center;flex-direction:column}.chat-form input[type="text"]{width:100%}
.loading-overlay{display:none;position:fixed;inset:0;z-index:9999;background:rgba(15,23,42,.88);backdrop-filter:blur(6px);justify-content:center;align-items:center;flex-direction:column;gap:1.5rem}.loading-overlay.active{display:flex}.loading-spinner{width:56px;height:56px;border:3px solid rgba(255,255,255,.08);border-top-color:var(--primary-color);border-radius:50%;animation:spin .7s linear infinite}.loading-text{font-weight:600}
@keyframes spin{to{transform:rotate(360deg);}}
@media (max-width:880px){.navbar-nav{display:none}.burger-btn{display:inline-flex;align-items:center;justify-content:center;}.navbar{padding:.6rem .8rem}}
@media (max-width:576px){.container{width:95%;padding:0}.neo-box{padding:1.2rem 1rem}.info-grid,.status-grid-2,.services-grid{grid-template-columns:1fr}.stats-container{flex-direction:column;align-items:center}}
</style>
</head>
<body>
<div class="loading-overlay" id="loadingOverlay"><div class="loading-spinner"></div><div class="loading-text">Creating your account...</div></div>
{{ navbar|safe }}
{{ content|safe }}
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
    <img src="https://raw.githubusercontent.com/hahacrunchyrollls/logo-s/refs/heads/main/icon_fuji.png" alt="FUJI PANEL" style="height:2.1em;">
    <span>FUJI PANEL</span>
    <span style="display:inline-flex;align-items:center;font-size:.78rem;font-weight:700;color:var(--text-secondary);margin-left:.55rem;padding:.18rem .45rem;background:rgba(255,255,255,.02);border-radius:8px;border:1px solid rgba(255,255,255,.03);white-space:nowrap;">IP: {visitor_ip}</span>
  </a>
  <div class="navbar-nav">
    <a href="/main/" class="nav-link"><i class="fa-solid fa-house"></i> Home</a>
    <a href="/status/" class="nav-link"><i class="fa-solid fa-server"></i> Status</a>
    <a href="/hostname-to-ip/" class="nav-link"><i class="fa-solid fa-globe"></i> Hostname to IP</a>
    <a href="/ip-lookup/" class="nav-link"><i class="fa-solid fa-location-dot"></i> IP Lookup</a>
    {announcement_link}
    <a href="/donate/" class="nav-link"><i class="fa-solid fa-donate"></i> Donate</a>
  </div>
  <button class="burger-btn" id="navbar-burger" type="button"><i class="fa-solid fa-bars"></i></button>
  <div class="mobile-menu" id="mobile-menu">
    <a href="/main/"><i class="fa-solid fa-house"></i> Home</a>
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


def render_home():
    visits = bump_visit_count()
    cards = []
    daily_limit = get_daily_account_limit()
    enabled = backend_configured()
    backends = load_backends()
    current_backend = selected_backend()
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
      <div><span style="background:rgba(255,255,255,.04);padding:4px 8px;border-radius:10px;font-weight:700;color:#fff;">{created}/{daily_limit}</span></div>
    </button>
  </a>
</div>"""
        )
    location_html = ""
    try:
        data = backend_location(current_backend)
        country = data.get("country", "Unknown")
        code = data.get("countryCode", "")
        city = data.get("city", "")
        if country != "Unknown":
            flag = f'https://flagcdn.com/48x36/{code.lower()}.png' if code else ""
            location_html = f"""
<div style="text-align:center;margin-bottom:1.2em;">
  {'<img src="' + flag + '" alt="' + html.escape(code) + ' flag" style="height:2.2em;vertical-align:middle;border-radius:6px;border:1px solid #222;margin-bottom:0.5em;margin-top:1em;">' if flag else ''}
  <div style="font-size:1.1em;color:var(--text-secondary);font-weight:600;margin-top:0.5em;">{html.escape(country)}{', ' + html.escape(city) if city else ''}</div>
</div>"""
    except Exception:
        pass
    selector_html = ""
    if len(backends) > 1:
        options = []
        current_id = selected_backend_id()
        for backend in backends:
            selected_attr = " selected" if backend["id"] == current_id else ""
            options.append(f'<option value="{html.escape(backend["id"])}"{selected_attr}>{html.escape(backend["label"])}</option>')
        selector_html = f"""
    <div class="link-box" style="max-width:520px;margin:0 auto 1.25rem auto;">
      <form method="POST" action="/select-server/" style="margin-bottom:0;">
        <div class="form-group" style="margin-bottom:1rem;">
          <label class="form-label"><i class="fa-solid fa-earth-asia"></i> Choose Country / Server</label>
          <div class="form-input-container" style="max-width:none;">
            <select name="backend_id" onchange="this.form.submit()">{''.join(options)}</select>
          </div>
        </div>
      </form>
    </div>"""
    current_server_note = ""
    if current_backend:
        current_server_note = f'<div style="color:var(--text-secondary);font-size:.95rem;margin-top:.2rem;">Selected server: <strong style="color:var(--text-primary);">{html.escape(current_backend["label"])}</strong></div>'
    page_error = (request.args.get("error", "") if has_request_context() else "").strip()
    return render_page(
        "FUJI PANEL",
        render_template_string(
            """
{{ location_html|safe }}
<div class="container">
  <div class="neo-box" style="text-align:center;">
    <div style="display:flex;align-items:center;justify-content:center;gap:.8em;margin-bottom:1.5em;">
      <i class="fa-solid fa-user-plus" style="font-size:1.8em;color:var(--accent-color);"></i>
      <h2 class="section-title" style="margin:0;">CREATE ACCOUNT</h2>
    </div>
    <style>.create-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px;margin:0 auto;max-width:640px}.create-cell a{text-decoration:none;display:block}@media (max-width:480px){.create-grid{grid-template-columns:1fr}}</style>
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
      <div>Set <code>SERVER_API_URL</code> and <code>SERVER_API_TOKEN</code> in Vercel to enable account creation.</div>
    </div>
    {% endif %}
    <div style="margin:2rem 0;"><div class="create-grid">{{ cards|safe }}</div></div>
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
            location_html=Markup(location_html),
            cards=Markup("".join(cards)),
            visits=visits["total_visits"],
            selector_html=Markup(selector_html),
            current_server_note=Markup(current_server_note),
            page_error=page_error,
            backend_ready=enabled,
        ),
    )


def render_status():
    return render_page(
        "Server Status",
        """
<div class="container"><div class="neo-box">
  <div style="display:flex;align-items:center;justify-content:center;gap:.8em;margin-bottom:1.5em;"><i class="fa-solid fa-server" style="font-size:1.8em;color:var(--accent-color);"></i><h2 class="section-title" style="margin:0;">Server Status</h2></div>
  <div class="status-subtitle"><i class="fa-solid fa-network-wired"></i> Network Traffic</div><div class="status-grid-2" id="network-grid"></div>
  <div class="status-subtitle"><i class="fa-solid fa-microchip"></i> System Resources</div><div class="status-grid-2" id="status-grid"></div>
  <div class="status-subtitle"><i class="fa-solid fa-plug"></i> Services</div><div class="services-grid" id="services-container"></div>
</div></div>
<script>
function formatSpeed(v){if(v>1024*1024)return (v/1024/1024).toFixed(2)+' MB/s';if(v>1024)return (v/1024).toFixed(2)+' KB/s';return v.toFixed(0)+' B/s';}
function formatBytes(v){if(v>1024*1024*1024)return (v/1024/1024/1024).toFixed(2)+' GB';if(v>1024*1024)return (v/1024/1024).toFixed(2)+' MB';if(v>1024)return (v/1024).toFixed(2)+' KB';return v.toFixed(0)+' B';}
function updateStatus(){fetch('/status/full?t='+Date.now()).then(r=>r.json()).then(data=>{document.getElementById('network-grid').innerHTML=`<div class="status-card"><div class="status-label"><i class="fa-solid fa-arrow-down" style="color:var(--success)"></i> Download Speed</div><div class="status-value">${formatSpeed(data.net.rx_rate)}</div></div><div class="status-card"><div class="status-label"><i class="fa-solid fa-arrow-up" style="color:var(--accent-color)"></i> Upload Speed</div><div class="status-value">${formatSpeed(data.net.tx_rate)}</div></div><div class="status-card"><div class="status-label"><i class="fa-solid fa-database" style="color:var(--success)"></i> Total Downloaded</div><div class="status-value">${formatBytes(data.net.rx_bytes)}</div></div><div class="status-card"><div class="status-label"><i class="fa-solid fa-database" style="color:var(--accent-color)"></i> Total Uploaded</div><div class="status-value">${formatBytes(data.net.tx_bytes)}</div></div>`;document.getElementById('status-grid').innerHTML=`<div class="status-card"><div class="status-label"><i class="fa-solid fa-microchip" style="color:var(--primary-color)"></i> CPU Usage</div><div class="status-value">${data.cpu}%</div></div><div class="status-card"><div class="status-label"><i class="fa-solid fa-chart-line" style="color:var(--accent-color)"></i> Load Average</div><div class="status-value">${data.load.join(', ')}</div></div><div class="status-card"><div class="status-label"><i class="fa-solid fa-memory" style="color:var(--success)"></i> Memory Used</div><div class="status-value">${data.mem.used} / ${data.mem.total} MB</div></div><div class="status-card"><div class="status-label"><i class="fa-solid fa-memory" style="color:var(--primary-color)"></i> Memory Available</div><div class="status-value">${data.mem.available} MB</div></div><div class="status-card"><div class="status-label"><i class="fa-solid fa-hdd" style="color:var(--accent-color)"></i> Storage Used</div><div class="status-value">${data.storage.used} / ${data.storage.total} MB</div></div><div class="status-card"><div class="status-label"><i class="fa-solid fa-hdd" style="color:var(--success)"></i> Storage Free</div><div class="status-value">${data.storage.free} MB</div></div>`;let s='';data.services.forEach(x=>{const icon=x[1]?'<i class="fa-solid fa-circle-check" style="color:var(--success)"></i>':'<i class="fa-solid fa-circle-xmark" style="color:var(--error)"></i>';s+=`<div class="service-item"><div>${icon} ${x[0]}</div></div>`;});document.getElementById('services-container').innerHTML=s;}).catch(()=>{});}
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
    current_backend = selected_backend()
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
  {f'<div style="color:var(--text-secondary);font-size:.95rem;margin:-1rem 0 1.4rem 0;">Selected server: <strong style="color:var(--text-primary);">{html.escape(current_backend["label"])}</strong> <a href="/main/" style="color:var(--accent-color);text-decoration:none;">Change</a></div>' if current_backend else ''}
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
  <a href="/main/" style="display:block;margin-top:1.5rem;text-decoration:none;">
    <button style="width:100%;max-width:400px;margin:0 auto;background:rgba(15,23,42,.6);border:1px solid var(--card-border);"><i class="fa-solid fa-arrow-left"></i> Back to Main</button>
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
  <a href="/main/" style="display:block;margin-top:1rem;text-decoration:none;">
    <button style="width:100%;background:rgba(15,23,42,.6);border:1px solid var(--card-border);"><i class="fa-solid fa-arrow-left"></i> Back to Main</button>
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
  <div style="display:flex;align-items:center;justify-content:center;gap:.8em;margin-bottom:1rem;"><i class="fa-solid fa-donate" style="font-size:1.6em;color:#fff;"></i><h2 class="section-title" style="margin:0;">Gcash Donation</h2></div>
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
  <div style="display:flex;justify-content:center;margin-top:1.5rem;"><a href="/main/" style="text-decoration:none;display:inline-block;width:100%;"><button style="width:100%;max-width:400px;min-width:220px;font-size:1.15em;padding:16px 0;margin:0 auto;background:rgba(15,23,42,.6);border:2px solid var(--card-border);border-radius:16px;font-weight:700;"><i class="fa-solid fa-arrow-left"></i> Back to Main</button></a></div>
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
      <a href="/admin/logout" style="text-decoration:none;"><button style="background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.16);"><i class="fa-solid fa-arrow-right-from-bracket"></i> Logout</button></a>
    </div>
    <div class="status-grid-2" style="margin-top:1.2rem;">
      <div class="link-box"><div style="font-weight:700;margin-bottom:.6rem;">Daily Account Limit</div><form method="POST" action="/admin/" style="margin-bottom:0;"><input type="hidden" name="action" value="update_limit"><div class="form-input-container" style="max-width:none;"><input type="number" name="limit" min="1" max="999" value="{get_daily_account_limit()}"></div><button type="submit" style="width:100%;max-width:400px;margin-top:1rem;"><i class="fa-solid fa-save"></i> Save Limit</button></form></div>
      <div class="link-box"><div style="font-weight:700;margin-bottom:.6rem;">Create Account Expiration</div><form method="POST" action="/admin/" style="margin-bottom:0;"><input type="hidden" name="action" value="update_create_expiry"><div class="form-group"><label class="form-label">Service</label><div class="form-input-container"><select name="service"><option value="ssh">SSH</option><option value="vless">VLESS</option><option value="hysteria">Hysteria</option><option value="openvpn">OpenVPN</option></select></div></div><div class="form-group"><label class="form-label">Days</label><div class="form-input-container"><input type="number" name="days" min="1" max="3650" value="{expiry.get("ssh", 5)}"></div></div><button type="submit" style="width:100%;max-width:400px;"><i class="fa-solid fa-calendar-plus"></i> Save Default</button></form></div>
    </div>
    <div style="margin-top:1.2rem;"><div style="font-weight:700;margin-bottom:.8rem;">Recent Audit</div>{event_cards}</div>
  </div>
</div>""")


hostname_page_html, ip_page_html = render_lookup_pages()


@app.get("/")
@app.get("/main/")
def main_page():
    return render_home()


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
    total_accounts = visits.get("total_accounts", 0)
    if backend_configured():
        try:
            data = backend_request("/status", payload=None, method="GET")
            online_users = int(data.get("online_users", 0) or 0)
            total_accounts = int(data.get("total_accounts", total_accounts) or total_accounts)
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
    if set_selected_backend(backend_id):
        return redirect("/main/", code=303)
    return redirect("/main/?error=" + urllib.parse.quote("Invalid server selection."), code=303)


def submit_service_request(service):
    values = {key: request.form.get(key, "") for key in ("username", "password", "bypass_option")}
    if not backend_configured():
        return render_unavailable(service_label(service))
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
