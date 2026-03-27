import errno, http.server, socketserver, urllib.parse, urllib.request, subprocess, os, time, re, html, json, uuid, threading, logging, secrets, http.cookies
from datetime import datetime, timedelta
logging.basicConfig(level=logging.ERROR)
# --- Add global for traffic snapshot ---
traffic_lock = threading.Lock()
last_traffic_snapshot = {
    'time': None,
    'rx': 0,
    'tx': 0
}
# --- Add global visit count ---
visit_count = 0
user_lock = threading.Lock()
# --- Public chat in-memory store ---
chat_lock = threading.Lock()
chat_messages = []
MAX_CHAT_MESSAGES = 200
PORT = 8000

# Daily account creation limit (resets by Philippine date)
DAILY_ACCOUNT_LIMIT_DEFAULT = 30
DAILY_ACCOUNT_LIMIT = DAILY_ACCOUNT_LIMIT_DEFAULT  # will be overridden by on-disk config if present
DAILY_ACCOUNT_FILE = "/etc/fuji_daily_created.json"
DAILY_LIMIT_FILE = "/etc/fuji_daily_limit.json"
CREATE_EXPIRY_FILE = "/etc/fuji_create_expiry.json"
ADMIN_AUDIT_FILE = "/etc/fuji_admin_audit.jsonl"
CREATE_EXPIRY_DEFAULTS = {
    "ssh": 5,
    "vless": 3,
    "hysteria": 5,
    "openvpn": 3,
}
daily_count_lock = threading.Lock()
daily_limit_lock = threading.Lock()
create_expiry_lock = threading.Lock()
admin_audit_lock = threading.Lock()

def _philippine_date_str():
  # Philippine time is UTC+8; use UTC + 8 hours to avoid tz dependency
  return (datetime.utcnow() + timedelta(hours=8)).strftime("%Y-%m-%d")

def _normalize_daily_count_scope(value):
  value = str(value or '').strip().lower()
  if not value:
    return ''
  value = re.sub(r'[^a-z0-9._:-]+', '-', value)
  return value.strip('-')

def _daily_count_scope_key():
  candidates = [
    os.environ.get('FUJI_DAILY_SCOPE'),
    os.environ.get('FUJI_SERVER_SCOPE'),
    get_domain(),
    os.environ.get('HOSTNAME'),
    os.environ.get('COMPUTERNAME'),
  ]
  for candidate in candidates:
    scope = _normalize_daily_count_scope(candidate)
    if scope:
      return scope
  return 'default'

def _normalize_daily_service_counts(raw_counts):
  if not isinstance(raw_counts, dict):
    return {}
  counts = {}
  for raw_service, raw_count in raw_counts.items():
    service = str(raw_service or '').strip().lower()
    if not service:
      continue
    try:
      count = int(raw_count)
    except Exception:
      count = 0
    if count > 0:
      counts[service] = count
  return counts

def _aggregate_daily_scope_counts(scopes):
  totals = {}
  if not isinstance(scopes, dict):
    return totals
  for raw_counts in scopes.values():
    counts = _normalize_daily_service_counts(raw_counts)
    for service, count in counts.items():
      totals[service] = totals.get(service, 0) + count
  return totals

def _load_daily_count_data_unlocked():
  today = _philippine_date_str()
  data = {'date': today, 'scopes': {}, 'counts': {}}
  if not os.path.exists(DAILY_ACCOUNT_FILE):
    return data
  try:
    with open(DAILY_ACCOUNT_FILE, 'r') as f:
      stored = json.load(f)
  except Exception:
    return data
  if stored.get('date') != today:
    return data

  scopes = {}
  raw_scopes = stored.get('scopes', {})
  if isinstance(raw_scopes, dict):
    for raw_scope, raw_counts in raw_scopes.items():
      scope = _normalize_daily_count_scope(raw_scope)
      if not scope:
        continue
      counts = _normalize_daily_service_counts(raw_counts)
      if counts:
        scopes[scope] = counts

  data['scopes'] = scopes
  data['counts'] = _aggregate_daily_scope_counts(scopes)
  return data

def get_daily_created_count(service=None):
  """Return the daily created count for the current server scope.
  If service is None, return the total across services for this server."""
  try:
    with daily_count_lock:
      data = _load_daily_count_data_unlocked()
      scope_counts = _normalize_daily_service_counts(
        data.get('scopes', {}).get(_daily_count_scope_key(), {})
      )
      if service:
        return int(scope_counts.get(str(service or '').strip().lower(), 0))
      return sum(int(v) for v in scope_counts.values())
  except Exception:
    return 0

def increment_daily_created_count(service):
  """Increment the daily created count for a specific service on the current server."""
  try:
    with daily_count_lock:
      service = str(service or '').strip().lower()
      if not service:
        return None
      data = _load_daily_count_data_unlocked()
      scope = _daily_count_scope_key()
      scope_counts = _normalize_daily_service_counts(data['scopes'].get(scope, {}))
      scope_counts[service] = int(scope_counts.get(service, 0)) + 1
      data['scopes'][scope] = scope_counts
      data['counts'] = _aggregate_daily_scope_counts(data['scopes'])
      tmp = DAILY_ACCOUNT_FILE + '.tmp'
      with open(tmp, 'w') as f:
        json.dump(data, f)
      try:
        os.replace(tmp, DAILY_ACCOUNT_FILE)
      except Exception:
        try:
          os.remove(DAILY_ACCOUNT_FILE)
        except Exception:
          pass
        os.rename(tmp, DAILY_ACCOUNT_FILE)
      return scope_counts[service]
  except Exception:
    return None

# --- Daily limit helpers (persistent across restarts) ---
def _load_daily_limit_unlocked():
  try:
    if os.path.exists(DAILY_LIMIT_FILE):
      with open(DAILY_LIMIT_FILE, 'r') as f:
        data = json.load(f)
      limit = int(data.get('limit', DAILY_ACCOUNT_LIMIT_DEFAULT))
      if limit < 1:
        limit = DAILY_ACCOUNT_LIMIT_DEFAULT
      return limit
  except Exception:
    pass
  return DAILY_ACCOUNT_LIMIT_DEFAULT

def get_daily_account_limit():
  """Return the configured daily limit (persisted on disk)."""
  global DAILY_ACCOUNT_LIMIT
  with daily_limit_lock:
    DAILY_ACCOUNT_LIMIT = _load_daily_limit_unlocked()
    return DAILY_ACCOUNT_LIMIT

def set_daily_account_limit(new_limit):
  """Persist and cache a new daily limit (min 1, max 999)."""
  global DAILY_ACCOUNT_LIMIT
  try:
    val = int(new_limit)
    if val < 1:
      val = 1
    if val > 999:
      val = 999
  except Exception:
    return False
  try:
    with daily_limit_lock:
      DAILY_ACCOUNT_LIMIT = val
      tmp = DAILY_LIMIT_FILE + ".tmp"
      with open(tmp, 'w') as f:
        json.dump({"limit": val}, f)
      os.replace(tmp, DAILY_LIMIT_FILE)
    return True
  except Exception:
    return False

def _load_create_expiry_unlocked():
  data = dict(CREATE_EXPIRY_DEFAULTS)
  try:
    if os.path.exists(CREATE_EXPIRY_FILE):
      with open(CREATE_EXPIRY_FILE, 'r') as f:
        stored = json.load(f)
      if isinstance(stored, dict):
        for service, default_days in CREATE_EXPIRY_DEFAULTS.items():
          try:
            days = int(stored.get(service, default_days))
          except Exception:
            days = default_days
          if days < 1:
            days = default_days
          if days > 3650:
            days = 3650
          data[service] = days
  except Exception:
    pass
  return data

def get_create_account_expiry(service=None):
  with create_expiry_lock:
    data = _load_create_expiry_unlocked()
  if service:
    return int(data.get(service, CREATE_EXPIRY_DEFAULTS.get(service, 3)))
  return data

def set_create_account_expiry(service, days):
  if service not in CREATE_EXPIRY_DEFAULTS:
    return False
  try:
    value = int(days)
  except Exception:
    return False
  if value < 1:
    value = 1
  if value > 3650:
    value = 3650
  try:
    with create_expiry_lock:
      data = _load_create_expiry_unlocked()
      data[service] = value
      tmp = CREATE_EXPIRY_FILE + ".tmp"
      with open(tmp, 'w') as f:
        json.dump(data, f)
      os.replace(tmp, CREATE_EXPIRY_FILE)
    return True
  except Exception:
    return False

def format_days_label(days):
  try:
    value = int(days)
  except Exception:
    value = 0
  return f"{value} day" if value == 1 else f"{value} days"

# --- Admin session/auth helpers ---
ADMIN_SESSION_DURATION = 3600  # seconds
admin_sessions = {}
admin_session_lock = threading.Lock()

def _get_cookie_value(headers, name):
  cookie_header = headers.get('Cookie')
  if not cookie_header:
    return None
  try:
    c = http.cookies.SimpleCookie()
    c.load(cookie_header)
    if name in c:
      return c[name].value
  except Exception:
    return None
  return None

def create_admin_session():
  token = secrets.token_hex(24)
  with admin_session_lock:
    admin_sessions[token] = time.time() + ADMIN_SESSION_DURATION
  return token

def is_admin_authenticated(handler):
  token = _get_cookie_value(handler.headers, 'admin_token')
  if not token:
    return False
  with admin_session_lock:
    expiry = admin_sessions.get(token)
    if expiry and expiry > time.time():
      admin_sessions[token] = time.time() + ADMIN_SESSION_DURATION  # sliding window
      return True
    if token in admin_sessions:
      admin_sessions.pop(token, None)
  return False

def clear_admin_session(token):
  with admin_session_lock:
    admin_sessions.pop(token, None)

def get_request_ip(handler):
  xff = handler.headers.get('X-Forwarded-For') or handler.headers.get('X-Real-IP') or ''
  if xff:
    return xff.split(',')[0].strip()
  return handler.client_address[0]

def log_admin_event(action, status="success", actor="root", ip=None, details=None):
  event = {
    "ts": int(time.time()),
    "time": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
    "action": str(action or "unknown"),
    "status": str(status or "info"),
    "actor": str(actor or "root"),
    "ip": str(ip or "-"),
    "details": details if isinstance(details, dict) else {},
  }
  try:
    with admin_audit_lock:
      with open(ADMIN_AUDIT_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(event, separators=(",", ":")) + "\n")
  except Exception:
    pass

def get_recent_admin_events(limit=12):
  events = []
  try:
    with admin_audit_lock:
      if not os.path.exists(ADMIN_AUDIT_FILE):
        return events
      with open(ADMIN_AUDIT_FILE, "r", encoding="utf-8") as f:
        lines = f.readlines()
    for raw in reversed(lines[-max(int(limit), 1) * 4:]):
      raw = raw.strip()
      if not raw:
        continue
      try:
        event = json.loads(raw)
      except Exception:
        continue
      events.append({
        "time": str(event.get("time", "-")),
        "action": str(event.get("action", "unknown")),
        "status": str(event.get("status", "info")),
        "actor": str(event.get("actor", "root")),
        "ip": str(event.get("ip", "-")),
        "details": event.get("details", {}) if isinstance(event.get("details"), dict) else {},
      })
      if len(events) >= limit:
        break
  except Exception:
    return []
  return events

def build_admin_usage_metrics(accounts, limit_val):
  now_ts = int(time.time())
  service_keys = ("ssh", "vless", "hysteria", "openvpn")
  service_counts = {key: 0 for key in service_keys}
  created_today = {key: int(get_daily_created_count(key)) for key in service_keys}
  metrics = {
    "total": len(accounts),
    "active": 0,
    "expired": 0,
    "never": 0,
    "expiring_soon": 0,
    "service_counts": service_counts,
    "created_today": created_today,
    "remaining_today": 0,
  }
  for acct in accounts:
    service = acct.get("service")
    expiry = int(acct.get("expiry", 0) or 0)
    if service in service_counts:
      service_counts[service] += 1
    if expiry <= 0:
      metrics["active"] += 1
      metrics["never"] += 1
      continue
    if expiry <= now_ts:
      metrics["expired"] += 1
      continue
    metrics["active"] += 1
    if expiry - now_ts <= 3 * 86400:
      metrics["expiring_soon"] += 1
  metrics["remaining_today"] = sum(max(int(limit_val) - created_today[key], 0) for key in service_keys)
  return metrics

def verify_root_credentials(username, password):
  """Validate against system root password. Falls back to sudo if /etc/shadow is unreadable."""
  if username != "root" or not password:
    return False
  try:
    import crypt
    root_hash = None
    with open('/etc/shadow', 'r') as f:
      for line in f:
        if line.startswith('root:'):
          parts = line.split(':')
          if len(parts) > 1:
            root_hash = parts[1]
          break
    if root_hash and root_hash not in ("*", "!", ""):
      if crypt.crypt(password, root_hash) == root_hash:
        return True
  except PermissionError:
    # Not running as root – fall through to sudo check
    pass
  except Exception:
    pass
  # Fallback: sudo password check
  try:
    proc = subprocess.run(
      ['sudo', '-S', '-k', 'true'],
      input=(password + "\n").encode(),
      stdout=subprocess.DEVNULL,
      stderr=subprocess.DEVNULL,
      timeout=5
    )
    return proc.returncode == 0
  except Exception:
    return False

# Prime limit cache at startup
DAILY_ACCOUNT_LIMIT = get_daily_account_limit()
HTML_HEADER = """<!DOCTYPE html>
<html>
<head>
<title>FUJI PANEL</title>
<meta name='viewport' content='width=device-width, initial-scale=1'>
<link rel="icon" type="image/png" href="https://raw.githubusercontent.com/hahacrunchyrollls/logo-s/refs/heads/main/icon_fuji.png">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@shoelace-style/shoelace@2.13.0/cdn/themes/light.css" />
<script type="module" src="https://cdn.jsdelivr.net/npm/@shoelace-style/shoelace@2.13.0/cdn/shoelace.js"></script>
<!-- Chart.js CDN -->
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
:root {
    --primary-color: #00aaff; /* Enhanced blue */
    --primary-hover: #33bbff;
    --accent-color: #06b6d4;
    --accent-hover: #22d3ee;
    --secondary-accent: #8b5cf6; /* New purple accent */
    --bg-gradient: linear-gradient(135deg, #0f172a 0%, #1e293b 50%, #0f172a 100%);
    --card-bg: linear-gradient(145deg, #1e1e2e 0%, #1a1b26 100%);
    --card-border: #2f3255;
    --card-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
    --success: #22c55e;
    --error: #ef4444;
    --warning: #f59e0b;
    --text-primary: #f8fafc;
    --text-secondary: #cbd5e1;
    --text-muted: #94a3b8;
    --border-radius: 16px;
    --transition: all 0.25s ease;
    --glow-primary: 0 0 8px rgba(0, 170, 255, 0.12);
    --glow-accent: 0 0 8px rgba(6, 182, 212, 0.12);
}

body {
    background: var(--bg-gradient);
    color: var(--text-primary);
    font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
    margin: 0;
    min-height: 100vh;
    line-height: 1.6;
    overflow-x: hidden;
    position: relative;
}

/* Subtle static background */
body::before {
    content: "";
    position: fixed;
    inset: 0;
    z-index: -1;
    background:
        radial-gradient(ellipse at 20% 20%, rgba(0,170,255,0.05), transparent 60%),
        radial-gradient(ellipse at 80% 80%, rgba(34,197,94,0.03), transparent 60%);
}

button {
    background: linear-gradient(145deg, var(--primary-color) 0%, var(--accent-color) 100%);
    color: #fff;
    border: none;
    border-radius: var(--border-radius);
    font-weight: 600;
    font-size: 1rem;
    padding: 14px 28px;
    cursor: pointer;
    transition: var(--transition);
    box-shadow: var(--glow-primary);
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    position: relative;
    overflow: hidden;
}

button:hover, button:focus {
    transform: translateY(-1px);
    box-shadow: 0 6px 16px rgba(0, 170, 255, 0.25);
    background: linear-gradient(145deg, var(--primary-hover) 0%, var(--accent-hover) 100%);
    outline: none;
}

button:active {
    transform: translateY(0);
}

.container {
    width: 95%;
    max-width: 650px;
    margin: 2rem auto;
    padding: 0 1rem;
    animation: fadeInUp 0.5s ease both;
}

.neo-box {
    background: var(--card-bg);
    border-radius: var(--border-radius);
    box-shadow: var(--card-shadow);
    padding: 1.8rem 1.5rem;
    margin-bottom: 2rem;
    border: 1px solid var(--card-border);
    backdrop-filter: blur(10px);
    animation: fadeIn 0.4s ease both;
    transition: var(--transition);
    position: relative;
    overflow: hidden;
}

.neo-box:hover {
    box-shadow: 0 8px 24px rgba(0, 0, 0, 0.4);
    border-color: rgba(0, 170, 255, 0.3);
}

.neo-box-accent1 {
    border-left: 5px solid var(--primary-color);
}

.section-title {
    color: var(--text-primary);
    font-size: 2rem;
    font-weight: 700;
    margin-bottom: 1rem;
    letter-spacing: 1px;
    animation: fadeIn 1s;
    background: linear-gradient(to right, var(--text-primary), var(--text-secondary));
    -webkit-background-clip: text;
    background-clip: text;
    -webkit-text-fill-color: transparent;
}

.success-msg {
    display: flex;
    align-items: center;
    background: rgba(34, 197, 94, 0.1);
    border-left: 5px solid var(--success);
    border-radius: var(--border-radius);
    padding: 1rem;
    margin-bottom: 1.5rem;
    color: var(--text-primary);
    font-weight: 500;
    font-size: 1.1em;
    animation: slideInLeft 0.5s;
}

.success-msg i {
    font-size: 1.6em;
    margin-right: 0.7rem;
    color: var(--success);
    animation: bounceIn 1s;
}

.info-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 0.8rem 1.2rem;
    font-family: ui-monospace, 'Cascadia Code', 'SF Mono', monospace;
    background: rgba(15, 23, 42, 0.6);
    border-radius: var(--border-radius);
    padding: 1.2rem;
    margin-bottom: 1.5rem;
    font-size: 1rem;
    animation: fadeInUp 0.5s;
    border: 1px solid var(--card-border);
}

/* Equal-sized stats and chat styles */
.stats-container { display:flex; gap:12px; margin-top:1.5rem; }
.stat-item { flex:1; background:rgba(15,23,42,0.6); padding:12px; border-radius:12px; border:1px solid var(--card-border); display:flex; align-items:center; gap:10px; justify-content:space-between; min-width:0; }
.stat-icon { font-size:1.6em; color:var(--accent-color); margin-right:10px; }
.stat-value { font-weight:800; font-size:1.4rem; }
.stat-label { color:var(--text-secondary); font-size:0.95rem; }

.public-chat { margin-top:1.5rem; display:flex; flex-direction:column; gap:8px; align-items:center; }
/* unified responsive chat width: match inputs' max-width (400px) */
:root {
  /* fixed chat sizing to match input fields used elsewhere */
  --chat-width: 400px;
  --chat-padding: 10px;
  --chat-font-size: 0.98rem;
}
.chat-box { width:100%; max-width:var(--chat-width); background:rgba(15,23,42,0.6); border-radius:12px; padding:var(--chat-padding); border:1px solid var(--card-border); max-height:320px; overflow:auto; font-size:var(--chat-font-size); }
.chat-message { padding:6px;border-radius:8px;margin-bottom:6px;background:rgba(255,255,255,0.02); display:block; }
.chat-name { font-weight:700; color:var(--accent-color); margin-right:8px; }

/* Ensure the top chat display and the input fields share the same fixed width */
.public-chat .chat-box, .public-chat .chat-form { max-width:400px; width:100%; margin:0 auto; box-sizing:border-box; }
.chat-time { color:var(--text-muted); font-size:0.8rem; margin-left:auto; }
.chat-form { width:100%; max-width:var(--chat-width); display:flex; gap:8px; align-items:center; flex-direction:column; }

/* Make inputs full-width to match message box */
.chat-form input[type="text"] { background: rgba(15, 23, 42, 0.6); border: 1px solid var(--card-border); border-radius: 10px; color: var(--text-primary); padding: 10px; box-sizing: border-box; width:100%; }
.chat-form button { padding: 10px 16px; border-radius: 10px; align-self:center; margin-top:8px; }

/* Small screens: ensure same behavior and limit height */
@media (max-width: 520px) {
  .chat-form { max-width: 95%; }
  .chat-box { max-width: 95%; max-height: 260px; }
}
/* Device-specific chat sizing: ensure smaller on phones */
@media (max-width: 480px) {
  :root { --chat-width: 92vw; --chat-padding: 8px; --chat-font-size: 0.95rem; }
  .chat-form input[type="text"], .chat-form button { font-size:0.95rem; }
  .chat-box { max-height: 280px; }
}

@media (max-width: 360px) {
  :root { --chat-width: 94vw; --chat-padding: 6px; --chat-font-size: 0.92rem; }
  .chat-box { max-height: 240px; }
}

@media (min-width: 900px) {
  :root { --chat-width: 420px; }
}
/* New chat message layout: header + body */
.chat-message { display:block; }
.chat-meta { display:flex; align-items:center; gap:8px; }
.chat-text { margin-top:6px; white-space:pre-wrap; overflow-wrap:anywhere; word-break:break-word; }
.chat-meta .chat-time { margin-left:auto; font-size:0.85rem; color:var(--text-muted); }


.info-grid div:nth-child(2n) {
    font-weight: 600;
    color: var(--accent-color);
    word-break: break-all;
}

.link-box {
    background: rgba(15, 23, 42, 0.6);
    border-radius: var(--border-radius);
    padding: 1.2rem;
    margin-bottom: 1rem;
    border: 1px solid var(--card-border);
    font-family: ui-monospace, 'Cascadia Code', 'SF Mono', monospace;
    color: var(--text-primary);
    font-size: 0.95rem;
    transition: var(--transition);
    animation: fadeIn 0.5s;
}

.link-box:hover {
    box-shadow: 0 0 10px rgba(255, 255, 255, 0.08);
}

.link-title {
    font-weight: 600;
    margin-bottom: 0.8rem;
    font-size: 1rem;
    letter-spacing: 0.5px;
    display: flex;
    align-items: center;
    gap: 8px;
}

.link-title.tls { color: var(--success); }
.link-title.nontls { color: var(--warning); }

/* Consistent form styling */
input[type="text"], input[type="password"] {
    background: rgba(15, 23, 42, 0.6);
    border: 1px solid var(--card-border);
    border-radius: var(--border-radius);
    color: var(--text-primary);
    font-size: 0.95rem;
    padding: 12px 16px;
    width: 100%;
    transition: var(--transition);
    box-sizing: border-box;
    max-width: 400px;
    margin: 0 auto;
    display: block;
    outline: none;
    backdrop-filter: blur(5px);
    position: relative;
}

input[type="text"]:hover, input[type="password"]:hover {
    border-color: var(--accent-color);
}

input[type="text"]:focus, input[type="password"]:focus {
    outline: none;
    border-color: var(--primary-color);
    box-shadow: 0 0 0 2px rgba(0, 170, 255, 0.15);
    background: rgba(15, 23, 42, 0.8);
}

/* Form group styling with consistent spacing */
.form-group {
    margin-bottom: 1.8rem;
    text-align: center;
    width: 100%;
    display: flex;
    flex-direction: column;
    align-items: center;
}

.form-label {
    display: block;
    font-weight: 600;
    margin-bottom: 0.8rem;
    color: var(--text-primary);
    width: 100%;
    max-width: 400px;
    text-align: center;
    font-size: 1rem;
}

.form-input-container {
    width: 100%;
    display: flex;
    justify-content: center;
    position: relative;
    max-width: 400px;
}

/* Placeholder styling for consistency */
input::placeholder {
    color: var(--text-muted);
    opacity: 0.7;
}

/* Optional label styling */
.optional-label {
    color: var(--text-muted);
    font-weight: 400;
    font-size: 0.85rem;
    margin-left: 5px;
}

/* Optional field styling */
.form-group.optional .form-label {
    color: var(--text-secondary);
}

/* Make the forms more visually appealing */
form {
    display: flex;
    flex-direction: column;
    align-items: center;
    width: 100%;
    margin-bottom: 1.5rem;
}

/* Navbar styles with improved responsiveness */
.navbar {
    width: 100%;
    background: rgba(15, 23, 42, 0.9);
    backdrop-filter: blur(10px);
    border-bottom: 1px solid var(--card-border);
    box-shadow: 0 4px 15px rgba(0, 0, 0, 0.2);
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 1rem max(1.5rem, 5%);
    position: sticky;
    top: 0;
    z-index: 100;
    box-sizing: border-box;
}

.navbar-brand {
    display: flex;
    align-items: center;
    gap: 10px;
    font-weight: 700;
    font-size: clamp(0.95rem, 3vw, 1.4rem); /* Smaller and more responsive */
    color: var(--text-primary);
    text-decoration: none;
    margin-right: auto;
    padding-left: 5%;
    line-height: 1.1;
    transition: font-size 0.2s;
}

.navbar-brand i {
    color: var(--accent-color);
}

.navbar-nav {
    display: flex;
    align-items: center;
    gap: clamp(8px, 2vw, 15px);
    margin-left: auto;
    padding-right: 5%;
}

.nav-link {
    color: var(--text-secondary);
    text-decoration: none;
    font-weight: 500;
    padding: 8px 16px;
    border-radius: var(--border-radius);
    transition: var(--transition);
    font-size: clamp(0.9rem, 3vw, 1rem);
}

.nav-link:hover, .nav-link.active {
    color: var(--text-primary);
    background: rgba(255, 255, 255, 0.1);
}

/* Improved responsive design with device-specific breakpoints */
@media (max-width: 992px) {
    .container {
        max-width: 90%;
    }
    
    .section-title {
        font-size: 1.8rem;
    }
}

@media (max-width: 768px) {
    .navbar {
        padding: 0.8rem 1rem;
    }
    
    .navbar-nav {
        gap: 8px;
    }
    
    .nav-link {
        padding: 6px 12px;
    }
    
    .section-title {
        font-size: 1.6rem;
    }
    
    .container {
        padding: 0 0.5rem;
        margin: 1.5rem auto;
        width: 90%;
    }
    
    .neo-box {
        padding: 1.4rem 1.2rem;
    }
    
    button {
        padding: 10px 16px;
        font-size: 0.95rem;
    }
}

@media (max-width: 576px) {
    .navbar {
        flex-direction: column;
        padding: 0.8rem 0.5rem;
        gap: 8px;
    }
    
    .navbar-brand {
        padding-left: 0;
        justify-content: center;
        margin-right: 0;
    }
    
    .navbar-nav {
        padding-right: 0;
        justify-content: center;
        width: 100%;
    }
    
    .info-grid {
        grid-template-columns: 1fr;
        font-size: 0.95rem;
    }
    
    .section-title {
        font-size: 1.5rem;
    }
    
    .container {
        width: 95%;
        padding: 0;
    }
    
    .neo-box {
        padding: 1.2rem 1rem;
    }
}

@media (min-width: 1200px) {
    .container {
        max-width: 850px;
    }
}

/* Service status styles */
.service-list { 
  display: grid; 
  grid-template-columns: 1fr 80px; /* Name and status columns */
  gap: 12px; 
  margin-top: 0.8rem;
}

.service-name {
  font-size: 1rem;
  font-weight: 500;
  padding: 8px;
  display: flex;
  align-items: center;
  gap: 8px;
}

.service-status {
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: var(--border-radius);
  padding: 8px;
}

.status-green {
  color: var(--success);
  background: rgba(34, 197, 94, 0.1);
  border: 1px solid rgba(34, 197, 94, 0.3);
}

.status-red {
  color: var(--error);
  background: rgba(239, 68, 68, 0.1);
  border: 1px solid rgba(239, 68, 68, 0.3);
}

/* Status grid */
.status-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 12px;
  font-family: ui-monospace, 'Cascadia Code', 'SF Mono', monospace;
  margin-bottom: 1.2rem;
}

.status-grid-2 {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 12px;
  font-family: ui-monospace, 'Cascadia Code', 'SF Mono', monospace;
  margin-bottom: 1.2rem;
}

.status-card {
  background: rgba(15, 23, 42, 0.6);
  border-radius: var(--border-radius);
  padding: 1rem;
  border: 1px solid var(--card-border);
  display: flex;
  flex-direction: column;
  gap: 8px;
  transition: var(--transition);
  backdrop-filter: blur(5px);
  position: relative;
  overflow: hidden;
}

.status-card:hover {
  background: rgba(15, 23, 42, 0.8);
  border-color: rgba(0, 170, 255, 0.3);
}

.status-label {
  color: var(--text-muted);
  font-size: 0.9rem;
  display: flex;
  align-items: center;
  gap: 6px;
}

.status-value {
  color: var(--text-primary);
  font-size: 1.2rem;
  font-weight: 600;
}

.status-subtitle {
  font-size: 1rem;
  font-weight: 600;
  margin: 1.2rem 0 0.8rem 0;
  color: var(--text-secondary);
  display: flex;
  align-items: center;
  gap: 8px;
}

.status-subtitle i {
  color: var(--accent-color);
}

/* Simple spinner loader */
.loader {
  width: 48px;
  height: 48px;
  border: 3px solid rgba(255,255,255,0.1);
  border-top-color: var(--primary-color);
  border-radius: 50%;
  animation: spin 0.8s linear infinite;
  margin: 2rem auto;
}

@keyframes spin {
  to { transform: rotate(360deg); }
}

/* Additional animations */
@keyframes fadeInUp {
    from { opacity: 0; transform: translateY(12px); }
    to   { opacity: 1; transform: translateY(0); }
}

@keyframes fadeIn {
    from { opacity: 0; }
    to   { opacity: 1; }
}

@keyframes popIn {
    from { opacity: 0; }
    to   { opacity: 1; }
}

@keyframes slideInLeft {
    from { transform: translateX(-10px); opacity: 0; }
    to   { transform: translateX(0); opacity: 1; }
}

/* Reveal on scroll animation */
.reveal {
    opacity: 0;
    transform: translateY(8px);
    transition: opacity 0.4s ease, transform 0.4s ease;
}

.reveal.visible {
    opacity: 1;
    transform: translateY(0);
}

/* Stats display - responsive improvements */
.stats-container {
    display: flex;
    justify-content: center;
    gap: clamp(1rem, 4vw, 2rem);
    margin: 1.5rem 0;
    flex-wrap: wrap;
}

.stat-item {
    background: rgba(15, 23, 42, 0.5);
    border-radius: var(--border-radius);
    padding: 0.8rem 1.5rem;
    display: flex;
    align-items: center;
    gap: 10px;
    border: 1px solid var(--card-border);
    flex: 1;
    min-width: 200px;
    max-width: 300px;
}

.stat-icon {
    color: var(--accent-color);
    font-size: clamp(1.1rem, 3vw, 1.2rem);
}

.stat-value {
    font-weight: 600;
    font-size: clamp(1rem, 3vw, 1.1rem);
    color: var(--text-primary);
}

.stat-label {
    font-size: clamp(0.8rem, 2vw, 0.9rem);
    color: var(--text-secondary);
}

/* Footer styles */
.footer {
    text-align: center;
    padding: 1.5rem;
    color: var(--text-muted);
    font-size: 0.9rem;
    border-top: 1px solid var(--card-border);
    margin-top: 3rem;
}

.developer-badge {
    position: fixed;
    bottom: 1rem;
    left: 1rem;
    background: rgba(15, 23, 42, 0.8);
    backdrop-filter: blur(10px);
    border-radius: var(--border-radius);
    padding: 0.5rem 1rem;
    border: 1px solid var(--card-border);
    font-size: 0.9rem;
    color: var(--text-secondary);
    transition: var(--transition);
    z-index: 999;
}

.developer-badge:hover {
    box-shadow: 0 4px 10px rgba(0, 0, 0, 0.2);
}

/* Responsive topbar */
.topbar {
    display: flex;
    justify-content: center;
    gap: 1rem;
    background: rgba(15, 23, 42, 0.9);
    backdrop-filter: blur(10px);
    border-bottom: 1px solid var(--card-border);
    padding: 1rem;
    position: sticky;
    top: 0;
    z-index: 100;
}

.topbar-btn {
    padding: 8px 16px;
    border-radius: var(--border-radius);
    font-weight: 600;
    transition: var(--transition);
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    min-width: 140px;
    font-size: 0.9rem;
}

@media (max-width: 640px) {
    .topbar-btn {
        min-width: auto;
        padding: 8px 12px;
        font-size: 0.8rem;
    }
    
    .stats-container {
        gap: 1rem;
        flex-direction: column;
        align-items: center;
    }
}

/* --- Remove this media query block:
@media (max-width: 640px) {
  .services-grid {
    grid-template-columns: 1fr;
  }
}
--- */

.services-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 12px;
  margin-top: 0.8rem;
}

/* Bottom link button */
.bottom-link-container {
    display: flex;
    justify-content: center;
    margin: 2rem 0;
    animation: fadeInUp 0.8s ease;
}

.bottom-link-btn {
    background: rgba(15, 23, 42, 0.7);
    border: 1px solid var(--card-border);
    box-shadow: 0 4px 15px rgba(0, 0, 0, 0.2);
    color: var(--text-primary);
    font-weight: 600;
    padding: 12px 24px;
    border-radius: var(--border-radius);
    text-decoration: none;
    display: inline-flex;
    align-items: center;
    gap: 10px;
    transition: var(--transition);
    backdrop-filter: blur(5px);
}

.bottom-link-btn:hover {
    box-shadow: 0 6px 16px rgba(0, 0, 0, 0.3);
    background: rgba(15, 23, 42, 0.9);
}

.bottom-link-btn i {
    color: var(--accent-color);
    font-size: 1.1rem;
}
<div id="qr-modal" style="display:none;position:fixed;top:0;left:0;width:100vw;height:100vh;background:rgba(0,0,0,0.85);z-index:9999;align-items:center;justify-content:center;">
  <div id="qr-modal-content" style="background:#fff;padding:2.5em 2em 1.5em 2em;border-radius:24px;box-shadow:0 8px 32px #000;max-width:95vw;max-height:95vh;position:relative;text-align:center;display:flex;flex-direction:column;align-items:center;">
    <canvas id="wg-qr-modal" style="margin:0 auto;width:320px;height:320px;"></canvas>
    <button id="close-qr-btn" style="margin-top:1.5em;background:#222;color:#fff;border:none;border-radius:10px;padding:0.7em 0;font-weight:600;cursor:pointer;width:90%;max-width:320px;font-size:1.1em;box-shadow:0 2px 8px rgba(0,0,0,0.15);">
      Close
    </button>
  </div>
</div>
<style>
#qr-modal {
  display: none;
  position: fixed;
  top: 0; left: 0;
  width: 100vw; height: 100vh;
  background: rgba(0,0,0,0.85);
  z-index: 9999;
  align-items: center;
  justify-content: center;
}
#qr-modal-content {
  background: #fff;
  border-radius: 24px;
  box-shadow: 0 8px 32px #000;
  padding: 2.5em 2em 1.5em 2em;
  text-align: center;
  display: flex;
  flex-direction: column;
  align-items: center;
}
#wg-qr-modal {
  width: 320px;
  height: 320px;
  margin: 0 auto;
  display: block;
}
#close-qr-btn {
  margin-top: 1.5em;
  background: #222;
  color: #fff;
  border: none;
  border-radius: 10px;
  padding: 0.7em 0;
  font-weight: 600;
  cursor: pointer;
  width: 90%;
  max-width: 320px;
  font-size: 1.1em;
  box-shadow: 0 2px 8px rgba(0,0,0,0.15);
}
@media (max-width: 480px) {
  #qr-modal-content {
    padding: 1em 0.5em 1em 0.5em;
  }
  #wg-qr-modal {
    width: 220px;
    height: 220px;
  }
  #close-qr-btn {
    font-size: 1em;
    max-width: 220px;
  }
  @media (max-width: 576px) {
    /* Keep navbar items on a single row: brand left, burger right.
       Do not center the brand on small screens — keep it aligned left. */
    .navbar {
        flex-direction: row;
        align-items: center;
        justify-content: space-between;
        padding: 0.6rem 0.8rem;
    }
    
    .navbar-brand {
        padding-left: 0.8rem;
        justify-content: flex-start;
        margin-right: auto;
    }
    
    /* Hide the full desktop nav on small devices; burger will be visible */
    .navbar-nav {
        display: none;
        padding-right: 0;
        justify-content: flex-end;
        width: auto;
    }
    
    .info-grid {
        grid-template-columns: 1fr;
        font-size: 0.95rem;
    }
    
    .section-title {
        font-size: 1.5rem;
    }
    
    .container {
        width: 95%;
        padding: 0;
    }
    
    .neo-box {
        padding: 1.2rem 1rem;
    }
}
}

/* Clean Loading Overlay */
.loading-overlay {
  display: none;
  position: fixed;
  inset: 0;
  z-index: 9999;
  background: rgba(15, 23, 42, 0.88);
  backdrop-filter: blur(6px);
  justify-content: center;
  align-items: center;
  flex-direction: column;
  gap: 1.5rem;
}
.loading-overlay.active {
  display: flex;
}
.loading-overlay .loading-text {
  color: var(--text-primary);
  font-size: 1.1rem;
  font-weight: 600;
  letter-spacing: 0.03em;
  opacity: 0.9;
}
.loading-spinner {
  width: 56px;
  height: 56px;
  border: 3px solid rgba(255,255,255,0.08);
  border-top-color: var(--primary-color);
  border-radius: 50%;
  animation: spin 0.7s linear infinite;
}
/* placeholder to keep old selectors from breaking */
.wheel-and-hamster, .wheel, .hamster, .hamster div, .spoke { display: none; }
</style>
</head>
<body>

<!-- Loading Overlay -->
<div class="loading-overlay" id="loadingOverlay">
  <div class="loading-spinner"></div>
  <div class="loading-text">Creating your account...</div>
</div>

"""

HTML_FOOTER = """
<script>
// Remove Shoelace copy popout notification
window.addEventListener('sl-copy', function(event) {
  event.preventDefault();
});

// Add active class to current nav link
document.addEventListener('DOMContentLoaded', function() {
    const currentPath = window.location.pathname;
    const navLinks = document.querySelectorAll('.nav-link');
    navLinks.forEach(link => {
        const href = link.getAttribute('href');
        if (currentPath === href || (currentPath === '/' && href === '/main/')) {
            link.classList.add('active');
        }
    });

    // Reveal on scroll animation
    const obs = new IntersectionObserver((entries) => {
        entries.forEach(e => {
            if (e.isIntersecting) e.target.classList.add('visible');
        });
    }, { threshold: 0.12 });
    document.querySelectorAll('.neo-box, .link-box, .stat-item, .status-card').forEach(el => {
        el.classList.add('reveal');
        obs.observe(el);
    });
});
</script>
</body></html>
"""

def get_ipv4():
    try:
        import urllib.request
        # Try cloud provider metadata first
        for url in [
            "http://169.254.169.254/latest/meta-data/public-ipv4",
            "http://169.254.169.254/latest/meta-data/local-ipv4",
        ]:
            try:
                with urllib.request.urlopen(url, timeout=1) as r:
                    ip = r.read().decode().strip()
                    if ip and ip != "Not Found" and not ip.startswith("10.") and not ip.startswith("192.168.") and not ip.startswith("172."):
                        return ip
            except Exception:
                continue
        # Try external public IP service
        try:
            with urllib.request.urlopen("https://api.ipify.org", timeout=2) as r:
                ip = r.read().decode().strip()
                if ip and not ip.startswith("10.") and not ip.startswith("192.168.") and not ip.startswith("172."):
                    return ip
        except Exception:
            pass
        # Fallback to local IP
        ip = subprocess.check_output("hostname -I | awk '{print $1}'", shell=True).decode().strip()
        return ip
    except Exception:
        return "N/A"

def get_hysteria_user_count():
    try:
        import sqlite3
        db_path = "/etc/hysteria/udpusers.db"
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute("CREATE TABLE IF NOT EXISTS users (username TEXT, password TEXT, expiry INTEGER);")
        c.execute("SELECT COUNT(*) FROM users;")
        count = c.fetchone()[0]
        conn.close()
        return count
    except Exception as e:
        logging.error(f"Error in get_hysteria_user_count: {e}")
        return 0

def update_hysteria_userpass_config():
    import sqlite3, json, time
    db_path = "/etc/hysteria/udpusers.db"
    config_path = "/etc/hysteria/config.json"
    now = int(time.time())
    try:
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute("CREATE TABLE IF NOT EXISTS users (username TEXT, password TEXT, expiry INTEGER);")
        c.execute("SELECT username, password FROM users WHERE expiry IS NULL OR expiry > ?", (now,))
        users = c.fetchall()
        conn.close()
        userpass_list = sorted(set(
            [p for _, p in users if p] +
            [f"{u}:{p}" for u, p in users if u and p]
        ))
        # Update config.json
        with open(config_path, "r") as f:
            config = json.load(f)
        if "auth" not in config:
            config["auth"] = {}
        config["auth"]["mode"] = "passwords"
        config["auth"]["config"] = userpass_list
        config["auth"].pop("type", None)
        config["auth"].pop("userpass", None)
        with open(config_path, "w") as f:
            json.dump(config, f, indent=2)
        return True
    except Exception:
        return False

def add_hysteria_user(username, password, days=None):
    import sqlite3, time, subprocess, sys
    db_path = "/etc/hysteria/udpusers.db"
    try:
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute("CREATE TABLE IF NOT EXISTS users (username TEXT, password TEXT, expiry INTEGER);")
        c.execute("SELECT COUNT(*) FROM users WHERE username=?", (username,))
        if c.fetchone()[0] > 0:
            conn.close()
            return False, "Username already exists."
        if days is None:
            days = get_create_account_expiry('hysteria')
        days = max(1, int(days))
        expiry_timestamp = int(time.time()) + days * 86400
        c.execute("INSERT INTO users (username, password, expiry) VALUES (?, ?, ?);", (username, password, expiry_timestamp))
        conn.commit()
        conn.close()
        # Update config.json with all valid users
        update_hysteria_userpass_config()
        # Restart hysteria-v1.service
        subprocess.call(["systemctl", "restart", "hysteria-v1.service"])
        # --- Fix scheduled removal: remove user from DB, update config, restart hysteria-server ---
        if subprocess.call(['/usr/bin/which', 'at'], stdout=subprocess.DEVNULL) == 0:
            remove_cmd = (
                f"/usr/bin/python3 -c 'import sqlite3, time, json; "
                f"db=\"{db_path}\"; "
                f"cfg=\"/etc/hysteria/config.json\"; "
                f"u=\"{username}\"; "
                f"conn=sqlite3.connect(db); "
                f"c=conn.cursor(); "
                f"c.execute(\"DELETE FROM users WHERE username=?\", (u,)); "
                f"conn.commit(); "
                f"c.execute(\"SELECT username, password FROM users WHERE expiry IS NULL OR expiry > ?\", (int(time.time()),)); "
                f"users=c.fetchall(); "
                f"conn.close(); "
                f"up=sorted(set(([x[1] for x in users if x[1]] + [f\"{{}}:{{}}\".format(x[0],x[1]) for x in users if x[0] and x[1]]))); "
                f"conf=json.load(open(cfg)); "
                f"if \"auth\" not in conf: conf[\"auth\"]={{}}; "
                f"conf[\"auth\"][\"mode\"]=\"passwords\"; "
                f"conf[\"auth\"][\"config\"]=up; "
                f"conf[\"auth\"].pop(\"type\", None); "
                f"conf[\"auth\"].pop(\"userpass\", None); "
                f"json.dump(conf, open(cfg,\"w\"), indent=2)' && "
                f"/usr/bin/systemctl restart hysteria-v1.service"
            )
            subprocess.call(
                f"echo \"{remove_cmd}\" | /usr/bin/at now + {days} days",
                shell=True
            )
        # --- End schedule ---
        return True, expiry_timestamp
    except Exception as e:
        return False, str(e)


def add_openvpn_user(username, password, days):
    """Create OpenVPN user, configure expiry and generate .ovpn file."""
    try:
        os.makedirs('/etc/openvpn', exist_ok=True)
        users_file = '/etc/openvpn/users.txt'
        # duplicate check
        if os.path.isfile(users_file):
            with open(users_file, 'r') as f:
                for line in f:
                    if line.strip().startswith(f"{username}:"):
                        return None, "Username already exists."
        expiry = 0
        if days and days > 0:
            expiry = int(time.time()) + days * 86400
        with open(users_file, 'a') as f:
            f.write(f"{username}:{password}:{expiry}\n")
        # build ovpn client file
        SERVER_IP = get_ipv4()
        if os.path.isfile('/etc/domain'):
            try:
                REMOTE_HOST = open('/etc/domain').read().strip()
                host_display = REMOTE_HOST
            except Exception:
                REMOTE_HOST = SERVER_IP
                host_display = SERVER_IP
        else:
            REMOTE_HOST = SERVER_IP
            host_display = SERVER_IP
        ovpn_path = f"/etc/openvpn/{username}.ovpn"
        try:
            with open(ovpn_path, 'w') as outf:
                outf.write("""
# Jerico  Version 1.0
# https://t.me/fujivpn

client
""")
                outf.write("dev tun\nproto tcp\n")
                outf.write(f"remote {REMOTE_HOST} 443\n")
                outf.write("remote-cert-tls server\nresolv-retry infinite\nconnect-retry 5\n")
                outf.write("cipher AES-128-GCM\nauth SHA256\nnobind\npersist-key\npersist-tun\n")
                outf.write("setenv CLIENT_CERT 0\nverb 3\n")
                outf.write("<auth-user-pass>\n")
                outf.write(f"{username}\n{password}\n")
                outf.write("</auth-user-pass>\n<ca>\n")
                try:
                    ca_text = open('/etc/openvpn/certs/ca.crt').read()
                except Exception:
                    ca_text = ''
                outf.write(ca_text)
                outf.write("\n</ca>\n")
        except Exception as e:
            return None, str(e)
        os.chmod(ovpn_path, 0o644)
        try:
            with open(ovpn_path, 'r') as ovpnf:
                ovpn_content = ovpnf.read()
        except Exception:
            ovpn_content = ""
        if SERVER_IP:
            download_link = f"http://{SERVER_IP}:10/{username}.ovpn"
        else:
            download_link = ovpn_path
        if expiry == 0:
            expiry_display = "never"
            days_display = "never"
        else:
            try:
                expiry_display = time.strftime("%F", time.localtime(expiry))
            except Exception:
                expiry_display = str(expiry)
            now_ts = int(time.time())
            if expiry <= now_ts:
                days_left = 0
            else:
                days_left = (expiry - now_ts) // 86400
            days_display = str(days_left)
        info = {
            'username': username,
            'password': password,
            'SERVER_IP': SERVER_IP,
            'host_display': host_display,
            'expiry_display': expiry_display,
            'days_display': days_display,
            'download_link': download_link,
            'ovpn_content': ovpn_content,
            'nameserver': get_nameserver(),
            'public_key': get_public_key(),
        }
        return info, None
    except Exception as e:
        return None, str(e)


def get_hysteria_obfs():
    import json
    try:
        with open("/etc/hysteria/config.json") as f:
            obfs = json.load(f).get("obfs", "N/A")
        if isinstance(obfs, dict):
            return obfs.get("salamander", {}).get("password", "N/A")
        return obfs or "N/A"
    except Exception:
        return "N/A"

def get_hysteria_port():
    import json
    try:
        with open("/etc/hysteria/config.json") as f:
            listen = str(json.load(f).get("listen", ":10000")).strip()
        if ":" in listen:
            listen = listen.rsplit(":", 1)[1]
        listen = listen.lstrip(":")
        if not listen:
            return "10000-30000"
        if listen == "10000":
            return "10000-30000"
        return listen
    except Exception:
        return "10000-30000"

def get_hysteria_speed_mbps(field, default="100"):
    import json
    try:
        with open("/etc/hysteria/config.json") as f:
            value = str(json.load(f).get(field, default)).strip()
        return value or default
    except Exception:
        return default

def build_hysteria_uri(username, password, domain, obfs):
    import urllib.parse
    host = (domain or get_ipv4() or "127.0.0.1").strip()
    params = {
        "protocol": "udp",
        "auth": f"{username}:{password}",
        "peer": host,
        "insecure": "1",
        "upmbps": get_hysteria_speed_mbps("up_mbps"),
        "downmbps": get_hysteria_speed_mbps("down_mbps"),
    }
    if obfs and obfs != "N/A":
        params["obfs"] = "xplus"
        params["obfsParam"] = obfs
    return (
        f"hysteria://{host}:{get_hysteria_port()}?{urllib.parse.urlencode(params)}"
        f"#{urllib.parse.quote(username, safe='')}"
    )

def get_server_ip():
    try:
        import urllib.request
        for url in [
            "http://169.254.169.254/latest/meta-data/public-ipv4",
            "http://169.254.169.254/latest/meta-data/local-ipv4",
        ]:
            try:
                with urllib.request.urlopen(url, timeout=1) as r:
                    ip = r.read().decode().strip()
                    if ip and ip != "Not Found":
                        return ip
            except Exception:
                continue
        return subprocess.check_output("hostname -I | awk '{print $1}'", shell=True).decode().strip()
    except Exception:
        return "N/A"

def get_network_stats():
    stats = {}
    try:
        with open('/proc/net/dev') as f:
            for line in f.readlines()[2:]:
                if ':' not in line:
                    continue
                iface, data = line.split(':', 1)
                iface = iface.strip()
                if iface == "lo":
                    continue
                fields = data.split()
                rx_bytes = int(fields[0])
                tx_bytes = int(fields[8])
                stats[iface] = {'rx': rx_bytes, 'tx': tx_bytes}
    except Exception:
        pass
    return stats

def get_total_network_bytes():
    stats = get_network_stats()
    rx_total = sum(i['rx'] for i in stats.values()) if stats else 0
    tx_total = sum(i['tx'] for i in stats.values()) if stats else 0
    return rx_total, tx_total

def get_memory_stats():
    mem = {'total': 0, 'used': 0, 'free': 0, 'buffers': 0, 'cached': 0, 'available': 0}
    try:
        with open('/proc/meminfo') as f:
            lines = f.readlines()
        meminfo = {}
        for line in lines:
            parts = line.split()
            if len(parts) >= 2:
                meminfo[parts[0].rstrip(':')] = int(parts[1])
        total_kb = meminfo.get('MemTotal', 0)
        available_kb = meminfo.get('MemAvailable')
        if available_kb is None or available_kb <= 0:
            available_kb = (
                meminfo.get('MemFree', 0)
                + meminfo.get('Buffers', 0)
                + meminfo.get('Cached', 0)
                + meminfo.get('SReclaimable', 0)
                - meminfo.get('Shmem', 0)
            )
        if available_kb < 0:
            available_kb = 0
        if total_kb > 0 and available_kb > total_kb:
            available_kb = total_kb
        used_kb = total_kb - available_kb if total_kb > available_kb else 0
        cached_kb = meminfo.get('Cached', 0) + meminfo.get('SReclaimable', 0) - meminfo.get('Shmem', 0)
        if cached_kb < 0:
            cached_kb = 0

        mem['total'] = total_kb // 1024
        mem['available'] = available_kb // 1024
        mem['free'] = meminfo.get('MemFree', 0) // 1024
        mem['buffers'] = meminfo.get('Buffers', 0) // 1024
        mem['cached'] = cached_kb // 1024
        mem['used'] = used_kb // 1024
    except Exception:
        pass
    return mem

def get_service_statuses():
    services = [
        ("SSH", "ssh"),
        ("DNSTT", "dnstt"),
        ("SQUID", "squid"),
        ("WEBSOCKET", "websocket"),
        ("SSL", "multiplexer"),
        ("XRAY", "xray"),
        ("BADVPN-UDPGW", "badvpn-udpgw"),
        ("HYSTERIA-UDP", "hysteria-v1"),
        ("MULTIPLEXER", "multiplexer"),
        ("OPENVPN", "openvpn")
    ]
    status = {}
    for name, svc in services:
        try:
            # For SSH, try both common service names "ssh" and "sshd"
            if svc == "ssh":
                try:
                    result = subprocess.check_output(
                        ["systemctl", "is-active", "ssh.service"],
                        stderr=subprocess.DEVNULL
                    ).decode().strip()
                    status[name] = (result == "active")
                except Exception:
                    try:
                        result = subprocess.check_output(
                            ["systemctl", "is-active", "sshd.service"],
                            stderr=subprocess.DEVNULL
                        ).decode().strip()
                        status[name] = (result == "active")
                    except Exception:
                        status[name] = False
            else:
              unit = svc if '.' in svc else f"{svc}.service"
              result = subprocess.check_output(
                ["systemctl", "is-active", unit],
                stderr=subprocess.DEVNULL
              ).decode().strip()
              status[name] = (result == "active")
        except Exception:
            status[name] = False
    # Return as a list of tuples to preserve order
    return [(name, status[name]) for name, _ in services]

def get_storage_stats():
    try:
        st = os.statvfs('/')
        total = st.f_blocks * st.f_frsize // (1024 * 1024)
        free = st.f_bavail * st.f_frsize // (1024 * 1024)
        used = total - free
        return {'total': total, 'used': used, 'free': free}
    except Exception:
        return {'total': 0, 'used': 0, 'free': 0}

def get_cpu_usage():
    try:
        with open('/proc/stat') as f:
            cpu_line = f.readline()
        fields = [float(x) for x in cpu_line.strip().split()[1:]]
        idle = fields[3]
        total = sum(fields)
        return idle, total
    except Exception:
        return 0, 0

def get_nameserver():
    try:
        return open('/etc/nameserver').read().strip()
    except:
        return "Not configured"

def get_public_key():
    try:
        return open('/etc/dnstt/server.pub').read().strip()
    except:
        return "Not configured"

def get_domain():
    try:
        return open('/etc/domain').read().strip()
    except:
        return "yourdomain.com"

def get_dnstt_user_count():
    try:
        path = '/var/lib/regular_users'
        if not os.path.isdir(path):
            return 0
        count = 0
        for fname in os.listdir(path):
            if fname and os.path.isfile(os.path.join(path, fname)):
                try:
                    import pwd
                    pwd.getpwnam(fname)
                    count += 1
                except Exception:
                    continue
        return count
    except Exception:
        return 0


def get_openvpn_user_count():
    """Return number of entries in /etc/openvpn/users.txt (non-empty lines)."""
    try:
        path = '/etc/openvpn/users.txt'
        if not os.path.isfile(path):
            return 0
        with open(path, 'r') as f:
            return sum(1 for line in f if line.strip())
    except Exception:
        return 0


def is_username_taken_openvpn(username):
    """True if the given OpenVPN username already exists in users.txt."""
    try:
        username = str(username or '').strip()
        if not username:
            return False
        candidates = {username}
        if username.startswith("FUJI-"):
            stripped = username[5:]
            if stripped:
                candidates.add(stripped)
        else:
            candidates.add(f"FUJI-{username}")
        path = '/etc/openvpn/users.txt'
        if not os.path.isfile(path):
            return False
        with open(path, 'r') as f:
            for line in f:
                entry_username = line.strip().split(':', 1)[0]
                if entry_username in candidates:
                    return True
    except Exception:
        pass
    return False


def cleanup_openvpn_expired_users():
    """Remove expired users from /etc/openvpn/users.txt.

    This is invoked on each request so that stale accounts are purged
    automatically.  Expiry value of 0 means never expire.
    """
    path = '/etc/openvpn/users.txt'
    now = int(time.time())
    try:
        if not os.path.isfile(path):
            return
        kept = []
        with open(path, 'r') as f:
            for line in f:
                parts = line.strip().split(':')
                if len(parts) >= 3:
                    try:
                        exp = int(parts[2])
                    except Exception:
                        exp = 0
                    if exp == 0 or exp > now:
                        kept.append(line.strip())
                else:
                    kept.append(line.strip())
        with open(path, 'w') as f:
            for l in kept:
                f.write(l + "\n")
    except Exception:
        pass

def get_vless_user_count():
    try:
        config_path = "/etc/xray/config.json"
        with open(config_path, "r") as f:
            config = json.load(f)
        usernames = set()
        for inbound in config.get("inbounds", []):
            if inbound.get("protocol") == "vless" and "clients" in inbound.get("settings", {}):
                for client in inbound["settings"]["clients"]:
                    email = client.get("email", "")
                    uname = email.split("|")[0]
                    if uname not in ("vless-ws-nontls", "vless-ws-tls"):
                        usernames.add(uname)
        return len(usernames)
    except Exception:
        return 0

def add_vless_user(username, days=None):
    config_path = "/etc/xray/config.json"
    username = username.strip().lower()
    norm_input = normalize_username(username)
    try:
        with open(config_path, "r") as f:
            config = json.load(f)
        existing_usernames = set()
        for inbound in config.get("inbounds", []):
            if inbound.get("protocol") == "vless" and "clients" in inbound.get("settings", {}):
                for client in inbound["settings"]["clients"]:
                    email = client.get("email", "")
                    uname = email.split("|")[0]
                    norm_existing = normalize_username(uname)
                    existing_usernames.add(norm_existing)
        if norm_input in existing_usernames:
            return None, None, "Username already exists."
        if days is None:
            days = get_create_account_expiry('vless')
        days = max(1, int(days))
        exp_seconds = days * 86400
        exp_timestamp = int(time.time()) + exp_seconds
        email_exp = f"{username}|{exp_timestamp}"
        # Use the username as the client id instead of generating UUIDs
        uuid1 = username
        uuid2 = username
        found_10001 = found_10002 = False
        for inbound in config.get("inbounds", []):
            if inbound.get("protocol") == "vless" and "clients" in inbound.get("settings", {}):
                port = inbound.get("port")
                if str(port) == "10001":
                    inbound["settings"]["clients"].append({"id": uuid1, "level": 0, "email": email_exp})
                    found_10001 = True
                elif str(port) == "10002":
                    inbound["settings"]["clients"].append({"id": uuid2, "level": 0, "email": email_exp})
                    found_10002 = True

        if not (found_10001 and found_10002):
            return None, None, "VLESS inbounds on port 10001 and 10002 not found in config.json"

        with open(config_path, "w") as f:
            json.dump(config, f, indent=2)
        # --- Delay restart by 5 seconds ---
        threading.Thread(target=lambda: (time.sleep(5), subprocess.call(["systemctl", "restart", "xray"]))).start()

        # --- Fix scheduled removal: remove user from both 10001 and 10002 ---
        if subprocess.call(['/usr/bin/which', 'at'], stdout=subprocess.DEVNULL) == 0:
            remove_cmd = (
                f"/usr/bin/python3 -c 'import json; "
                f"cfg=\"{config_path}\"; "
                f"u=\"{username}\"; "
                f"c=json.load(open(cfg)); "
                f"for ib in c.get(\"inbounds\",[]): "
                f"    if ib.get(\"protocol\")==\"vless\" and \"clients\" in ib.get(\"settings\",{{}}): "
                f"        ib[\"settings\"][\"clients\"] = [cl for cl in ib[\"settings\"][\"clients\"] if cl.get(\"email\",\"\" ).split(\"|\")[0] != u]; "
                f"json.dump(c, open(cfg,\"w\"), indent=2)' && "
                f"/usr/bin/systemctl restart xray"
            )
            subprocess.call(
                f"echo \"{remove_cmd}\" | /usr/bin/at now + {days} days",
                shell=True
            )
        # --- End schedule ---
        return uuid2, uuid1, None
    except Exception as e:
        return None, None, str(e)

def get_vless_links(username, uuid_tls, uuid_nontls, domain):
    link_tls = f"vless://{uuid_tls}@{domain}:443?encryption=none&type=ws&security=tls&host={domain}&path=/vless#{username}"
    link_nontls = f"vless://{uuid_nontls}@{domain}:80?encryption=none&type=ws&host={domain}&path=/vless#{username}"
    return link_tls, link_nontls

def get_service_status(service_name):
    try:
        result = subprocess.check_output(
            ["systemctl", "is-active", service_name],
            stderr=subprocess.DEVNULL
        ).decode().strip()
        return result == "active"
    except Exception:
        return False

# ---------- Admin/user management helpers ----------

def cancel_at_jobs_containing(token):
    """Remove scheduled at(1) jobs that reference a specific token (e.g., username)."""
    try:
        # Ensure atq exists
        if subprocess.call(['/usr/bin/which', 'atq'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
            return
        queue = subprocess.check_output(['atq'], stderr=subprocess.DEVNULL).decode().strip().splitlines()
        for line in queue:
            parts = line.split()
            if not parts:
                continue
            job_id = parts[0]
            try:
                detail = subprocess.check_output(['at', '-c', job_id], stderr=subprocess.DEVNULL).decode()
                if token in detail:
                    subprocess.call(['atrm', job_id], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                continue
    except Exception:
        pass

def _extract_expiry(text):
    try:
        m = re.search(r'(\d+)', str(text))
        if m:
            return int(m.group(1))
    except Exception:
        pass
    return 0

def _expiry_label(ts):
    if not ts or ts <= 0:
        return "never"
    try:
        return datetime.fromtimestamp(int(ts)).strftime("%b %d, %Y %I:%M %p")
    except Exception:
        return str(ts)

def _days_left(ts):
    if not ts or ts <= 0:
        return "∞"
    now_ts = int(time.time())
    if ts <= now_ts:
        return "0"
    return str((ts - now_ts) // 86400)

def list_ssh_accounts():
    accounts = []
    path = '/var/lib/regular_users'
    if not os.path.isdir(path):
        return accounts
    for fname in os.listdir(path):
        fpath = os.path.join(path, fname)
        if not os.path.isfile(fpath):
            continue
        try:
            with open(fpath, 'r') as f:
                raw = f.read()
            expiry = _extract_expiry(raw)
        except Exception:
            expiry = 0
        accounts.append({'service': 'ssh', 'username': fname, 'expiry': expiry})
    return accounts

def list_vless_accounts():
    accounts = {}
    config_path = "/etc/xray/config.json"
    try:
        with open(config_path, "r") as f:
            config = json.load(f)
        for inbound in config.get("inbounds", []):
            if inbound.get("protocol") == "vless" and "clients" in inbound.get("settings", {}):
                for client in inbound["settings"]["clients"]:
                    email = client.get("email", "")
                    uname = email.split("|")[0]
                    if uname in ("vless-ws-nontls", "vless-ws-tls"):
                        continue
                    parts = email.split("|")
                    expiry = 0
                    if len(parts) > 1:
                        try:
                            expiry = int(parts[1])
                        except Exception:
                            expiry = 0
                    if uname not in accounts or expiry > accounts[uname]["expiry"]:
                        accounts[uname] = {"service": "vless", "username": uname, "expiry": expiry}
    except Exception:
        pass
    return list(accounts.values())

def list_hysteria_accounts():
    accounts = []
    try:
        import sqlite3
        db_path = "/etc/hysteria/udpusers.db"
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute("CREATE TABLE IF NOT EXISTS users (username TEXT, password TEXT, expiry INTEGER);")
        c.execute("SELECT username, expiry FROM users;")
        for username, expiry in c.fetchall():
            accounts.append({"service": "hysteria", "username": username, "expiry": int(expiry)})
        conn.close()
    except Exception:
        pass
    return accounts

def list_openvpn_accounts():
    accounts = []
    path = '/etc/openvpn/users.txt'
    try:
        if not os.path.isfile(path):
            return accounts
        with open(path, 'r') as f:
            for line in f:
                parts = line.strip().split(':')
                if len(parts) >= 3:
                    username = parts[0]
                    try:
                        expiry = int(parts[2])
                    except Exception:
                        expiry = 0
                    accounts.append({"service": "openvpn", "username": username, "expiry": expiry})
    except Exception:
        pass
    return accounts

def list_all_accounts():
    accounts = list_ssh_accounts() + list_vless_accounts() + list_hysteria_accounts() + list_openvpn_accounts()
    return sorted(accounts, key=lambda a: (a["service"], a["username"]))

def remove_ssh_account(username):
    cancel_at_jobs_containing(username)
    try:
        subprocess.call(['/usr/sbin/userdel', '-r', username], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass
    try:
        os.remove(f"/var/lib/regular_users/{username}")
    except Exception:
        pass
    return True, "SSH account removed."

def remove_vless_account(username):
    config_path = "/etc/xray/config.json"
    changed = False
    try:
        with open(config_path, "r") as f:
            config = json.load(f)
        for inbound in config.get("inbounds", []):
            if inbound.get("protocol") == "vless" and "clients" in inbound.get("settings", {}):
                clients = inbound["settings"]["clients"]
                new_clients = [c for c in clients if c.get("email", "").split("|")[0] != username]
                if len(new_clients) != len(clients):
                    changed = True
                inbound["settings"]["clients"] = new_clients
        if changed:
            with open(config_path, "w") as f:
                json.dump(config, f, indent=2)
            subprocess.call(["systemctl", "restart", "xray"])
        cancel_at_jobs_containing(username)
        return True, "VLESS account removed." if changed else "No VLESS entries found for that user."
    except Exception as e:
        return False, str(e)

def remove_hysteria_account(username):
    try:
        import sqlite3
        db_path = "/etc/hysteria/udpusers.db"
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute("DELETE FROM users WHERE username=?", (username,))
        removed = c.rowcount > 0
        conn.commit()
        conn.close()
        if removed:
            update_hysteria_userpass_config()
            subprocess.call(["systemctl", "restart", "hysteria-v1.service"])
        cancel_at_jobs_containing(username)
        return True, "Hysteria account removed." if removed else "User not found in Hysteria."
    except Exception as e:
        return False, str(e)

def remove_openvpn_account(username):
    path = '/etc/openvpn/users.txt'
    changed = False
    try:
        if os.path.isfile(path):
            kept = []
            with open(path, 'r') as f:
                for line in f:
                    if not line.strip().startswith(f"{username}:"):
                        kept.append(line.strip())
                    else:
                        changed = True
            with open(path, 'w') as f:
                for l in kept:
                    f.write(l + "\n")
        # Remove generated ovpn file if present
        ovpn_path = f"/etc/openvpn/{username}.ovpn"
        if os.path.isfile(ovpn_path):
            try:
                os.remove(ovpn_path)
            except Exception:
                pass
        return True, "OpenVPN account removed." if changed else "User not found in OpenVPN."
    except Exception as e:
        return False, str(e)

def update_ssh_expiry(username, days):
    try:
        new_expiry = int(time.time()) + int(days) * 86400
    except Exception:
        return False, "Invalid days value."
    try:
        path = f"/var/lib/regular_users/{username}"
        if not os.path.isfile(path):
            return False, "SSH user not found."
        with open(path, 'w') as f:
            f.write(str(new_expiry))
        cancel_at_jobs_containing(username)
        return True, "SSH expiry updated."
    except Exception as e:
        return False, str(e)

def update_vless_expiry(username, days):
    config_path = "/etc/xray/config.json"
    try:
        new_expiry = int(time.time()) + int(days) * 86400
    except Exception:
        return False, "Invalid days value."
    try:
        with open(config_path, "r") as f:
            config = json.load(f)
        found = False
        for inbound in config.get("inbounds", []):
            if inbound.get("protocol") == "vless" and "clients" in inbound.get("settings", {}):
                for client in inbound["settings"]["clients"]:
                    email = client.get("email", "")
                    uname = email.split("|")[0]
                    if uname == username:
                        client["email"] = f"{username}|{new_expiry}"
                        found = True
        if not found:
            return False, "VLESS user not found."
        with open(config_path, "w") as f:
            json.dump(config, f, indent=2)
        cancel_at_jobs_containing(username)
        subprocess.call(["systemctl", "restart", "xray"])
        return True, "VLESS expiry updated."
    except Exception as e:
        return False, str(e)

def update_hysteria_expiry(username, days):
    try:
        import sqlite3
        new_expiry = int(time.time()) + int(days) * 86400
        db_path = "/etc/hysteria/udpusers.db"
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute("UPDATE users SET expiry=? WHERE username=?", (new_expiry, username))
        updated = c.rowcount > 0
        conn.commit()
        conn.close()
        if not updated:
            return False, "Hysteria user not found."
        update_hysteria_userpass_config()
        cancel_at_jobs_containing(username)
        subprocess.call(["systemctl", "restart", "hysteria-v1.service"])
        return True, "Hysteria expiry updated."
    except Exception as e:
        return False, str(e)

def update_openvpn_expiry(username, days):
    path = '/etc/openvpn/users.txt'
    try:
        new_expiry = int(time.time()) + int(days) * 86400 if int(days) > 0 else 0
    except Exception:
        return False, "Invalid days value."
    try:
        if not os.path.isfile(path):
            return False, "OpenVPN users file missing."
        changed = False
        lines = []
        with open(path, 'r') as f:
            for line in f:
                parts = line.strip().split(':')
                if len(parts) >= 3 and parts[0] == username:
                    parts[2] = str(new_expiry)
                    changed = True
                    lines.append(':'.join(parts))
                else:
                    lines.append(line.strip())
        if not changed:
            return False, "OpenVPN user not found."
        with open(path, 'w') as f:
            for l in lines:
                f.write(l + "\n")
        return True, "OpenVPN expiry updated."
    except Exception as e:
        return False, str(e)

def perform_user_removal(service, username):
    if service == "ssh":
        return remove_ssh_account(username)
    if service == "vless":
        return remove_vless_account(username)
    if service == "hysteria":
        return remove_hysteria_account(username)
    if service == "openvpn":
        return remove_openvpn_account(username)
    return False, "Unknown service."

def perform_expiry_update(service, username, days):
    if service == "ssh":
        return update_ssh_expiry(username, days)
    if service == "vless":
        return update_vless_expiry(username, days)
    if service == "hysteria":
        return update_hysteria_expiry(username, days)
    if service == "openvpn":
        return update_openvpn_expiry(username, days)
    return False, "Unknown service."

def admin_login_content(error=None):
    error_html = ""
    if error:
        error_html = f"""
    <div class="admin-alert error">
      <i class="fa-solid fa-triangle-exclamation"></i>
      <div>{html.escape(error)}</div>
    </div>"""
    return f"""
<style>
  .admin-shell {{ max-width:620px; margin:0 auto; }}
  .admin-card {{ background: linear-gradient(145deg, #121a2f 0%, #0e1525 100%); border:1px solid rgba(255,255,255,0.06); border-radius:18px; padding:1.6rem; box-shadow:0 18px 45px rgba(0,0,0,0.35); }}
  .admin-head {{ display:flex; align-items:center; gap:12px; margin-bottom:1rem; }}
  .admin-badge {{ height:46px; width:46px; border-radius:14px; background:rgba(6,182,212,0.16); border:1px solid rgba(6,182,212,0.28); display:flex; align-items:center; justify-content:center; }}
  .admin-sub {{ color:var(--text-muted); font-size:0.95rem; }}
  .admin-alert {{ display:flex; align-items:center; gap:10px; padding:12px 14px; border-radius:12px; border:1px solid rgba(255,255,255,0.08); background:rgba(255,255,255,0.04); margin-bottom:1rem; }}
  .admin-alert.error {{ border-color:rgba(239,68,68,0.35); background:rgba(239,68,68,0.12); color:var(--error); }}
  .admin-form {{ display:grid; gap:1rem; }}
  .admin-label {{ display:flex; align-items:center; gap:8px; color:var(--text-secondary); font-weight:600; margin-bottom:0.35rem; }}
  .admin-input {{ width:100%; background:rgba(255,255,255,0.03); border:1px solid rgba(255,255,255,0.08); padding:12px 14px; border-radius:12px; color:var(--text-primary); font-size:1rem; transition:var(--transition); }}
  .admin-input:focus {{ border-color:var(--primary-color); box-shadow:0 0 0 2px rgba(0,170,255,0.18); outline:none; }}
  .admin-btn-primary {{ width:100%; display:inline-flex; justify-content:center; align-items:center; gap:10px; padding:12px 16px; border-radius:12px; border:1px solid rgba(0,170,255,0.35); background:linear-gradient(135deg,#00aaff 0%,#22d3ee 100%); color:#fff; font-weight:700; cursor:pointer; box-shadow:var(--glow-primary); }}
  .admin-btn-primary:hover {{ transform:translateY(-1px); box-shadow:0 12px 28px rgba(0,170,255,0.26); }}
</style>
<div class="container admin-shell">
  <div class="admin-card">
    <div class="admin-head">
      <div class="admin-badge"><i class="fa-solid fa-lock" style="color:var(--accent-color);font-size:1.1rem;"></i></div>
      <div>
        <h2 class="section-title" style="margin:0;font-size:1.6rem;">Admin Login</h2>
        <div class="admin-sub">Sign in with the server's root credentials to manage users.</div>
      </div>
    </div>
    {error_html}
    <form method="POST" action="/admin/" class="admin-form">
      <input type="hidden" name="action" value="login">
      <div>
        <label class="admin-label" for="admin-username"><i class="fa-solid fa-user-shield"></i> Username</label>
        <input class="admin-input" id="admin-username" name="username" type="text" required placeholder="root">
      </div>
      <div>
        <label class="admin-label" for="admin-password"><i class="fa-solid fa-key"></i> Password</label>
        <input class="admin-input" id="admin-password" name="password" type="password" required placeholder="Server root password">
      </div>
      <button type="submit" class="admin-btn-primary">
        <i class="fa-solid fa-right-to-bracket"></i> Sign In
      </button>
    </form>
  </div>
</div>
"""

def admin_dashboard_content(accounts, limit_val, success=None, error=None):
    now_ts = int(time.time())
    msg_html = ""
    create_expiry = get_create_account_expiry()
    metrics = build_admin_usage_metrics(accounts, limit_val)
    audit_events = get_recent_admin_events(14)
    if success:
        msg_html = f"""
    <div class="admin-alert success">
      <i class="fa-solid fa-circle-check"></i>
      <div>{html.escape(success)}</div>
    </div>"""
    elif error:
        msg_html = f"""
    <div class="admin-alert error">
      <i class="fa-solid fa-triangle-exclamation"></i>
      <div>{html.escape(error)}</div>
    </div>"""
    rows = ""
    service_counts = {"ssh": 0, "vless": 0, "hysteria": 0, "openvpn": 0}
    for acct in accounts:
        svc = acct.get('service')
        if svc in service_counts:
            service_counts[svc] += 1
    summary_cards = ""
    usage_meta = [
        ("Total Accounts", metrics["total"], "fa-users"),
        ("Active", metrics["active"], "fa-user-check"),
        ("Expired", metrics["expired"], "fa-user-clock"),
        ("Expiring Soon", metrics["expiring_soon"], "fa-hourglass-half"),
        ("Created Today", sum(metrics["created_today"].values()), "fa-chart-line"),
        ("Remaining Today", metrics["remaining_today"], "fa-layer-group"),
    ]
    for label, value, icon in usage_meta:
        summary_cards += f"""
      <div class="admin-stat-card">
        <div class="admin-stat-icon"><i class="fa-solid {icon}"></i></div>
        <div>
          <div class="admin-stat-label">{html.escape(str(label))}</div>
          <div class="admin-stat-value">{html.escape(str(value))}</div>
        </div>
      </div>"""
    protocol_cards = ""
    service_meta = [
        ("ssh", "SSH", "fa-terminal"),
        ("vless", "VLESS", "fa-bolt"),
        ("hysteria", "Hysteria", "fa-signal"),
        ("openvpn", "OpenVPN", "fa-shield-halved"),
    ]
    for key, label, icon in service_meta:
        protocol_cards += f"""
      <div class="admin-stat-card">
        <div class="admin-stat-icon"><i class="fa-solid {icon}"></i></div>
        <div>
          <div class="admin-stat-label">{label}</div>
          <div class="admin-stat-value">{service_counts.get(key, 0)}</div>
          <div class="admin-stat-note">Today: {metrics['created_today'].get(key, 0)} | Default: {html.escape(format_days_label(create_expiry.get(key, 0)))}</div>
        </div>
      </div>"""
    for acct in accounts:
        expiry_val = int(acct.get('expiry', 0) or 0)
        if expiry_val <= 0:
            status_key = "never"
            status_label = "No expiry"
            expiry_sort = 9999999999
        elif expiry_val <= now_ts:
            status_key = "expired"
            status_label = "Expired"
            expiry_sort = expiry_val
        elif expiry_val - now_ts <= 3 * 86400:
            status_key = "soon"
            status_label = "Expiring soon"
            expiry_sort = expiry_val
        else:
            status_key = "active"
            status_label = "Active"
            expiry_sort = expiry_val
        rows += f"""
        <tr data-service="{html.escape(acct['service'])}" data-username="{html.escape(acct['username'].lower())}" data-status="{status_key}" data-expiry="{expiry_sort}">
          <td data-label="Service"><span class="pill pill-service">{html.escape(acct['service']).upper()}</span></td>
          <td data-label="Username" class="mono">{html.escape(acct['username'])}</td>
          <td data-label="Expires">{html.escape(_expiry_label(expiry_val))}</td>
          <td data-label="Days Left" style="text-align:center;">{html.escape(_days_left(expiry_val))}</td>
          <td data-label="Status"><span class="table-status {status_key}">{status_label}</span></td>
          <td data-label="Actions" class="actions-cell">
            <div class="action-stack">
            <form method="POST" action="/admin/" class="admin-inline-form">
              <input type="hidden" name="action" value="remove_user">
              <input type="hidden" name="service" value="{html.escape(acct['service'])}">
              <input type="hidden" name="username" value="{html.escape(acct['username'])}">
              <button type="submit" class="btn-ghost danger">
                <i class="fa-solid fa-user-slash"></i> Remove
              </button>
            </form>
            <form method="POST" action="/admin/" class="admin-inline-form">
              <input type="hidden" name="action" value="update_expiry">
              <input type="hidden" name="service" value="{html.escape(acct['service'])}">
              <input type="hidden" name="username" value="{html.escape(acct['username'])}">
              <div class="stepper">
                <button type="button" class="stepper-btn" data-step="-1">-</button>
                <input class="mini-input stepper-input" type="number" name="days" min="1" max="3650" value="3" required>
                <button type="button" class="stepper-btn" data-step="1">+</button>
              </div>
              <button type="submit" class="btn-ghost success">
                <i class="fa-solid fa-calendar-plus"></i> Set expiry
              </button>
            </form>
            </div>
          </td>
        </tr>"""
    if not rows:
        rows = "<tr><td colspan='6' style='text-align:center;color:var(--text-muted);padding:14px;'>No accounts found.</td></tr>"
    audit_html = ""
    for event in audit_events:
        raw_status = str(event.get("status", "info"))
        if raw_status in ("failed", "error"):
            status_class = "expired"
            status_label = "Failed"
        elif raw_status in ("warning", "warn"):
            status_class = "soon"
            status_label = "Warning"
        else:
            status_class = "active"
            status_label = "Success"
        detail_parts = []
        for key, value in event.get("details", {}).items():
            if value in (None, ""):
                continue
            label = str(key).replace("_", " ").title()
            detail_parts.append(f"{html.escape(label)}: {html.escape(str(value))}")
        detail_text = " | ".join(detail_parts) if detail_parts else "No extra details"
        audit_html += f"""
      <div class="audit-item">
        <div class="audit-top">
          <div>
            <div class="audit-action">{html.escape(str(event.get('action', 'unknown')).replace('_', ' ').title())}</div>
            <div class="audit-meta">{html.escape(event.get('time', '-'))} | {html.escape(event.get('actor', 'root'))} | {html.escape(event.get('ip', '-'))}</div>
          </div>
          <span class="table-status {status_class}">{status_label}</span>
        </div>
        <div class="audit-detail">{detail_text}</div>
      </div>"""
    if not audit_html:
        audit_html = "<div class='audit-empty'>No admin actions logged yet.</div>"
    script_block = """
<script>
(function() {
  const tableBody = document.querySelector('.admin-table tbody');
  const rows = tableBody ? Array.from(tableBody.querySelectorAll('tr[data-service]')) : [];
  const filterPills = Array.from(document.querySelectorAll('.pill-filter'));
  const searchInput = document.getElementById('adminUserSearch');
  const statusSelect = document.getElementById('adminStatusFilter');
  const sortSelect = document.getElementById('adminSortUsers');
  const visibleCounter = document.getElementById('visibleUserCount');
  let activeService = 'all';

  function matchStatus(rowStatus, selectedStatus) {
    if (selectedStatus === 'all') return true;
    if (selectedStatus === 'active') return rowStatus !== 'expired';
    return rowStatus === selectedStatus;
  }

  function expiryRank(row, descending) {
    const rowStatus = row.dataset.status || 'active';
    if (rowStatus === 'never') return descending ? -1 : 9999999999;
    const raw = parseInt(row.dataset.expiry || '0', 10);
    return isNaN(raw) ? (descending ? -1 : 9999999999) : raw;
  }

  function compareRows(a, b, mode) {
    const userA = a.dataset.username || '';
    const userB = b.dataset.username || '';
    const serviceA = a.dataset.service || '';
    const serviceB = b.dataset.service || '';
    if (mode === 'username_desc') return userB.localeCompare(userA);
    if (mode === 'expiry_soon') return expiryRank(a, false) - expiryRank(b, false) || userA.localeCompare(userB);
    if (mode === 'expiry_late') return expiryRank(b, true) - expiryRank(a, true) || userA.localeCompare(userB);
    if (mode === 'service') return serviceA.localeCompare(serviceB) || userA.localeCompare(userB);
    return userA.localeCompare(userB);
  }

  function applyUserFilters() {
    if (!tableBody) return;
    const query = (searchInput ? searchInput.value : '').trim().toLowerCase();
    const selectedStatus = statusSelect ? statusSelect.value : 'all';
    const sortMode = sortSelect ? sortSelect.value : 'service';
    const orderedRows = rows.slice().sort((a, b) => compareRows(a, b, sortMode));
    let visible = 0;
    orderedRows.forEach((row) => {
      const rowService = row.dataset.service || '';
      const rowUser = row.dataset.username || '';
      const rowStatus = row.dataset.status || 'active';
      const matchesService = activeService === 'all' || rowService === activeService;
      const matchesQuery = !query || rowUser.indexOf(query) !== -1;
      const matchesStatusValue = matchStatus(rowStatus, selectedStatus);
      const show = matchesService && matchesQuery && matchesStatusValue;
      row.style.display = show ? '' : 'none';
      tableBody.appendChild(row);
      if (show) visible += 1;
    });
    if (visibleCounter) visibleCounter.textContent = visible + ' shown';
  }

  filterPills.forEach((pill) => {
    pill.addEventListener('click', () => {
      filterPills.forEach((item) => item.classList.remove('active'));
      pill.classList.add('active');
      activeService = pill.dataset.filter || 'all';
      applyUserFilters();
    });
  });

  if (searchInput) searchInput.addEventListener('input', applyUserFilters);
  if (statusSelect) statusSelect.addEventListener('change', applyUserFilters);
  if (sortSelect) sortSelect.addEventListener('change', applyUserFilters);

  document.querySelectorAll('.stepper-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      const input = btn.parentElement.querySelector('.stepper-input');
      if (!input) return;
      const step = parseInt(btn.dataset.step, 10);
      const min = parseInt(input.min || '1', 10);
      const max = parseInt(input.max || '3650', 10);
      let val = parseInt(input.value || '0', 10);
      val = isNaN(val) ? min : val + step;
      if (val < min) val = min;
      if (val > max) val = max;
      input.value = val;
    });
  });

  document.querySelectorAll('.admin-select').forEach((select) => {
    const syncExpiryInput = () => {
      const option = select.options[select.selectedIndex];
      const days = option ? option.getAttribute('data-days') : '';
      const input = select.closest('form').querySelector('input[name="days"]');
      if (input && days) input.value = days;
    };
    if (select.name === 'service') {
      select.addEventListener('change', syncExpiryInput);
      syncExpiryInput();
    }
  });

  applyUserFilters();
})();
</script>
"""
    return f"""
<style>
  .admin-shell {{ max-width: 1120px; margin: 0 auto; }}
  .admin-page {{ position: relative; overflow: hidden; border: 1px solid rgba(82, 173, 255, 0.12); border-radius: 24px; padding: 1.4rem; background:
    radial-gradient(circle at top left, rgba(0, 170, 255, 0.12), transparent 30%),
    radial-gradient(circle at top right, rgba(34, 197, 94, 0.08), transparent 24%),
    linear-gradient(160deg, #0d1324 0%, #11182c 48%, #0b1020 100%);
    box-shadow: 0 22px 60px rgba(0, 0, 0, 0.42);
  }}
  .admin-page::before {{ content: ""; position: absolute; inset: 0; background:
    linear-gradient(90deg, rgba(255,255,255,0.03) 1px, transparent 1px),
    linear-gradient(rgba(255,255,255,0.02) 1px, transparent 1px);
    background-size: 32px 32px; opacity: 0.18; pointer-events: none;
  }}
  .admin-page > * {{ position: relative; z-index: 1; }}
  .admin-top {{ position: relative; z-index: 1; display: flex; align-items: flex-start; gap: 16px; justify-content: space-between; flex-wrap: wrap; }}
  .admin-title-block {{ display: flex; align-items: center; gap: 14px; }}
  .admin-logo {{ height: 54px; width: 54px; border-radius: 16px; display: flex; align-items: center; justify-content: center; color: #fff; background: linear-gradient(145deg, rgba(0,170,255,0.28), rgba(34,211,238,0.08)); border: 1px solid rgba(0,170,255,0.24); box-shadow: inset 0 1px 0 rgba(255,255,255,0.08), 0 12px 28px rgba(0,0,0,0.26); }}
  .admin-subtitle {{ color: var(--text-secondary); max-width: 520px; font-size: 0.98rem; }}
  .admin-section-head {{ display:flex; align-items:center; justify-content:space-between; gap:12px; flex-wrap:wrap; margin-bottom:0.85rem; }}
  .admin-headline {{ display:flex; align-items:center; gap:10px; }}
  .admin-counter-chip {{ display:inline-flex; align-items:center; gap:8px; padding:8px 12px; border-radius:999px; background:rgba(255,255,255,0.06); border:1px solid rgba(255,255,255,0.08); color:var(--text-primary); font-weight:700; }}
  .admin-stats {{ position: relative; z-index: 1; display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px; margin-top: 1.2rem; }}
  .admin-stat-card {{ background: linear-gradient(145deg, rgba(255,255,255,0.06), rgba(255,255,255,0.03)); border: 1px solid rgba(255,255,255,0.08); border-radius: 18px; padding: 14px; display: flex; align-items: center; gap: 12px; backdrop-filter: blur(6px); }}
  .admin-stat-icon {{ height: 42px; width: 42px; border-radius: 14px; display: flex; align-items: center; justify-content: center; background: rgba(0, 170, 255, 0.14); color: var(--accent-color); }}
  .admin-stat-label {{ color: var(--text-muted); font-size: 0.86rem; text-transform: uppercase; letter-spacing: 0.08em; }}
  .admin-stat-value {{ color: var(--text-primary); font-size: 1.55rem; font-weight: 800; line-height: 1; margin-top: 4px; }}
  .admin-stat-note {{ color: var(--text-secondary); font-size: 0.84rem; margin-top: 4px; }}
  .admin-grid {{ position: relative; z-index: 1; display: grid; gap: 16px; margin-top: 1rem; }}
  .admin-tool-grid {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 16px; }}
  .admin-panel {{ background: linear-gradient(145deg, rgba(17,24,39,0.86), rgba(15,23,42,0.78)); border: 1px solid rgba(255,255,255,0.08); border-radius: 20px; padding: 1.2rem; box-shadow: inset 0 1px 0 rgba(255,255,255,0.04); }}
  .admin-panel-head {{ display: flex; align-items: center; gap: 10px; margin-bottom: 0.85rem; }}
  .admin-panel-icon {{ height: 38px; width: 38px; border-radius: 12px; display: flex; align-items: center; justify-content: center; background: rgba(255,255,255,0.06); color: var(--accent-color); }}
  .admin-panel-title {{ margin: 0; color: var(--text-primary); font-size: 1.08rem; }}
  .admin-panel-note {{ color: var(--text-muted); font-size: 0.92rem; margin-top: 0.2rem; }}
  .pill {{ display: inline-flex; align-items: center; gap: 8px; padding: 7px 12px; border-radius: 999px; font-weight: 700; font-size: 0.88rem; }}
  .pill-service {{ background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.08); color: var(--text-primary); }}
  .pill-limit {{ background: rgba(0,170,255,0.14); border: 1px solid rgba(0,170,255,0.3); color: #9fddff; }}
  .pill-filter {{ cursor: pointer; transition: var(--transition); user-select: none; }}
  .pill-filter:hover {{ border-color: rgba(0,170,255,0.28); background: rgba(0,170,255,0.08); }}
  .pill-filter.active {{ background: linear-gradient(145deg, rgba(34,197,94,0.24), rgba(34,197,94,0.1)); border-color: rgba(34,197,94,0.4); color: #dfffea; }}
  .admin-alert {{ display: flex; align-items: center; gap: 10px; padding: 13px 14px; border-radius: 14px; border: 1px solid rgba(255,255,255,0.08); background: rgba(255,255,255,0.04); margin-top: 1rem; position: relative; z-index: 1; }}
  .admin-alert.success {{ border-color: rgba(34,197,94,0.35); background: rgba(34,197,94,0.12); color: #dfffea; }}
  .admin-alert.error {{ border-color: rgba(239,68,68,0.35); background: rgba(239,68,68,0.12); color: #ffe3e3; }}
  .admin-form-row {{ display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }}
  .admin-form-row > div[style*="font-size:0.94rem"] {{ display: none; }}
  .admin-field, .admin-select {{ height: 48px; border-radius: 14px; border: 1px solid rgba(255,255,255,0.1); background: linear-gradient(145deg, rgba(255,255,255,0.06), rgba(255,255,255,0.03)); color: #f8fafc; padding: 0 14px; font-size: 0.98rem; box-shadow: inset 0 1px 0 rgba(255,255,255,0.05); }}
  .admin-field:focus, .admin-select:focus, .stepper-input:focus {{ outline: none; border-color: rgba(0,170,255,0.45); box-shadow: 0 0 0 3px rgba(0,170,255,0.14); }}
  .admin-field {{ width: 128px; }}
  .select-wrap {{ position: relative; min-width: 210px; }}
  .admin-select {{ width: 100%; appearance: none; -webkit-appearance: none; -moz-appearance: none; padding-right: 44px; color-scheme: dark; cursor: pointer; }}
  .admin-select option {{ background: #12182a; color: #f8fafc; }}
  .admin-select option:checked {{ background: #1674d1; color: #ffffff; }}
  .select-arrow {{ position: absolute; right: 14px; top: 50%; transform: translateY(-50%); color: #d7e9ff; pointer-events: none; }}
  .btn-primary, .btn-outline, .btn-ghost {{ height: 48px; border-radius: 14px; padding: 0 16px; display: inline-flex; align-items: center; justify-content: center; gap: 9px; font-weight: 700; cursor: pointer; transition: var(--transition); }}
  .btn-primary {{ border: 1px solid rgba(0,170,255,0.38); background: linear-gradient(135deg, #00aaff 0%, #22d3ee 100%); color: #fff; box-shadow: 0 14px 28px rgba(0,170,255,0.18); }}
  .btn-primary:hover {{ transform: translateY(-1px); box-shadow: 0 16px 32px rgba(0,170,255,0.24); }}
  .btn-outline {{ border: 1px solid rgba(255,255,255,0.16); background: rgba(255,255,255,0.05); color: var(--text-primary); }}
  .btn-outline:hover {{ border-color: rgba(255,255,255,0.28); background: rgba(255,255,255,0.08); }}
  .btn-ghost {{ height: 42px; border: 1px solid rgba(255,255,255,0.12); background: rgba(255,255,255,0.06); color: #fff; }}
  .btn-ghost:hover {{ background: rgba(255,255,255,0.1); }}
  .btn-ghost.danger {{ border-color: rgba(239,68,68,0.42); background: linear-gradient(135deg, rgba(239,68,68,0.74), rgba(239,68,68,0.44)); }}
  .btn-ghost.success {{ border-color: rgba(34,197,94,0.42); background: linear-gradient(135deg, rgba(34,197,94,0.74), rgba(34,197,94,0.44)); }}
  .stepper {{ display: inline-flex; align-items: center; border: 1px solid rgba(255,255,255,0.14); border-radius: 16px; overflow: hidden; background: linear-gradient(145deg, rgba(17,24,39,0.96), rgba(30,41,59,0.94)); box-shadow: inset 0 1px 0 rgba(255,255,255,0.05), 0 10px 20px rgba(0,0,0,0.2); }}
  .stepper-input {{ width: 72px; height: 46px; border: none; background: transparent; text-align: center; padding: 0 6px; color: #fff; font-weight: 700; font-size: 1rem; }}
  .stepper-btn {{ width: 46px; height: 46px; background: rgba(255,255,255,0.04); border: none; color: #fff; cursor: pointer; font-weight: 800; font-size: 1.15rem; }}
  .stepper-btn:hover {{ background: rgba(0,170,255,0.12); }}
  .manage-toolbar {{ display:grid; grid-template-columns:minmax(0,1.2fr) minmax(0,0.8fr); gap:12px; margin-bottom:0.9rem; }}
  .search-wrap {{ display:flex; align-items:center; gap:10px; padding:0 14px; border-radius:16px; border:1px solid rgba(255,255,255,0.08); background:rgba(255,255,255,0.04); }}
  .search-wrap i {{ color: var(--text-secondary); }}
  .search-input {{ flex:1 1 auto; height:48px; width:100%; border:none; background:transparent; color:#f8fafc; font-size:0.98rem; }}
  .search-input:focus {{ outline:none; }}
  .manage-select-row {{ display:grid; grid-template-columns:repeat(2, minmax(0, 1fr)); gap:12px; }}
  .select-wrap.compact {{ min-width:0; }}
  .admin-table-wrap {{ overflow-x: auto; border-radius: 18px; border: 1px solid rgba(255,255,255,0.06); background: rgba(255,255,255,0.025); }}
  .admin-table {{ width: 100%; min-width: 860px; border-collapse: collapse; font-size: 0.95rem; }}
  .admin-table thead th {{ text-align: left; padding: 14px 12px; color: var(--text-secondary); font-size: 0.86rem; letter-spacing: 0.06em; text-transform: uppercase; border-bottom: 1px solid rgba(255,255,255,0.06); }}
  .admin-table tbody tr {{ border-bottom: 1px solid rgba(255,255,255,0.05); }}
  .admin-table tbody tr:last-child {{ border-bottom: none; }}
  .admin-table tbody tr:hover {{ background: rgba(255,255,255,0.04); }}
  .admin-table tbody td {{ padding: 14px 12px; vertical-align: middle; color: var(--text-primary); }}
  .admin-inline-form {{ display: inline-flex; align-items: center; gap: 8px; margin: 4px 8px 4px 0; }}
  .mini-input {{ color: #fff; }}
  .mono {{ font-family: ui-monospace, 'Cascadia Code', 'SF Mono', monospace; }}
  .actions-cell {{ min-width: 290px; }}
  .action-stack {{ display:flex; flex-direction:column; gap:8px; align-items:flex-start; }}
  .table-status {{ display:inline-flex; align-items:center; justify-content:center; min-width:92px; padding:8px 10px; border-radius:999px; font-size:0.82rem; font-weight:800; border:1px solid rgba(255,255,255,0.08); }}
  .table-status.active {{ background: rgba(34,197,94,0.14); border-color: rgba(34,197,94,0.34); color: #dfffea; }}
  .table-status.soon {{ background: rgba(251,191,36,0.15); border-color: rgba(251,191,36,0.38); color: #fff1bf; }}
  .table-status.expired {{ background: rgba(239,68,68,0.14); border-color: rgba(239,68,68,0.34); color: #ffe3e3; }}
  .table-status.never {{ background: rgba(0,170,255,0.14); border-color: rgba(0,170,255,0.3); color: #d8f3ff; }}
  .users-toolbar {{ display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap; margin-bottom: 0.9rem; }}
  .filter-row {{ display: flex; flex-wrap: wrap; gap: 8px; }}
  .audit-list {{ display:grid; gap:10px; }}
  .audit-item {{ padding:14px; border-radius:16px; border:1px solid rgba(255,255,255,0.07); background:rgba(255,255,255,0.04); }}
  .audit-top {{ display:flex; align-items:flex-start; justify-content:space-between; gap:12px; }}
  .audit-action {{ color: var(--text-primary); font-weight:700; }}
  .audit-meta {{ color: var(--text-muted); font-size:0.88rem; margin-top:4px; }}
  .audit-detail {{ color: var(--text-secondary); font-size:0.94rem; margin-top:10px; word-break:break-word; }}
  .audit-empty {{ padding:18px; border-radius:16px; border:1px dashed rgba(255,255,255,0.12); color:var(--text-muted); text-align:center; }}
  @media (max-width: 980px) {{
    .admin-stats {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
    .admin-tool-grid {{ grid-template-columns: 1fr; }}
    .manage-toolbar, .manage-select-row {{ grid-template-columns: 1fr; }}
  }}
  @media (max-width: 640px) {{
    .admin-page {{ padding: 1rem; border-radius: 20px; }}
    .admin-stats {{ grid-template-columns: 1fr; }}
    .admin-title-block {{ align-items: flex-start; }}
    .admin-form-row {{ align-items: stretch; }}
    .select-wrap, .admin-field {{ width: 100%; }}
    .btn-primary, .btn-outline {{ width: 100%; }}
    .admin-table thead {{ display:none; }}
    .admin-table, .admin-table tbody, .admin-table tr, .admin-table td {{ display:block; width:100%; min-width:0; }}
    .admin-table tbody {{ display:grid; gap:12px; padding:12px; }}
    .admin-table tbody tr {{ border:1px solid rgba(255,255,255,0.08); border-radius:16px; padding:12px; background:rgba(255,255,255,0.03); }}
    .admin-table tbody td {{ padding:8px 0; border-bottom:1px solid rgba(255,255,255,0.05); }}
    .admin-table tbody td:last-child {{ border-bottom:none; }}
    .admin-table tbody td::before {{ content: attr(data-label); display:block; color: var(--text-muted); font-size:0.74rem; letter-spacing:0.08em; text-transform:uppercase; margin-bottom:6px; }}
    .actions-cell, .action-stack, .admin-inline-form {{ width:100%; min-width:0; }}
    .admin-inline-form {{ display:flex; flex-direction:column; align-items:stretch; }}
    .btn-ghost {{ width:100%; }}
    .stepper {{ width:100%; justify-content:space-between; }}
    .stepper-input {{ flex:1 1 auto; width:auto; }}
    .audit-top {{ flex-direction:column; }}
  }}
</style>
<div class="container admin-shell">
  <div class="admin-page">
    <div class="admin-top">
      <div class="admin-title-block">
        <div class="admin-logo"><i class="fa-solid fa-screwdriver-wrench" style="font-size:1.25rem;"></i></div>
        <div>
          <h2 class="section-title" style="margin:0;font-size:1.7rem;">Admin Dashboard</h2>
          <div class="admin-subtitle">Manage per-protocol limits, default expiry for new accounts, live user filtering, and recent admin activity from one mobile-friendly panel.</div>
        </div>
      </div>
      <a href="/admin/logout" style="text-decoration:none;">
        <button type="button" class="btn-outline">
          <i class="fa-solid fa-arrow-right-from-bracket"></i> Logout
        </button>
      </a>
    </div>
    {msg_html}
    <div class="admin-section-head" style="margin-top:1rem;">
      <div class="admin-headline">
        <div class="admin-panel-icon"><i class="fa-solid fa-chart-pie"></i></div>
        <div>
          <h3 class="admin-panel-title">Usage Dashboard</h3>
          <div class="admin-panel-note">Quick view of account health, daily usage, and per-protocol defaults.</div>
        </div>
      </div>
      <div class="admin-counter-chip"><i class="fa-solid fa-calendar-day"></i> Philippine daily limit: {limit_val}</div>
    </div>
    <div class="admin-stats">
      {summary_cards}
    </div>
    <div class="admin-stats" style="margin-top:12px;">
      {protocol_cards}
    </div>
    <div class="admin-grid">
      <div class="admin-tool-grid">
      <div class="admin-panel">
        <div class="admin-panel-head">
          <div class="admin-panel-icon"><i class="fa-solid fa-chart-column"></i></div>
          <div>
            <h3 class="admin-panel-title">Daily Account Limit</h3>
            <div class="admin-panel-note">Controls how many accounts each protocol can create per day.</div>
          </div>
        </div>
        <form method="POST" action="/admin/" class="admin-form-row">
          <input type="hidden" name="action" value="update_limit">
          <input class="admin-field" type="number" name="limit" min="1" max="999" value="{limit_val}">
          <button type="submit" class="btn-primary"><i class="fa-solid fa-save"></i> Save Limit</button>
          <span class="pill pill-limit">Philippine time reset</span>
        </form>
      </div>
      <div class="admin-panel">
        <div class="admin-panel-head">
          <div class="admin-panel-icon"><i class="fa-solid fa-calendar-plus"></i></div>
          <div>
            <h3 class="admin-panel-title">Create Account Expiration</h3>
            <div class="admin-panel-note">Sets the default expiry for newly created accounts in the selected protocol only.</div>
          </div>
        </div>
        <form method="POST" action="/admin/" class="admin-form-row">
          <input type="hidden" name="action" value="update_create_expiry">
            <div class="select-wrap">
              <select name="service" class="admin-select">
                <option value="ssh" data-days="{create_expiry.get('ssh', 5)}">SSH</option>
                <option value="vless" data-days="{create_expiry.get('vless', 3)}">VLESS</option>
                <option value="hysteria" data-days="{create_expiry.get('hysteria', 5)}">Hysteria</option>
                <option value="openvpn" data-days="{create_expiry.get('openvpn', 3)}">OpenVPN</option>
              </select>
              <span class="select-arrow"><i class="fa-solid fa-chevron-down"></i></span>
            </div>
            <div class="stepper">
              <button type="button" class="stepper-btn" data-step="-1">-</button>
              <input class="stepper-input" type="number" name="days" min="1" max="3650" value="{create_expiry.get('ssh', 5)}" required>
              <button type="button" class="stepper-btn" data-step="1">+</button>
            </div>
          <button type="submit" class="btn-primary"><i class="fa-solid fa-wand-magic-sparkles"></i> Save Default</button>
        </form>
      </div>
      </div>
      <div class="admin-panel">
        <div class="users-toolbar">
          <div class="admin-panel-head" style="margin-bottom:0;">
            <div class="admin-panel-icon"><i class="fa-solid fa-users-gear"></i></div>
            <div>
              <h3 class="admin-panel-title">Manage Users</h3>
              <div class="admin-panel-note">Search usernames, filter by protocol or status, and sort accounts without leaving the page.</div>
            </div>
          </div>
          <div class="admin-counter-chip" id="visibleUserCount">{len(accounts)} shown</div>
        </div>
        <div class="manage-toolbar">
          <label class="search-wrap" for="adminUserSearch">
            <i class="fa-solid fa-magnifying-glass"></i>
            <input id="adminUserSearch" class="search-input" type="search" placeholder="Search username">
          </label>
          <div class="manage-select-row">
            <div class="select-wrap compact">
              <select id="adminStatusFilter" class="admin-select">
                <option value="all">All status</option>
                <option value="active">Active</option>
                <option value="soon">Expiring soon</option>
                <option value="expired">Expired</option>
                <option value="never">No expiry</option>
              </select>
              <span class="select-arrow"><i class="fa-solid fa-filter"></i></span>
            </div>
            <div class="select-wrap compact">
              <select id="adminSortUsers" class="admin-select">
                <option value="service">Sort: service</option>
                <option value="username_asc">Sort: username A-Z</option>
                <option value="username_desc">Sort: username Z-A</option>
                <option value="expiry_soon">Sort: nearest expiry</option>
                <option value="expiry_late">Sort: latest expiry</option>
              </select>
              <span class="select-arrow"><i class="fa-solid fa-arrow-down-wide-short"></i></span>
            </div>
          </div>
        </div>
        <div class="filter-row">
          <span class="pill pill-service pill-filter active" data-filter="all">All ({len(accounts)})</span>
          <span class="pill pill-service pill-filter" data-filter="ssh">SSH ({service_counts.get('ssh',0)})</span>
          <span class="pill pill-service pill-filter" data-filter="vless">VLESS ({service_counts.get('vless',0)})</span>
          <span class="pill pill-service pill-filter" data-filter="hysteria">Hysteria ({service_counts.get('hysteria',0)})</span>
          <span class="pill pill-service pill-filter" data-filter="openvpn">OpenVPN ({service_counts.get('openvpn',0)})</span>
        </div>
        <div class="admin-table-wrap">
        <table class="admin-table">
          <thead>
            <tr>
              <th>Service</th>
              <th>Username</th>
              <th>Expires</th>
              <th>Days Left</th>
              <th>Status</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {rows}
          </tbody>
        </table>
        </div>
      </div>
      <div class="admin-panel">
        <div class="users-toolbar">
          <div class="admin-panel-head" style="margin-bottom:0;">
            <div class="admin-panel-icon"><i class="fa-solid fa-clipboard-list"></i></div>
            <div>
              <h3 class="admin-panel-title">Audit Log</h3>
              <div class="admin-panel-note">Latest admin logins, account actions, and settings changes.</div>
            </div>
          </div>
          <div class="admin-counter-chip"><i class="fa-solid fa-clock-rotate-left"></i> Last {len(audit_events) if audit_events else 0} events</div>
        </div>
        <div class="audit-list">
          {audit_html}
        </div>
      </div>
    </div>
  </div>
</div>
{script_block}
"""

def cleanup_dnstt_expired_users():
    path = '/var/lib/regular_users'
    now = int(time.time())
    if not os.path.isdir(path):
        return
    for fname in os.listdir(path):
        fpath = os.path.join(path, fname)
        if not os.path.isfile(fpath):
            continue
        try:
            with open(fpath, 'r') as f:
                raw = f.read().strip()
            # try to find a numeric timestamp; if none found, treat as "no expiry" -> delete
            m = re.search(r'(\d+)', raw)
            if m:
                try:
                    expiry = int(m.group(1))
                except Exception:
                    expiry = 0
                should_delete = (expiry < now)
            else:
                # No timestamp found -> delete per request
                should_delete = True

            if should_delete:
                # Attempt to remove system user (ignore errors) then remove file
                try:
                    subprocess.call(['/usr/sbin/userdel', '-r', fname], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                except Exception as e:
                    logging.debug(f"cleanup_dnstt_expired_users: userdel failed for {fname}: {e}")
                try:
                    os.remove(fpath)
                except Exception as e:
                    logging.debug(f"cleanup_dnstt_expired_users: failed to remove {fpath}: {e}")
        except Exception as e:
            # If we couldn't read the file, still attempt to remove user and file
            logging.debug(f"cleanup_dnstt_expired_users: error reading {fpath}: {e}")
            try:
                subprocess.call(['/usr/sbin/userdel', '-r', fname], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception as e2:
                logging.debug(f"cleanup_dnstt_expired_users: userdel failed for {fname}: {e2}")
            try:
                os.remove(fpath)
            except Exception as e3:
                logging.debug(f"cleanup_dnstt_expired_users: failed to remove {fpath}: {e3}")

def cleanup_vless_expired_users():
    config_path = "/etc/xray/config.json"
    now = int(time.time())
    changed = False
    try:
        with open(config_path, "r") as f:
            config = json.load(f)
        for inbound in config.get("inbounds", []):
            if inbound.get("protocol") == "vless" and "clients" in inbound.get("settings", {}):
                clients = inbound["settings"]["clients"]
                new_clients = []
                for client in clients:
                    email = client.get("email", "")
                    parts = email.split("|")
                    if len(parts) == 2:
                        try:
                            exp = int(parts[1])
                            if exp >= now:
                                new_clients.append(client)
                            else:
                                changed = True
                        except Exception:
                            new_clients.append(client)
                    else:
                        new_clients.append(client)
                inbound["settings"]["clients"] = new_clients
        if changed:
            with open(config_path, "w") as f:
                json.dump(config, f, indent=2)
            subprocess.call(["systemctl", "restart", "xray"])
    except Exception:
        pass

def cleanup_hysteria_expired_users():
    import sqlite3
    db_path = "/etc/hysteria/udpusers.db"
    config_path = "/etc/hysteria/config.json"
    now = int(time.time())
    changed = False
    try:
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute("CREATE TABLE IF NOT EXISTS users (username TEXT, password TEXT, expiry INTEGER);")
        c.execute("SELECT username, expiry FROM users;")
        users = c.fetchall()
        for username, expiry in users:
            if expiry < now:
                c.execute("DELETE FROM users WHERE username=?", (username,))
                changed = True
        conn.commit()
        conn.close()
        if changed:
            update_hysteria_userpass_config()
            subprocess.call(["systemctl", "restart", "hysteria-v1.service"])
    except Exception:
        pass


def is_username_taken_ssh(username):
    # DNSTT: check /var/lib/regular_users AND system user exists
    dnstt_path = f'/var/lib/regular_users/{username}'
    if not os.path.exists(dnstt_path):
        return False
    try:
        import pwd
        pwd.getpwnam(username)
        return True                 
    except Exception:
        # If file exists but system user does not, treat as not taken
        return False

def normalize_username(username):
    # Lowercase, remove spaces and special chars (_ - .)
    return re.sub(r'[\s_\-\.]', '', username.strip().lower())

def is_username_taken_vless(username):
    try:
        config_path = "/etc/xray/config.json"
        with open(config_path, "r") as f:
            config = json.load(f)
        norm_input = normalize_username(username)
        for inbound in config.get("inbounds", []):
            if inbound.get("protocol") == "vless" and "clients" in inbound.get("settings", {}):
                for client in inbound["settings"]["clients"]:
                    email = client.get("email", "")
                    uname = email.split("|")[0]
                    norm_existing = normalize_username(uname)
                    if norm_existing == norm_input:
                        return True
    except Exception:
        pass
    return False

def is_username_taken_hysteria(username):
    try:
        import sqlite3
        db_path = "/etc/hysteria/udpusers.db"
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute("CREATE TABLE IF NOT EXISTS users (username TEXT, password TEXT, expiry INTEGER);")
        c.execute("SELECT COUNT(*) FROM users WHERE username=?", (username,))
        exists = c.fetchone()[0] > 0
        conn.close()
        return exists
    except Exception:
        pass
    return False

def get_online_user_count():
    try:
        # SSHD (exclude root, priv processes)
        f = int(subprocess.check_output("ps -x | grep sshd | grep -v root | grep priv | wc -l", shell=True).decode().strip())
    except Exception:
        f = 0
    try:
        # Dropbear (subtract 1 if count > 0)
        g = int(subprocess.check_output("ps aux | grep dropbear | grep -v grep | wc -l", shell=True).decode().strip())
        g = g - 1 if g > 0 else 0
    except Exception:
        g = 0
    try:
        # OpenVPN (count lines with 10.8.0 in status log)
        h = int(subprocess.check_output("grep -c \"10.8.0\" /etc/openvpn/openvpn-status.log 2>/dev/null || echo \"0\"", shell=True).decode().strip())
    except Exception:
        h = 0
    return f + g + h

def get_server_location():
    try:
        import urllib.request
        with urllib.request.urlopen("http://ip-api.com/json/", timeout=2) as r:
            data = json.load(r)
            country = data.get("country", "Unknown")
            country_code = data.get("countryCode", "")
            city = data.get("city", "")
            return country, country_code, city
    except Exception:
        return "Unknown", "", ""

def flag_image_url(country_code):
    # Returns SVG flag image URL from flagcdn.com
    if not country_code or len(country_code) != 2:
        return ""
    return f"https://flagcdn.com/48x36/{country_code.lower()}.png"

account_cooldown = {}
cooldown_lock = threading.Lock()
COOLDOWN_SECONDS = 600  # 10 minutes

def is_on_cooldown(ip, endpoint):
    now = time.time()
    key = f"{ip}:{endpoint}"
    with cooldown_lock:
        last = account_cooldown.get(key, 0)
        if now - last < COOLDOWN_SECONDS:
            return int(COOLDOWN_SECONDS - (now - last))
        return 0

def set_cooldown(ip, endpoint):
    key = f"{ip}:{endpoint}"
    with cooldown_lock:
        account_cooldown[key] = time.time()

class Handler(http.server.SimpleHTTPRequestHandler):
    @staticmethod
    def _is_client_disconnect(exc):
        return isinstance(
            exc, (BrokenPipeError, ConnectionResetError, ConnectionAbortedError)
        ) or getattr(exc, "errno", None) in {
            errno.EPIPE,
            errno.ECONNRESET,
            errno.ECONNABORTED,
        }

    def handle_one_request(self):
        try:
            super().handle_one_request()
        except OSError as exc:
            if self._is_client_disconnect(exc):
                self.close_connection = True
                return
            raise

    def finish(self):
        try:
            super().finish()
        except OSError as exc:
            if self._is_client_disconnect(exc):
                self.close_connection = True
                return
            raise

    def do_GET(self):
        # --- Cleanup expired users before handling request ---
        cleanup_dnstt_expired_users()
        cleanup_vless_expired_users()
        cleanup_hysteria_expired_users()
        cleanup_openvpn_expired_users()
        global visit_count
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path
        query_params = urllib.parse.parse_qs(parsed_url.query)
        dnstt_count = get_dnstt_user_count()
        vless_count = get_vless_user_count()
        hysteria_count = get_hysteria_user_count()
        openvpn_count = get_openvpn_user_count()
        ssh_create_days = get_create_account_expiry('ssh')
        vless_create_days = get_create_account_expiry('vless')
        hysteria_create_days = get_create_account_expiry('hysteria')
        openvpn_create_days = get_create_account_expiry('openvpn')
        # --- Add service status checks for /main/ buttons ---
        dnstt_online = get_service_status("dnstt.service")
        vless_online = get_service_status("xray.service")
        hysteria_online = get_service_status("hysteria-v1.service")
        openvpn_online = get_service_status("openvpn.service")
        # --- NEW: reliable SSH status (try both ssh and sshd) ---
        ssh_online = get_service_status("ssh.service") or get_service_status("sshd.service")
        show_announcement = False
        announcement_content = ""
        try:
            if os.path.exists("/etc/README.md"):
                with open("/etc/README.md", "r", encoding="utf-8") as f:
                    announcement_content = f.read().strip()
                    if announcement_content:
                        show_announcement = True
        except Exception:
            show_announcement = False

        # --- Chat messages API (JSON) ---
        if path == '/chat/messages':
          try:
            self.send_response(200)
            self.send_header('Content-type','application/json')
            self.end_headers()
            with chat_lock:
              msgs = list(chat_messages)
            self.wfile.write(json.dumps({'messages': msgs}).encode())
          except Exception:
            try:
              self.send_response(500)
              self.send_header('Content-type','application/json')
              self.end_headers()
              self.wfile.write(json.dumps({'messages': []}).encode())
            except Exception:
              pass
          return
        
        # --- Updated navbar with better positioning ---
        navbar_html = """
<nav class="navbar" role="navigation" aria-label="Main navigation">
    <a href="/main/" class="navbar-brand" aria-label="FUJI PANEL home">
        <span style="display:inline-block;vertical-align:middle;">
            <img src="https://raw.githubusercontent.com/hahacrunchyrollls/logo-s/refs/heads/main/icon_fuji.png" alt="FUJI PANEL" style="height:2.1em;vertical-align:middle;">
        </span>
        <span>FUJI PANEL</span>
    </a>

    <!-- Desktop nav -->
    <div class="navbar-nav" id="navbar-desktop" aria-hidden="false">
        <a href="/main/" class="nav-link"><i class="fa-solid fa-house"></i> Home</a>
        <a href="/status/" class="nav-link"><i class="fa-solid fa-server"></i> Status</a>
        <a href="/hostname-to-ip/" class="nav-link"><i class="fa-solid fa-globe"></i> Hostname to IP</a>
        <a href="/ip-lookup/" class="nav-link"><i class="fa-solid fa-location-dot"></i> IP Lookup</a>
"""
        if show_announcement:
          navbar_html += """
            <a href="/readme/" class="nav-link"><i class="fa-solid fa-bullhorn"></i> Announcement</a>"""
        navbar_html += """
        <a href="/donate/" class="nav-link"><i class="fa-solid fa-donate" style="color:#ffffff"></i> Donate</a>
        <a href="https://t.me/fujivpn" target="_blank" class="nav-link" style="display:inline-flex;align-items:center;gap:6px;">
        <i class="fa-brands fa-telegram" style="color:#229ED9;"></i> Telegram
    </a>
    <a href="https://play.google.com/store/apps/details?id=com.fujivpn.hahaha" target="_blank" class="nav-link" style="display:inline-flex;align-items:center;gap:6px;">
        <i class="fa-brands fa-google-play" style="color:#3bccff;background: linear-gradient(45deg,#3bccff 40%,#34a853 60%,#fbbc04 80%,#ea4335 100%);background-clip:text;-webkit-background-clip:text;-webkit-text-fill-color:transparent;"></i> Play Store
    </a>
    <a href="https://phcorner.org/members/phc_jerico.1922181/" target="_blank" class="nav-link" style="display:inline-flex;align-items:center;gap:6px;">
        <img src="https://phcorner.org/data/assets/logo/XenForo.png" style="height:1.1em;vertical-align:middle;margin-right:0.3em;"> PHCorner
    </a>
    </div>
    <!-- Burger button for smaller screens (kep   t at right) -->
    <button class="burger-btn" id="navbar-burger" aria-label="Open menu" aria-expanded="false" title="Menu" type="button">
        <i class="fa-solid fa-bars" aria-hidden="true" style="font-size:1.1rem;"></i>
    </button>
    <!-- Mobile menu (hidden by default) - links will be cloned from desktop nav -->
    <div id="mobile-menu" class="mobile-menu hidden" aria-hidden="true" role="menu"></div>
    <style>
    /* Burger and mobile menu styles */
        /* Force the desktop nav hidden and show burger on all sizes */
        #navbar-desktop { display: none !important; }
        .burger-btn { display: inline-flex !important; }
        .burger-btn {
      /* display overridden above */
      background: transparent;
      border: 1px solid rgba(255,255,255,0.06);
      color: var(--text-secondary);
      padding: 0;
      border-radius: 10px;
      cursor: pointer;
      backdrop-filter: blur(6px);
      transition: var(--transition);
      align-items: center;
      gap: 6px;
      margin-left: 1rem;
      margin-right: 0.5rem;
      height: 44px;
      width: 44px;
      display:inline-flex;
      align-self:center;
      justify-content: center;
      box-sizing: border-box;
    }
    /* Remove blue background and shadow on hover/focus/open */
    .burger-btn:hover,
    .burger-btn:focus,
    .burger-btn.open {
      background: transparent !important;
      box-shadow: none !important;
    }
    .burger-btn i { font-size: 1.15rem; line-height: 1; }

    .mobile-menu {
      display: none; /* ensure hidden by default on load */
      position: absolute;
      top: calc(100% + 8px);
      right: 12px;
      min-width: 220px;
      max-width: 92vw;
      background: rgba(15,23,42,0.98);
      border: 1px solid var(--card-border);
      border-radius: 12px;
      box-shadow: 0 12px 40px rgba(0,0,0,0.6);
      padding: 8px 8px;
      z-index: 1000;
      flex-direction: column;
      gap: 6px;
    }
    .mobile-menu.hidden { display: none !important; }
    .mobile-menu a.mobile-link {
      display: block;
      text-decoration: none;
      color: var(--text-primary);
      padding: 10px 12px;
      border-radius: 8px;
      font-weight: 600;
    }
    .mobile-menu a.mobile-link:hover { background: rgba(255,255,255,0.03); color: var(--accent-color); }

    @media (max-width: 880px) {
      /* Keep brand left and burger right on narrow screens */
      .navbar { flex-direction: row; align-items: center; justify-content: space-between; padding: 0.6rem 0.8rem; }
      .navbar-brand { padding-left: 0.8rem; margin-right: auto; }
      #navbar-desktop { display: none !important; }
      .burger-btn { display: inline-flex !important; }
    }

    @media (max-width: 576px) {
      .navbar { padding: 0.5rem 0.6rem; }
      .burger-btn { margin-left: 0.6rem; margin-right: 0.6rem; }
      .mobile-menu { right: 8px; left: auto; top: calc(100% + 6px); min-width: 180px; }
    }

    @media (min-width: 881px) {
      /* Keep burger visible on larger screens and allow mobile menu to function */
      #mobile-menu { /* don't forcibly hide; menu visibility controlled by JS */ }
      .burger-btn { display: inline-flex !important; }
    }
    </style>

    <script>
    (function(){
      var burger = null;
      var menu = null;
      var desktopNav = null;

      function cloneDesktopLinks() {
        // Clone desktop nav links into mobile menu to ensure both contain same items
        if (!desktopNav || !menu) return;
        // If already cloned and menu has children, skip
        if (menu.dataset.cloned === "1") return;
        menu.innerHTML = '';
        var links = desktopNav.querySelectorAll('a.nav-link');
        links.forEach(function(a){
          var clone = a.cloneNode(true);
          clone.classList.remove('nav-link');
          clone.classList.add('mobile-link');
          // When mobile link is clicked, close the menu (allow navigation to proceed)
          clone.addEventListener('click', function(){
            closeMenu();
            // allow natural navigation after short delay for close animation if needed
            // no preventDefault so navigation proceeds
          });
          menu.appendChild(clone);
        });
        // Ensure important static links present (fallback)
        if (!menu.querySelector('a[href="/main/"]')) {
          var home = document.createElement('a');
          home.href = '/main/';
          home.className = 'mobile-link';
          home.innerHTML = '<i class="fa-solid fa-house"></i> Home';
          home.addEventListener('click', closeMenu);
          menu.appendChild(home);
        }
        menu.dataset.cloned = "1";
      }

      function openMenu() {
        if (!menu || !burger) return;
        menu.classList.remove('hidden');
        menu.style.display = 'flex';
        menu.setAttribute('aria-hidden', 'false');
        burger.setAttribute('aria-expanded', 'true');
        burger.classList.add('open'); // only toggle class, do not change icon/size
      }
      function closeMenu() {
        if (!menu || !burger) return;
        menu.classList.add('hidden');
        menu.style.display = 'none';
        menu.setAttribute('aria-hidden', 'true');
        burger.setAttribute('aria-expanded', 'false');
        burger.classList.remove('open'); // restore state, keep same icon
      }

      function toggleMenu() {
        if (!menu) return;
        var isOpen = menu.getAttribute('aria-hidden') === 'false' && menu.style.display !== 'none';
        if (isOpen) closeMenu(); else openMenu();
      }

      function initNav() {
        burger = document.getElementById('navbar-burger');
        menu = document.getElementById('mobile-menu');
        desktopNav = document.getElementById('navbar-desktop');
        if (!burger || !menu) return;

        cloneDesktopLinks();

        // Ensure menu is closed on initial load
        menu.classList.add('hidden');
        menu.style.display = 'none';
        menu.setAttribute('aria-hidden', 'true');
        if (burger) {
          burger.setAttribute('aria-expanded', 'false');
          // ensure burger always shows the bars icon and consistent size
          burger.innerHTML = '<i class="fa-solid fa-bars" aria-hidden="true" style="font-size:1.15rem;"></i>';
          burger.classList.remove('open');
        }

        burger.addEventListener('click', function(e){
          e.stopPropagation();
          toggleMenu();
        });

        // Close when clicking outside
        document.addEventListener('click', function(e){
          if (!menu || !burger) return;
          if (!menu.contains(e.target) && !burger.contains(e.target) && menu.getAttribute('aria-hidden') === 'false') {
            closeMenu();
          }
        });

        // Re-clone on resize (in case desktop nav changes)
        var resizeTimer = null;
        window.addEventListener('resize', function(){
          clearTimeout(resizeTimer);
          resizeTimer = setTimeout(function(){
            // if mobile active, ensure clones exist
            cloneDesktopLinks();
            // if viewport widened to desktop, close mobile menu
            if (window.innerWidth > 880) closeMenu();
          }, 150);
        });

        // Keyboard: close on ESC
        document.addEventListener('keydown', function(e){
          if (e.key === 'Escape') closeMenu();
        });

        // Close menu before leaving the page (navigations / refresh)
        window.addEventListener('beforeunload', function(){ closeMenu(); });
        // When page becomes visible again (back/forward) ensure closed
        window.addEventListener('pageshow', function(){ closeMenu(); });

        // Also close menu when any internal link is clicked (covers anchors added after clone)
        document.addEventListener('click', function(e){
          var el = e.target;
          while(el && el !== document){
            if (el.tagName && el.tagName.toLowerCase() === 'a') {
              var href = el.getAttribute('href') || '';
              // Only act on same-origin or internal navigation links to avoid interfering with external targets
              if (href.startsWith('/') || href.indexOf(window.location.origin) === 0) {
                // schedule close slightly later so click can navigate
                setTimeout(closeMenu, 10);
              }
              break;
            }
            el = el.parentNode;
          }
        }, true);
      }

      // init after DOMContentLoaded if possible
      if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initNav);
      } else {
        initNav();
      }
    })();
    </script>
</nav>
"""
        # --- Top bar removed; navigation consolidated into navbar/burger ---
        main_topbar_html = ""
        try:
            # Prefer forwarded header when behind proxy, fallback to socket client address
            xff = self.headers.get('X-Forwarded-For') or self.headers.get('X-Real-IP') or ''
            if xff:
                client_ip = xff.split(',')[0].strip()
            else:
                client_ip = self.client_address[0]
            escaped_ip = html.escape(client_ip)
            # build a span placed right next to the "FUJI PANEL" text but prevent it from activating the link
            server_span = (
                f'<span class="server-ip" onclick="event.preventDefault();event.stopPropagation();" tabindex="-1" role="note" '
                f'style="display:inline-flex;align-items:center;font-size:0.85rem;font-weight:700;color:var(--text-secondary);'
                f'margin-left:0.6rem;padding:0.18rem 0.45rem;background:rgba(255,255,255,0.02);'
                f'border-radius:8px;border:1px solid rgba(255,255,255,0.03);vertical-align:middle;user-select:none;cursor:default;white-space:nowrap;">'
                f'IP: {escaped_ip}</span>'
            )
          
            navbar_html += """
<style>
@media (max-width: 600px) {
  .server-ip {
    white-space: nowrap !important;
    font-size: 0.75rem !important;
    max-width: 90vw;
    overflow-wrap: normal;
    word-break: normal;
    display: inline-flex !important;
    align-items: center;
    padding: 0.18rem 0.45rem;
  }
  .navbar-brand {
    font-size: clamp(0.85rem, 5vw, 1.1rem) !important; /* Even smaller on mobile */
  }
}
</style>
"""
            # insert the span immediately after the "FUJI PANEL" span so it appears at its side
            navbar_html = navbar_html.replace('<span>FUJI PANEL</span>', '<span>FUJI PANEL</span>' + server_span, 1)
        except Exception:
            pass
        # --- Add endpoint that returns online users + totals as JSON (no caching) ---

        # --- Admin pages ---
        if path == "/admin/logout":
            token = _get_cookie_value(self.headers, 'admin_token')
            log_admin_event("logout", ip=get_request_ip(self), details={"result": "session cleared" if token else "no active session"})
            if token:
                clear_admin_session(token)
            self.send_response(302)
            self.send_header('Set-Cookie', 'admin_token=; Max-Age=0; Path=/admin/; HttpOnly')
            self.send_header('Location', '/admin/')
            self.end_headers()
            return

        if path == "/admin/":
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            if not is_admin_authenticated(self):
                self.end_headers()
                self.wfile.write(HTML_HEADER.replace("<title>CREATE ACCOUNT</title>", "<title>Admin Login</title>").encode())
                self.wfile.write(navbar_html.encode())
                self.wfile.write(admin_login_content().encode())
                self.wfile.write(HTML_FOOTER.encode())
                return
            accounts = list_all_accounts()
            limit_val = get_daily_account_limit()
            success_msg = (query_params.get('success', [''])[0] or None)
            error_msg = (query_params.get('error', [''])[0] or None)
            self.end_headers()
            self.wfile.write(HTML_HEADER.replace("<title>CREATE ACCOUNT</title>", "<title>Admin</title>").encode())
            self.wfile.write(navbar_html.encode())
            self.wfile.write(admin_dashboard_content(accounts, limit_val, success_msg, error_msg).encode())
            self.wfile.write(HTML_FOOTER.encode())
            return

        if path == "/readme/":
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(HTML_HEADER.replace("<title>CREATE ACCOUNT</title>", "<title>Announcement</title>").encode())
            self.wfile.write(navbar_html.encode())
            announcement = ""
            try:
                with open("/etc/README.md", "r", encoding="utf-8") as f:
                    announcement = f.read().strip()
            except Exception:
                announcement = ""
            # --- Markdown to HTML conversion with code block detection ---
            def md_to_html(md):
              # Escape HTML
              md = html.escape(md)
              # Headers
              md = re.sub(r'(^|\n)### (.*)', r'\1<h3>\2</h3>', md)
              md = re.sub(r'(^|\n)## (.*)', r'\1<h2>\2</h2>', md)
              md = re.sub(r'(^|\n)# (.*)', r'\1<h1>\2</h1>', md)
              # Bold/italic/links
              md = re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', md)
              md = re.sub(r'\*(.+?)\*', r'<i>\1</i>', md)
              md = re.sub(r'\[(.+?)\]\((.+?)\)', r'<a href="\2" target="_blank">\1</a>', md)
              # Code blocks (```...```)
              def code_block_repl(match):
                  code = match.group(1).strip('\n')
                  return (
                      '<div style="background:rgba(15, 23, 42, 0.8);'
                      'border-radius:var(--border-radius);'
                      'padding:0.8rem 1rem;'
                      'display:flex;align-items:center;'
                      'gap:1.2rem;'
                      'border:1px solid var(--card-border);'
                      'margin:1.2em 0;">'
                      f'<input type="text" readonly value="{code}" '
                      'style="max-width:none;flex:1;padding:0.6em 1em;font-size:1.08em;'
                      'background:transparent;color:#fff;border:none;outline:none;'
                      'margin-right:0.5em;">'
                      f'<sl-copy-button value="{code}" '
                      'style="background:transparent;border:none;padding:0;margin-left:0.5em;"></sl-copy-button>'
                      '</div>'
                  )
              md = re.sub(r'```([\s\S]+?)```', code_block_repl, md)
              # Inline code (`...`)
              md = re.sub(r'`([^`]+)`', r'<code style="background:#222;padding:2px 6px;border-radius:6px;">\1</code>', md)
              # Make http/https links clickable
              md = make_links_clickable(md)
              # Line breaks
              md = md.replace('\n', '<br>')
              return md
            self.wfile.write(b"""
<div class="container">
  <div class="neo-box" style="max-width:800px;margin:0 auto;">
    <div style="display:flex;align-items:center;justify-content:center;gap:0.8em;margin-bottom:1.5em;">
      <i class="fa-solid fa-bullhorn" style="font-size:1.8em;color:var(--accent-color);"></i>
      <h2 class="section-title" style="margin:0;">ANNOUNCEMENT!</h2>
    </div>
    <div class="announcement-content" style="font-size:1.1em;color:var(--text-primary);padding:1em 0;">
""")
            if not announcement:
                self.wfile.write(b"""
<div style='color:var(--error);font-weight:600;text-align:center;'>NO ANNOUNCEMENT!</div>
""")
            else:
                self.wfile.write(md_to_html(announcement).encode())
            self.wfile.write(b"""
    </div>
    <div style="display:flex;justify-content:center;margin-top:1.5rem;">
      <a href="/main/" style="text-decoration:none;display:inline-block;width:100%;">
        <button style="
          width:100%;
          max-width:400px;
          min-width:220px;
          font-size:1.15em;
          padding:16px 0;
          margin:0 auto;
          background:rgba(15, 23, 42, 0.6);
          border:2px solid var(--card-border);
          border-radius:16px;
          font-weight:700;
          box-shadow:0 4px 18px rgba(0,0,0,0.18);
          display:block;
        ">
          <i class="fa-solid fa-arrow-left"></i> Back to Main
        </button>
      </a>
    </div>
    <script>
    // Simple GitHub-style COPY button for code blocks
    document.addEventListener('DOMContentLoaded', function() {
      document.querySelectorAll('.code-block-container').forEach(function(container) {
        var btn = container.querySelector('.copy-btn');
        var code = container.querySelector('code');
        if (btn && code) {
          btn.addEventListener('click', function() {
            navigator.clipboard.writeText(code.textContent);
            btn.innerHTML = '<svg aria-hidden="true" height="18" viewBox="0 0 16 16" width="18" style="vertical-align:middle;"><path fill="white" d="M5 1.75C5 .784 5.784 0 6.75 0h7.5C15.216 0 16 .784 16 1.75v7.5A1.75 1.75 0 0 1 14.25 11h-7.5A1.75 1.75 0 0 1 5 9.25Zm1.75-.25a.25.25 0 0 0-.25.25v7.5c0 .138.112.25.25.25h7.5a.25.25 0 0 0 .25-.25v-7.5a.25.25 0 0 0-.25-.25Z"></path></svg>';
            setTimeout(function(){ btn.innerHTML = '<svg aria-hidden="true" height="18" viewBox="0 0 16 16" width="18" style="vertical-align:middle;"><path fill="white" d="M5 1.75C5 .784 5.784 0 6.75 0h7.5C15.216 0 16 .784 16 1.75v7.5A1.75 1.75 0 0 1 14.25 11h-7.5A1.75 1.75 0 0 1 5 9.25Zm1.75-.25a.25.25 0 0 0-.25.25v7.5c0 .138.112.25.25.25h7.5a.25.25 0 0 0 .25-.25v-7.5a.25.25 0 0 0-.25-.25Z"></path></svg>';
            }, 1200);
          });
        }
      });
    });
    </script>
  </div>
</div>
""")
            self.wfile.write(HTML_FOOTER.encode())
            return

        if path == "/main/stats":
            try:
                online = get_online_user_count()
                visit_data = load_visit_data()
                resp = {
                    "online_users": online,
                    "total_visits": visit_data.get("total_visits", 0),
                    "total_accounts": visit_data.get("total_accounts", 0)
                }
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                # prevent caching so browser always gets fresh value
                self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0')
                self.send_header('Pragma', 'no-cache')
                self.send_header('Expires', '0')
                self.end_headers()
                self.wfile.write(json.dumps(resp).encode())
            except Exception:
                self.send_response(500)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"online_users": 0, "total_visits": 0, "total_accounts": 0}).encode())
            return

        if path == "/status/":
            self.send_response(200)
            self.send_header('Content-type','text/html')
            self.end_headers()
            self.wfile.write(HTML_HEADER.replace("<title>CREATE ACCOUNT</title>", "<title>Server Status</title>").encode())
            self.wfile.write(navbar_html.encode())
            self.wfile.write(b"""
<div class="container">
  <div class="neo-box">
    <div style="display:flex;align-items:center;justify-content:center;gap:0.8em;margin-bottom:1.5em;">
      <i class="fa-solid fa-server" style="font-size:1.8em;color:var(--accent-color);"></i>
      <h2 class="section-title" style="margin:0;">Server Status</h2>
    </div>
    
    <div class="status-subtitle">
      <i class="fa-solid fa-network-wired"></i> Network Traffic
    </div>
    <div class="status-grid-2" id="network-grid"></div>
    
    <div class="status-subtitle">
      <i class="fa-solid fa-microchip"></i> System Resources
    </div>
    <div class="status-grid-2" id="status-grid"></div>
    
    <div class="status-subtitle">
      <i class="fa-solid fa-plug"></i> Services
    </div>
    <div class="services-grid" id="services-container"></div>
  </div>
</div>
<style>
.services-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 12px;
  margin-top: 0.8rem;
}

.service-item {
  background: rgba(15, 23, 42, 0.6);
  border-radius: var(--border-radius);
  padding: 12px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  border: 1px solid var(--card-border);
}

.service-name {
  display: flex;
  align-items: center;
  gap: 8px;
}

.service-icon {
  font-size: 1.2rem;
}

.service-active {
  color: var(--success);
}

.service-inactive {
  color: var(--error);
}
</style>
<script>
let totalIn = 0, totalOut = 0;
function formatSpeed(bytesPerSec) {
  if (bytesPerSec > 1024*1024)
    return (bytesPerSec/1024/1024).toFixed(2) + " MB/s";
  if (bytesPerSec > 1024)
    return (bytesPerSec/1024).toFixed(2) + " KB/s";
  return bytesPerSec.toFixed(0) + " B/s";
}
function formatBytes(bytes) {
  if (bytes > 1024*1024*1024)
    return (bytes/1024/1024/1024).toFixed(2) + " GB";
  if (bytes > 1024*1024)
    return (bytes/1024/1024).toFixed(2) + " MB";
  if (bytes > 1024)
    return (bytes/1024).toFixed(2) + " KB";
  return bytes.toFixed(0) + " B";
}
function updateStatus() {
  fetch('/status/full').then(r=>r.json()).then(data=>{
    // Network traffic
    let rx = data.net.rx_bytes;
    let tx = data.net.tx_bytes;
    let rxSpeed = data.net.rx_rate;
    let txSpeed = data.net.tx_rate;
    totalIn = rx;
    totalOut = tx;
    
    document.getElementById('network-grid').innerHTML = `
      <div class="status-card">
        <div class="status-label"><i class="fa-solid fa-arrow-down" style="color:var(--success)"></i> Download Speed</div>
        <div class="status-value">${formatSpeed(rxSpeed)}</div>
      </div>
      <div class="status-card">
        <div class="status-label"><i class="fa-solid fa-arrow-up" style="color:var(--accent-color)"></i> Upload Speed</div>
        <div class="status-value">${formatSpeed(txSpeed)}</div>
      </div>
      <div class="status-card">
        <div class="status-label"><i class="fa-solid fa-database" style="color:var(--success)"></i> Total Downloaded</div>
        <div class="status-value">${formatBytes(totalIn)}</div>
      </div>
      <div class="status-card">
        <div class="status-label"><i class="fa-solid fa-database" style="color:var(--accent-color)"></i> Total Uploaded</div>
        <div class="status-value">${formatBytes(totalOut)}</div>
      </div>
    `;
    
    // Other stats
    let html = '';
    html += `
      <div class="status-card">
        <div class="status-label"><i class="fa-solid fa-microchip" style="color:var(--primary-color)"></i> CPU Usage</div>
        <div class="status-value">${data.cpu}%</div>
      </div>
      <div class="status-card">
        <div class="status-label"><i class="fa-solid fa-chart-line" style="color:var(--accent-color)"></i> Load Average</div>
        <div class="status-value">${data.load.join(', ')}</div>
      </div>
      <div class="status-card">
        <div class="status-label"><i class="fa-solid fa-memory" style="color:var(--success)"></i> Memory Used</div>
        <div class="status-value">${data.mem.used} / ${data.mem.total} MB</div>
      </div>
      <div class="status-card">
        <div class="status-label"><i class="fa-solid fa-memory" style="color:var(--primary-color)"></i> Memory Available</div>
        <div class="status-value">${data.mem.available} MB</div>
      </div>
      <div class="status-card">
        <div class="status-label"><i class="fa-solid fa-hdd" style="color:var(--accent-color)"></i> Storage Used</div>
        <div class="status-value">${data.storage.used} / ${data.storage.total} MB</div>
      </div>
      <div class="status-card">
        <div class="status-label"><i class="fa-solid fa-hdd" style="color:var(--success)"></i> Storage Free</div>
        <div class="status-value">${data.storage.free} MB</div>
      </div>
    `;
    document.getElementById('status-grid').innerHTML = html;
    
    // Services
    let shtml = '';
    for (let i = 0; i < data.services.length; i++) {
      let name = data.services[i][0];
      let ok = data.services[i][1];
      let icon = ok ? 
        '<i class="fa-solid fa-circle-check service-icon service-active"></i>' : 
        '<i class="fa-solid fa-circle-xmark service-icon service-inactive"></i>';
      shtml += `
        <div class="service-item">
          <div class="service-name">${icon} ${name}</div>
        </div>`;
    }
    document.getElementById('services-container').innerHTML = shtml;
  });
}
updateStatus();
setInterval(updateStatus, 2000);
</script>
""")
            return
        elif path == "/hostname-to-ip/":
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            # Remove navigation button in the bottom by not writing HTML_FOOTER here
            self.wfile.write(HTML_HEADER.replace("<title>CREATE ACCOUNT</title>", "<title>Hostname to IP</title>").encode())
            self.wfile.write(navbar_html.encode())
            self.wfile.write(b"""
<div class="container">
  <div class="neo-box" style="max-width:500px;margin:0 auto;text-align:center;">
    <div style="display:flex;align-items:center;justify-content:center;gap:0.8em;margin-bottom:1.5em;">
      <i class="fa-solid fa-globe" style="font-size:1.8em;color:var(--accent-color);"></i>
      <h2 class="section-title" style="margin:0;">Hostname to IP</h2>
    </div>
    <form id="hostname-form" method="POST" action="/hostname-to-ip/" style="margin-bottom:2em;">
      <div class="form-group">
        <label for="hostname" class="form-label">
          <i class="fa-solid fa-globe"></i> Hostname
        </label>
        <div class="form-input-container">
          <input name="hostname" id="hostname" type="text" placeholder="Enter hostname (e.g. google.com)" required="" maxlength="255">
        </div>
      </div>
      <button type="submit" style="width:100%;max-width:400px;margin:0 auto;">
        <i class="fa-solid fa-magnifying-glass"></i> Check IP Address
      </button>
    </form>
    <div id="hostname-result"></div>
  </div>
</div>
<script>
document.getElementById('hostname-form').addEventListener('submit', function(e) {
  e.preventDefault();
  var hostname = document.getElementById('hostname').value.trim();
  var resultDiv = document.getElementById('hostname-result');
  resultDiv.innerHTML = '<div style="color:var(--text-muted);margin-top:1em;"><i class="fa-solid fa-spinner fa-spin"></i> Checking...</div>';
  fetch('/hostname-to-ip/', {
    method: 'POST',
    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    body: 'hostname=' + encodeURIComponent(hostname)
  }).then(r=>r.text()).then(html=>{
    resultDiv.innerHTML = html;
  }).catch(()=>{
    resultDiv.innerHTML = '<div style="color:var(--error);margin-top:1em;">Error checking hostname.</div>';
  });
});
</script>
""")
            return
        elif path == "/ip-lookup/":
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(HTML_HEADER.replace("<title>CREATE ACCOUNT</title>", "<title>IP Lookup</title>").encode())
            self.wfile.write(navbar_html.encode())
            self.wfile.write(b"""
<div class="container">
  <div class="neo-box" style="max-width:600px;margin:0 auto;text-align:center;">
    <div style="display:flex;align-items:center;justify-content:center;gap:0.8em;margin-bottom:1.5em;">
      <i class="fa-solid fa-location-dot" style="font-size:1.8em;color:var(--accent-color);"></i>
      <h2 class="section-title" style="margin:0;">IP Lookup</h2>
    </div>
    <form id="ip-form" method="POST" action="/ip-lookup/" style="margin-bottom:2em;">
      <div class="form-group">
        <label for="ip" class="form-label">
          <i class="fa-solid fa-network-wired"></i> IP Address
        </label>
        <div class="form-input-container">
          <input name="ip" id="ip" type="text" placeholder="Enter IP (leave blank for your IP)" maxlength="255">
        </div>
      </div>
      <button type="submit" style="width:100%;max-width:400px;margin:0 auto;">
        <i class="fa-solid fa-magnifying-glass"></i> Lookup
      </button>
    </form>
    <div id="ip-result"></div>
  </div>
</div>
<script>
document.getElementById('ip-form').addEventListener('submit', function(e) {
  e.preventDefault();
  var ip = document.getElementById('ip').value.trim();
  var resultDiv = document.getElementById('ip-result');
  resultDiv.innerHTML = '<div style="color:var(--text-muted);margin-top:1em;"><i class="fa-solid fa-spinner fa-spin"></i> Looking up...</div>';
  fetch('/ip-lookup/', {
    method: 'POST',
    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    body: 'ip=' + encodeURIComponent(ip)
  }).then(r=>r.text()).then(html=>{
    resultDiv.innerHTML = html;
  }).catch(()=>{
    resultDiv.innerHTML = '<div style="color:var(--error);margin-top:1em;">Error performing lookup.</div>';
  });
});
</script>
""")
            return
        elif path == "/status/full":
            mem = get_memory_stats()
            storage = get_storage_stats()
            global last_traffic_snapshot
            now = time.time()
            rx_total, tx_total = get_total_network_bytes()
            with traffic_lock:
                prev = last_traffic_snapshot.copy()
                if prev['time'] is None:
                    rx_rate = tx_rate = 0
                else:
                    dt = now - prev['time']
                    rx_rate = (rx_total - prev['rx']) / dt if dt > 0 else 0
                    tx_rate = (tx_total - prev['tx']) / dt if dt > 0 else 0
                last_traffic_snapshot['time'] = now
                last_traffic_snapshot['rx'] = rx_total
                last_traffic_snapshot['tx'] = tx_total
            idle1, total1 = get_cpu_usage()
            time.sleep(0.1)
            idle2, total2 = get_cpu_usage()
            cpu_percent = 0.0
            if total2 > total1:
                cpu_percent = round(100.0 * (1 - (idle2 - idle1) / (total2 - total1)), 2)
            try:
                with open('/proc/loadavg') as f:
                    load1, load5, load15, *_ = f.read().split()
            except Exception:
                load1 = load5 = load15 = "N/A"
            services = get_service_statuses()
            resp = {
                "cpu": cpu_percent,
                "load": [load1, load5, load15],
                "mem": mem,
                "storage": storage,
                "net": {
                    "rx_bytes": rx_total,
                    "tx_bytes": tx_total,
                    "rx_rate": rx_rate,
                    "tx_rate": tx_rate
                },
                "services": services
            }
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(resp).encode())
            return
        elif path.startswith("/download/"):
            # Serve file download if /download/filename is accessed
            fname = path[len("/download/"):]
            file_path = os.path.join("/etc/download", fname)
            if fname and os.path.isfile(file_path):
                self.send_response(200)
                # Use generic binary content type for all file types
                self.send_header('Content-Type', 'application/octet-stream')
                self.send_header('Content-Disposition', f'attachment; filename="{os.path.basename(file_path)}"')
                self.end_headers()
                with open(file_path, "rb") as f:
                    self.wfile.write(f.read())
                return
            # If just /download/, show file list
            files = []
            if os.path.isdir("/etc/download"):
                files = [f for f in os.listdir("/etc/download") if os.path.isfile(os.path.join("/etc/download", f))]
            self.send_response(200)
            self.send_header('Content-type','text/html')
            self.end_headers()
            self.wfile.write(HTML_HEADER.replace("<title>CREATE ACCOUNT</title>", "<title>Download</title>").encode())
            self.wfile.write(navbar_html.encode())
            self.wfile.write(b"""
<div class="container">
  <div class="neo-box">
    <div style="display:flex;align-items:center;justify-content:center;gap:0.8em;margin-bottom:1.5em;">
      <i class="fa-solid fa-download" style="font-size:1.8em;color:var(--accent-color);"></i>
      <h2 class="section-title" style="margin:0;">Download Files</h2>
    </div>
""")
            if not files:
                self.wfile.write(b"""
  <div style="text-align:center;padding:2rem 0;color:var(--text-muted);">
    <i class="fa-solid fa-folder-open" style="font-size:3rem;margin-bottom:1rem;"></i>
    <div>No files available for download.</div>
  </div>
  """)
            else:
                for fname in files:
                    self.wfile.write(f"""
  <div class="file-card" style="text-align:center;">
    <div class="file-title" style="display:flex;align-items:center;justify-content:center;gap:8px;margin-bottom:0.5rem;">
      <i class="fa-solid fa-file" style="color:var(--accent-color)"></i>
      <span style="font-weight:600;">{html.escape(fname)}</span>
    </div>
    <a href="/download/{urllib.parse.quote(fname)}" style="text-decoration:none;display:block;margin-bottom:1rem;">
      <button class="download-btn" style="width:300px;margin:0 auto;display:block;">
        <i class="fa-solid fa-download"></i> Download
      </button>
    </a>
  </div>
  """.encode())
            self.wfile.write(HTML_FOOTER.encode())
            return
            
        # Donate page
        if path == "/donate/":
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(HTML_HEADER.replace("<title>CREATE ACCOUNT</title>", "<title>Donate</title>").encode())
            self.wfile.write(navbar_html.encode())
            self.wfile.write(b"""
<div class="container">
  <div class="neo-box" style="max-width:720px;margin:0 auto;text-align:center;">
    <div style="display:flex;align-items:center;justify-content:center;gap:0.8em;margin-bottom:1rem;">
      <i class="fa-solid fa-donate" style="font-size:1.6em;color:#ffffff;"></i>
      <h2 class="section-title" style="margin:0;">Gcash Donation</h2>
    </div>
    <div style="margin-top:0.6rem;">
      <img src="https://raw.githubusercontent.com/hahacrunchyrollls/logo-s/refs/heads/main/Donate.png" alt="Donate" style="max-width:100%;height:auto;border-radius:12px;border:1px solid var(--card-border);">
    </div>
    <div style="margin-top:1rem;color:var(--text-secondary);">Thank you for supporting all donation will be appriciated.</div>
    <a href="/main/" style="display:block;margin-top:1.2rem;text-decoration:none;">
      <button style="width:100%;max-width:320px;margin:0.8rem auto 0;display:block;"><i class="fa-solid fa-arrow-left"></i> Back to Main</button>
    </a>
  </div>
</div>
""")
            self.wfile.write(HTML_FOOTER.encode())
            return

        # Main and user creation logic
        self.send_response(200)
        self.send_header('Content-type','text/html')
        self.end_headers()

        # Set tab title for /main/, /ssh/, /vless/, /hysteria/
        if path == "/main/" or path == "/":
            visit_data = update_today_stats(1, dnstt_count + vless_count + hysteria_count + openvpn_count)
            visit_count = visit_data["total_visits"]
            total_accounts = visit_data["total_accounts"]
            online_users = get_online_user_count()
            # --- Detect server location and flag ---
            country, country_code, city = get_server_location()
            cloud_icon_url = get_cloud_icon_url()
            flag_url = flag_image_url(country_code)
            location_html = f"""
<div style="text-align:center;margin-bottom:1.2em;">
  {'<img src="' + flag_url + '" alt="' + country_code + ' flag" style="height:2.2em;vertical-align:middle;border-radius:6px;border:1px solid #222;margin-bottom:0.5em;margin-top:1em;">' if flag_url else ''}
  <div style="font-size:1.1em;color:var(--text-secondary);font-weight:600;margin-top:0.5em;">
    {html.escape(country)}{', ' + html.escape(city) if city else ''}
  </div>
</div>
"""
            self.wfile.write(HTML_HEADER.replace("<title>CREATE ACCOUNT</title>", "<title>FUJI PANEL</title>").encode())
            self.wfile.write(navbar_html.encode())
            # --- Show location above CREATE ACCOUNT ---
            self.wfile.write(location_html.encode())
        elif path == "/status/":
            self.wfile.write(HTML_HEADER.replace("<title>CREATE ACCOUNT</title>", "<title>STATUS</title>").encode())
            self.wfile.write(navbar_html.encode())
        elif path == "/download/":
            self.wfile.write(HTML_HEADER.replace("<title>CREATE ACCOUNT</title>", "<title>DOWNLOAD</title>").encode())
            self.wfile.write(navbar_html.encode())
        elif path == "/ssh/":
            self.wfile.write(HTML_HEADER.replace("<title>CREATE ACCOUNT</title>", "<title>SSH</title>").encode())
            self.wfile.write(navbar_html.encode())
        elif path == "/vless/":
            self.wfile.write(HTML_HEADER.replace("<title>CREATE ACCOUNT</title>", "<title>VLESS</title>").encode())
            self.wfile.write(navbar_html.encode())
        elif path == "/openvpn/":
            self.wfile.write(HTML_HEADER.replace("<title>CREATE ACCOUNT</title>", "<title>OPENVPN</title>").encode())
            self.wfile.write(navbar_html.encode())
        elif path == "/hysteria/":
            self.wfile.write(HTML_HEADER.replace("<title>CREATE ACCOUNT</title>", "<title>HYSTERIA</title>").encode())
            self.wfile.write(navbar_html.encode())

        else:
            self.wfile.write(HTML_HEADER.encode())
            self.wfile.write(navbar_html.encode())
            
        if path == "/main/" or path == "/":
            self.wfile.write(b"""
<div class="container">
  <div class="neo-box" style="text-align:center;">
    <div style="display:flex;align-items:center;justify-content:center;gap:0.8em;margin-bottom:1.5em;">
      <i class="fa-solid fa-user-plus" style="font-size:1.8em;color:var(--accent-color);"></i>
      <h2 class="section-title" style="margin:0;">CREATE ACCOUNT</h2>
    </div>
    <style>
      .create-grid { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:12px; margin:0 auto; max-width:640px; }
      .create-cell a { text-decoration:none; display:block; }
      .create-btn { width:100%; display:flex; align-items:center; justify-content:space-between; gap:10px; padding:12px 14px; }
      .btn-left { display:flex; align-items:center; gap:10px; font-weight:700; color:var(--text-primary); }
      .btn-right { display:flex; align-items:center; justify-content:flex-end; }
      .create-count { background:rgba(255,255,255,0.04); padding:4px 8px; border-radius:10px; font-weight:700; color:#ffffff; }
      @media (max-width:480px) { .create-grid { grid-template-columns:1fr; } }
    </style>
    <div style="margin: 2rem 0;">
      <div class="create-grid">
""")
            # --- Always show SSH button; disable when service offline ---
            ssh_a_attr = '' if ssh_online else 'onclick="return false;"'
            ssh_btn_attr = '' if ssh_online else 'disabled'
            ssh_btn_style = '' if ssh_online else 'opacity:0.55;cursor:not-allowed;'
            # daily created counts per service (Philippine date)
            try:
              ssh_created = get_daily_created_count('ssh')
            except Exception:
              ssh_created = 0
            try:
              vless_created = get_daily_created_count('vless')
            except Exception:
              vless_created = 0
            try:
              hysteria_created = get_daily_created_count('hysteria')
            except Exception:
              hysteria_created = 0
            try:
              openvpn_created = get_daily_created_count('openvpn')
            except Exception:
              openvpn_created = 0
            limit_val = get_daily_account_limit()
            ssh_label = f"{ssh_created}/{limit_val}"
            vless_label = f"{vless_created}/{limit_val}"
            hysteria_label = f"{hysteria_created}/{limit_val}"
            openvpn_label = f"{openvpn_created}/{limit_val}"
            self.wfile.write(f"""
      <div class="create-cell">
        <a href="/ssh/" {ssh_a_attr}>
          <button class="create-btn" {ssh_btn_attr} style="{ssh_btn_style}">
            <div class="btn-left"><img src="https://raw.githubusercontent.com/hahacrunchyrollls/logo-s/refs/heads/main/icon-ssh.png" style="height:1.1em;vertical-align:middle;"> CREATE SSH</div>
            <div class="btn-right"><span class="create-count">{ssh_label}</span></div>
          </button>
        </a>
      </div>
""".encode())
            # --- Always show VLESS button; disable when service offline ---
            vless_a_attr = '' if vless_online else 'onclick="return false;"'
            vless_btn_attr = '' if vless_online else 'disabled'
            vless_btn_style = '' if vless_online else 'opacity:0.55;cursor:not-allowed;'
            self.wfile.write(f"""
      <div class="create-cell">
        <a href="/vless/" {vless_a_attr}>
          <button class="create-btn" {vless_btn_attr} style="{vless_btn_style}">
            <div class="btn-left"><img src="https://raw.githubusercontent.com/hahacrunchyrollls/logo-s/refs/heads/main/icon-v2ray.png" style="height:1.1em;vertical-align:middle;"> CREATE VLESS</div>
            <div class="btn-right"><span class="create-count">{vless_label}</span></div>
          </button>
        </a>
      </div>
""".encode())
            # --- Always show HYSTERIA button; disable when service offline ---
            hysteria_a_attr = '' if hysteria_online else 'onclick="return false;"'
            hysteria_btn_attr = '' if hysteria_online else 'disabled'
            hysteria_btn_style = '' if hysteria_online else 'opacity:0.55;cursor:not-allowed;'
            self.wfile.write(f"""
      <div class="create-cell">
        <a href="/hysteria/" {hysteria_a_attr}>
          <button class="create-btn" {hysteria_btn_attr} style="{hysteria_btn_style}">
            <div class="btn-left"><img src="https://raw.githubusercontent.com/hahacrunchyrollls/logo-s/refs/heads/main/icon-hysteria.png" style="height:1.1em;vertical-align:middle;"> CREATE HYSTERIA</div>
            <div class="btn-right"><span class="create-count">{hysteria_label}</span></div>
          </button>
        </a>
      </div>
""".encode())
            # --- Always show OPENVPN button; disable when service offline ---
            openvpn_a_attr = '' if openvpn_online else 'onclick="return false;"'
            openvpn_btn_attr = '' if openvpn_online else 'disabled'
            openvpn_btn_style = '' if openvpn_online else 'opacity:0.55;cursor:not-allowed;'
            self.wfile.write(f"""
      <div class="create-cell">
        <a href="/openvpn/" {openvpn_a_attr}>
          <button class="create-btn" {openvpn_btn_attr} style="{openvpn_btn_style}">
            <div class="btn-left"><img src="https://raw.githubusercontent.com/hahacrunchyrollls/logo-s/refs/heads/main/icon-openvpn.png" style="height:1.1em;vertical-align:middle;"> CREATE OPENVPN</div>
            <div class="btn-right"><span class="create-count">{openvpn_label}</span></div>
          </button>
        </a>
      </div>
""".encode())

            self.wfile.write(b"""
      </div>
    </div>
  </div>
</div>
""")

            # --- Public chat placed below CREATE ACCOUNT and above the stats ---
            self.wfile.write(b"""
<div class="public-chat">
  <div class="chat-box" id="public-chat-box"></div>
  <form id="public-chat-form" onsubmit="sendPublicChat(event)" class="chat-form">
    <input name="name" id="chat-name" type="text" placeholder="Name (max 10 letters)" maxlength="10" autocomplete="off">
    <input name="message" id="chat-message" type="text" placeholder="Message" required>
    <button type="submit">Send</button>
  </form>
</div>
<script>
function renderChat(messages){
  const box = document.getElementById('public-chat-box'); if(!box) return;
  box.innerHTML = '';
  messages.forEach(m=>{
    const d = document.createElement('div'); d.className='chat-message';

    const header = document.createElement('div'); header.className = 'chat-meta';
    const name = document.createElement('div'); name.className='chat-name'; name.textContent = m.name || 'Anonymous';
    const time = document.createElement('div'); time.className='chat-time'; time.textContent = m.time || '';
    header.appendChild(name); header.appendChild(time);

    const msg = document.createElement('div'); msg.className = 'chat-text'; msg.style.whiteSpace = 'pre-wrap'; msg.textContent = m.message || '';

    d.appendChild(header);
    d.appendChild(msg);
    box.appendChild(d);
  });
  box.scrollTop = box.scrollHeight;
}
function fetchChat(){
  fetch('/chat/messages?t='+Date.now(),{cache:'no-store'}).then(r=>r.json()).then(j=>{ if(j && j.messages) renderChat(j.messages); }).catch(()=>{});
}
function sendPublicChat(e){
  e.preventDefault();
  let name = document.getElementById('chat-name').value || '';
  const message = document.getElementById('chat-message').value || '';
  // sanitize: allow letters only and limit to 10 characters
  name = name.replace(/[^A-Za-z]/g, '').slice(0,10);
  if(!message.trim()) return;
  const body = new URLSearchParams(); body.append('name', name); body.append('message', message);
  fetch('/chat/send', {method:'POST', body: body}).then(()=>{ document.getElementById('chat-message').value=''; fetchChat(); }).catch(()=>{});
}
fetchChat(); setInterval(fetchChat, 3000);
</script>
""")

            self.wfile.write(f"""
<div class="stats-container">
  <div class="stat-item">
    <i class="fa-regular fa-eye stat-icon"></i>
    <div>
      <div class="stat-value" id="total-visits">{visit_count}</div>
      <div class="stat-label">Total Visits</div>
    </div>
  </div>
  <div class="stat-item">
    <i class="fa-solid fa-user-check stat-icon"></i>
    <div>
      <div class="stat-value" id="online-users">{online_users}</div>
      <div class="stat-label">Online Users</div>
    </div>
  </div>
  <div class="stat-item">
    <i class="fa-solid fa-users stat-icon"></i>
    <div>
      <div class="stat-value" id="total-accounts">{total_accounts}</div>
      <div class="stat-label">Accounts Created</div>
    </div>
  </div>
</div>
<script>
function updateMainStats() {{
  // add timestamp to avoid any intermediary caching and ensure fresh response
  fetch('/main/stats?t=' + Date.now(), {{cache: 'no-store'}})
    .then(r => r.json())
    .then(data => {{
      var elOnline = document.getElementById('online-users');
      var elVisits = document.getElementById('total-visits');
      var elAccounts = document.getElementById('total-accounts');
      if (elOnline) elOnline.textContent = data.online_users;
      if (elVisits) elVisits.textContent = data.total_visits;
      if (elAccounts) elAccounts.textContent = data.total_accounts;
    }}).catch(function(){{}});
}}
// call immediately then every second
updateMainStats();
setInterval(updateMainStats, 1000);
</script>
""".encode())
        elif path == "/ssh/":
            # Show form only when SSH service is actually online; otherwise show unavailable message
            if ssh_online:
                self.wfile.write(f"""
<div class="container">
  <div class="neo-box" style="max-width:500px;margin:0 auto;text-align:center;">
    <div style="display:flex;align-items:center;justify-content:center;gap:0.8em;margin-bottom:1.5em;">
      <img src="https://raw.githubusercontent.com/hahacrunchyrollls/logo-s/refs/heads/main/icon-ssh.png" style="height:1.8em;color:var(--accent-color);vertical-align:middle;margin-right:0.2em;">
      <h2 class="section-title" style="margin:0;">Create SSH Account</h2>
    </div>
    <div style="font-size:1rem;color:var(--text-secondary);margin-bottom:2rem;">
          Create SSH account ({html.escape(format_days_label(ssh_create_days))})
    </div>
    <form method='POST' action='/ssh/'>
      <div class="form-group">
        <label for="dnstt-username" class="form-label">
          <i class="fa-solid fa-user"></i> Username
        </label>
        <div class="form-input-container">
          <input name="username" id="dnstt-username" type="text" placeholder="Enter username" required="" pattern="[a-zA-Z0-9_]+" maxlength="10">
        </div>
      </div>
      <div class="form-group">
        <label for="dnstt-password" class="form-label">
          <i class="fa-solid fa-key"></i> Password
        </label>
        <div class="form-input-container">
          <input name="password" id="dnstt-password" type="password" placeholder="Enter password" required="" minlength="4" maxlength="32">
        </div>
      </div>
      <button type='submit' style="width:100%;max-width:400px;margin:0 auto;">
        <i class="fa-solid fa-user-plus"></i> Create Account
      </button>
    </form>
    <script>
    (function() {{
      var form = document.querySelector("form[action='/ssh/']");
      if (form) {{
        form.addEventListener('submit', function(e) {{
          if (!form.checkValidity()) return;
          e.preventDefault();
          var overlay = document.getElementById('loadingOverlay');
          if (overlay) overlay.classList.add('active');
          setTimeout(function() {{ form.submit(); }}, 5000);
        }});
      }}
    }})();
    </script>
    <a href="/main/" style="display:block;margin-top:1.5rem;text-decoration:none;">
      <button style="width:100%;max-width:400px;margin:0 auto;background:rgba(15, 23, 42, 0.6);border:1px solid var(--card-border);">
        <i class="fa-solid fa-arrow-left"></i> Back to Main
      </button>
    </a>
  </div>
</div>
""".encode())
            else:
                self.wfile.write(b"""
<div class="container">
  <div class="neo-box" style="max-width:500px;margin:0 auto;text-align:center;">
    <div style="color:var(--error);font-size:3rem;margin-bottom:1rem;">
      <i class="fa-solid fa-circle-exclamation"></i>
    </div>
    <h2 class="section-title" style="color:var(--error);">SSH Not Available</h2>
    <div style="margin:1.5rem 0;color:var(--text-secondary);">SSH service is not online. Please contact admin.</div>
    <a href="/main/" style="display:block;margin-top:1.5rem;text-decoration:none;">
      <button>
        <i class="fa-solid fa-arrow-left"></i> Back to Main
      </button>
    </a>
  </div>
</div>
""")
            return
        elif path == "/openvpn/":
            # OpenVPN creation form
            if not openvpn_online:
                self.wfile.write(b"""
<div class="container">
  <div class="neo-box" style="max-width:500px;margin:0 auto;text-align:center;">
    <div style="color:var(--error);font-size:3rem;margin-bottom:1rem;">
      <i class="fa-solid fa-circle-exclamation"></i>
    </div>
    <h2 class="section-title" style="color:var(--error);">OpenVPN Not Available</h2>
    <div style="margin:1.5rem 0;color:var(--text-secondary);">OpenVPN service is not online. Please contact admin.</div>
    <a href="/main/" style="display:block;margin-top:1.5rem;text-decoration:none;">
      <button>
        <i class="fa-solid fa-arrow-left"></i> Back to Main
      </button>
    </a>
  </div>
</div>
""")
                return
            self.wfile.write(f"""
<div class="container">
  <div class="neo-box" style="max-width:500px;margin:0 auto;text-align:center;">
    <div style="display:flex;align-items:center;justify-content:center;gap:0.8em;margin-bottom:1.5em;">
      <img src="https://raw.githubusercontent.com/hahacrunchyrollls/logo-s/refs/heads/main/icon-openvpn.png" style="height:1.8em;vertical-align:middle;margin-right:0.2em;">
      <h2 class="section-title" style="margin:0;">Create OpenVPN Account</h2>
    </div>
    <div style="font-size:1rem;color:var(--text-secondary);margin-bottom:2rem;">
          Create OpenVPN account (expires in {html.escape(format_days_label(openvpn_create_days))})
    </div>
    <form method='POST' action='/openvpn/'>
      <div class="form-group">
        <label for="openvpn-username" class="form-label">
          <i class="fa-solid fa-user"></i> Username
        </label>
        <div class="form-input-container">
          <input name="username" id="openvpn-username" type="text" placeholder="Enter username" required="" pattern="[a-zA-Z0-9_]+" maxlength="10">
        </div>
      </div>
      <div class="form-group">
        <label for="openvpn-password" class="form-label">
          <i class="fa-solid fa-key"></i> Password
        </label>
        <div class="form-input-container">
          <input name="password" id="openvpn-password" type="password" placeholder="Enter password" required="" minlength="4" maxlength="32">
        </div>
      </div>
      <button type='submit' style="width:100%;max-width:400px;margin:0 auto;">
        <i class="fa-solid fa-user-plus"></i> Create Account
      </button>
    </form>
    <script>
    (function() {{
      var form = document.querySelector("form[action='/openvpn/']");
      if (form) {{
        form.addEventListener('submit', function(e) {{
          if (!form.checkValidity()) return;
          e.preventDefault();
          var overlay = document.getElementById('loadingOverlay');
          if (overlay) overlay.classList.add('active');
          setTimeout(function() {{ form.submit(); }}, 5000);
        }});
      }}
    }})();
    </script>
    <a href="/main/" style="display:block;margin-top:1.5rem;text-decoration:none;">
      <button style="width:100%;max-width:400px;margin:0 auto;background:rgba(15, 23, 42, 0.6);border:1px solid var(--card-border);">
        <i class="fa-solid fa-arrow-left"></i> Back to Main
      </button>
    </a>
  </div>
</div>
""".encode())
            return
            if not raw_username.strip() or not password:
                error = "Username and password are required."
            elif " " in raw_username:
                error = "Username cannot contain spaces."
            elif not re.match(r'^[a-zA-Z0-9_]+$', raw_username):
                error = "Username must be alphanumeric or underscore."
            elif len(raw_username) > 20 or len(password) > 32:
                error = "Username must be at most 20 characters and password at most 32 characters."
            elif len(password) < 4:
                error = "Password must be at least 4 characters."
            elif is_username_taken_openvpn(raw_username):
                error = "Username already exists."
            if error:
                self.wfile.write(f"""
<div class="container">
  <div class="neo-box" style="max-width:500px;margin:0 auto;text-align:center;">
    <div class="success-msg" style="background:rgba(239,68,68,0.1);border-left:5px solid var(--error);color:var(--error);margin-bottom:1.2rem;">
      <i class="fa-solid fa-circle-xmark"></i>
      <div>{html.escape(error)}</div>
    </div>
    <form method='POST' action='/openvpn/'>
      <div class="form-group">
        <label for="openvpn-username" class="form-label">
          <i class="fa-solid fa-user"></i> Username
        </label>
        <div class="form-input-container">
          <input name="username" id="openvpn-username" type="text" placeholder="Enter username" required="" pattern="[a-zA-Z0-9_]+" maxlength="20" value="{html.escape(raw_username)}">
        </div>
      </div>
      <div class="form-group">
        <label for="openvpn-password" class="form-label">
          <i class="fa-solid fa-key"></i> Password
        </label>
        <div class="form-input-container">
          <input name="password" id="openvpn-password" type="password" placeholder="Enter password" required="" minlength="4" maxlength="32" value="{html.escape(password)}">
        </div>
      </div>
      <div style="margin:-0.25rem 0 1.2rem;color:var(--text-secondary);font-size:0.95rem;">
        Expiration uses the OpenVPN default set in <code>/admin/</code>.
      </div>
      <button type='submit' style="width:100%;max-width:400px;margin:0 auto;">
        <i class="fa-solid fa-user-plus"></i> Create Account
      </button>
    </form>
    <a href="/main/" style="display:block;margin-top:1.5rem;text-decoration:none;">
      <button style="width:100%;max-width:400px;margin:0 auto;background:rgba(15, 23, 42, 0.6);border:1px solid var(--card-border);">
        <i class="fa-solid fa-arrow-left"></i> Back to Main
      </button>
    </a>
  </div>
</div>
""".encode())
                self.wfile.write(HTML_FOOTER.encode())
                return
        elif path == "/vless/":
            if not vless_online:
                self.wfile.write(b"""
<div class="container">
  <div class="neo-box" style="max-width:500px;margin:0 auto;text-align:center;">
    <div style="color:var(--error);font-size:3rem;margin-bottom:1rem;">
      <i class="fa-solid fa-circle-exclamation"></i>
    </div>
    <h2 class="section-title" style="color:var(--error);">VLESS Not Available</h2>
    <div style="margin:1.5rem 0;color:var(--text-secondary);">VLESS service is not online. Please contact admin.</div>
    <a href="/main/" style="display:block;margin-top:1.5rem;text-decoration:none;">
      <button>
        <i class="fa-solid fa-arrow-left"></i> Back to Main
      </button>
    </a>
  </div>
</div>
""")
                return
            self.wfile.write(f"""
<div class="container">
  <div class="neo-box" style="max-width:500px;margin:0 auto;text-align:center;">
    <div style="display:flex;align-items:center;justify-content:center;gap:0.8em;margin-bottom:1.5em;">
      <img src="https://raw.githubusercontent.com/hahacrunchyrollls/logo-s/refs/heads/main/icon-v2ray.png" style="height:1.8em;vertical-align:middle;margin-right:0.2em;">
      <h2 class="section-title" style="margin:0;">Create VLESS Account</h2>
    </div>
    <div style="font-size:1rem;color:var(--text-secondary);margin-bottom:2rem;">
          Create VLESS account ({html.escape(format_days_label(vless_create_days))})
    </div>
    <form method='POST' action='/vless/'>
      <div class="form-group">
        <label for="vless-username" class="form-label">
          <i class="fa-solid fa-user"></i> Username
        </label>
        <div class="form-input-container">
          <input name="username" id="vless-username" type="text" placeholder="Enter username" required="" pattern="[a-zA-Z0-9_]+" maxlength="10">
        </div>
      </div>
      <!-- Bypass Options Selection -->
      <div class="form-group">
        <label for="vless-bypass" class="form-label">
          <i class="fa-solid fa-shield-alt"></i> BYPASS OPTIONS
        </label>
        <div class="form-input-container">
          <select name="bypass_option" id="vless-bypass" style="width:100%;max-width:400px;padding:12px 16px;border-radius:12px;background:rgba(15,23,42,0.6);color:var(--text-primary);border:1px solid var(--card-border);">
            <option value="">Default</option>
            <option value="DITO_UNLI_SOCIAL">DITO UNLI SOCIAL | USE TLS</option>
            <option value="SMART_POWER_ALL">SMART POWER ALL | USE Non-TLS</option>
            <option value="GLOBE_GOSHARE">GLOBE GOSHARE | USE Non-TLS</option>
          </select>
        </div>
      </div>
      <button type='submit' style="width:100%;max-width:400px;margin:0 auto;">
        <i class="fa-solid fa-user-plus"></i> Create Account
      </button>
    </form>
    <script>
    (function() {{
      var form = document.querySelector("form[action='/vless/']");
      if (form) {{
        form.addEventListener('submit', function(e) {{
          if (!form.checkValidity()) return;
          e.preventDefault();
          var overlay = document.getElementById('loadingOverlay');
          if (overlay) overlay.classList.add('active');
          setTimeout(function() {{ form.submit(); }}, 5000);
        }});
      }}
    }})();
    </script>
    <a href="/main/" style="display:block;margin-top:1.5rem;text-decoration:none;">
      <button style="width:100%;max-width:400px;margin:0 auto;background:rgba(15, 23, 42, 0.6);border:1px solid var(--card-border);">
        <i class="fa-solid fa-arrow-left"></i> Back to Main
      </button>
    </a>
  </div>
</div>
""".encode())
        elif path == "/hysteria/":
            if not hysteria_online:
                self.wfile.write(b"""
<div class="container">
  <div class="neo-box" style="max-width:500px;margin:0 auto;text-align:center;">
    <div style="color:var(--error);font-size:3rem;margin-bottom:1rem;">
      <i class="fa-solid fa-circle-exclamation"></i>
    </div>
    <h2 class="section-title" style="color:var(--error);">Hysteria Not Available</h2>
    <div style="margin:1.5rem 0;color:var(--text-secondary);">Hysteria service is not online. Please contact admin.</div>
    <a href="/main/" style="display:block;margin-top:1.5rem;text-decoration:none;">
      <button>
        <i class="fa-solid fa-arrow-left"></i> Back to Main
      </button>
    </a>
  </div>
</div>
""")
                return
            self.wfile.write(f"""
<div class="container">
  <div class="neo-box" style="max-width:500px;margin:0 auto;text-align:center;">
    <div style="display:flex;align-items:center;justify-content:center;gap:0.8em;margin-bottom:1.5em;">
      <img src="https://raw.githubusercontent.com/hahacrunchyrollls/logo-s/refs/heads/main/icon-hysteria.png" style="height:1.8em;vertical-align:middle;margin-right:0.2em;">
      <h2 class="section-title" style="margin:0;">Create Hysteria Account</h2>
    </div>
    <div style="font-size:1rem;color:var(--text-secondary);margin-bottom:2rem;">
      Create Hysteria account ({html.escape(format_days_label(hysteria_create_days))})
    </div>
    <form method='POST' action='/hysteria/'>
      <div class="form-group">
        <label for="hysteria-username" class="form-label">
          <i class="fa-solid fa-user"></i> Username
        </label>
        <div class="form-input-container">
          <input name="username" id="hysteria-username" type="text" placeholder="Enter username" required="" pattern="[a-zA-Z0-9_]+" maxlength="10">
        </div>
      </div>
      <div class="form-group">
        <label for="hysteria-password" class="form-label">
          <i class="fa-solid fa-key"></i> Password
        </label>
        <div class="form-input-container">
          <input name="password" id="hysteria-password" type="password" placeholder="Enter password" required="" minlength="4" maxlength="32">
        </div>
      </div>
      <button type='submit' style="width:100%;max-width:400px;margin:0 auto;">
        <i class="fa-solid fa-user-plus"></i> Create Account
      </button>
    </form>
    <script>
    (function() {{
      var form = document.querySelector("form[action='/hysteria/']");
      if (form) {{
        form.addEventListener('submit', function(e) {{
          if (!form.checkValidity()) return;
          e.preventDefault();
          var overlay = document.getElementById('loadingOverlay');
          if (overlay) overlay.classList.add('active');
          setTimeout(function() {{ form.submit(); }}, 5000);
        }});
      }}
    }})();
    </script>
    <a href="/main/" style="display:block;margin-top:1.5rem;text-decoration:none;"> 
      <button style="width:100%;max-width:400px;margin:0 auto;background:rgba(15, 23, 42, 0.6);border:1px solid var(--card-border);">
        <i class="fa-solid fa-arrow-left"></i> Back to Main
      </button>
    </a>
  </div>
</div>
""".encode())

        self.wfile.write(HTML_FOOTER.encode())

    def do_POST(self):
        # --- Cleanup expired users before handling request ---
        cleanup_dnstt_expired_users()
        cleanup_vless_expired_users()
        cleanup_hysteria_expired_users()
        cleanup_openvpn_expired_users()
        path = urllib.parse.urlparse(self.path).path
        length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(length).decode() if length > 0 else ""
        params = urllib.parse.parse_qs(post_data)
        dnstt_count = get_dnstt_user_count()
        vless_count = get_vless_user_count()
        hysteria_count = get_hysteria_user_count()
        openvpn_count = get_openvpn_user_count()

        # --- Handle public chat send endpoint early ---
        if path == '/chat/send':
            name = params.get('name', [''])[0].strip()[:50]
            message = params.get('message', [''])[0].strip()[:500]
            if message:
                try:
                    timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
                except Exception:
                    timestamp = str(time.time())
                with chat_lock:
                    chat_messages.append({'name': html.escape(name) if name else 'Anonymous', 'message': html.escape(message), 'time': timestamp})
                    if len(chat_messages) > MAX_CHAT_MESSAGES:
                        chat_messages.pop(0)
            self.send_response(200)
            self.send_header('Content-type','application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'ok': True}).encode())
            return

        # --- Admin actions ---
        if path == '/admin/':
            action = params.get('action', [''])[0]
            admin_ip = get_request_ip(self)
            # Login uses root system credentials
            if action == 'login':
                username = params.get('username', [''])[0]
                password = params.get('password', [''])[0]
                if verify_root_credentials(username, password):
                    log_admin_event("login", ip=admin_ip, details={"username": username or "-", "result": "authenticated"})
                    token = create_admin_session()
                    self.send_response(302)
                    self.send_header('Set-Cookie', f"admin_token={token}; HttpOnly; Path=/admin/; Max-Age={ADMIN_SESSION_DURATION}")
                    self.send_header('Location', '/admin/')
                    self.end_headers()
                    return
                else:
                    log_admin_event("login", status="failed", ip=admin_ip, details={"username": username or "-", "result": "invalid credentials"})
                    self.send_response(200)
                    self.send_header('Content-type','text/html')
                    self.end_headers()
                    self.wfile.write(HTML_HEADER.replace("<title>CREATE ACCOUNT</title>", "<title>Admin Login</title>").encode())
                    self.wfile.write(admin_login_content("Invalid root credentials.").encode())
                    self.wfile.write(HTML_FOOTER.encode())
                    return
            # All other admin actions require authentication
            if not is_admin_authenticated(self):
                log_admin_event("unauthorized_admin_action", status="failed", ip=admin_ip, details={"action": action or "-"})
                self.send_response(302)
                self.send_header('Location', '/admin/')
                self.end_headers()
                return
            success_msg = None
            error_msg = None
            if action == 'update_limit':
                new_limit = params.get('limit', [''])[0]
                if set_daily_account_limit(new_limit):
                    success_msg = "Daily account limit updated."
                    log_admin_event("update_limit", ip=admin_ip, details={"limit": new_limit, "result": success_msg})
                else:
                    error_msg = "Failed to update limit. Enter a number between 1 and 999."
                    log_admin_event("update_limit", status="failed", ip=admin_ip, details={"limit": new_limit, "result": error_msg})
            elif action == 'remove_user':
                service = params.get('service', [''])[0]
                username = params.get('username', [''])[0]
                ok, msg = perform_user_removal(service, username)
                if ok:
                    success_msg = msg
                    log_admin_event("remove_user", ip=admin_ip, details={"service": service, "username": username, "result": msg})
                else:
                    error_msg = msg
                    log_admin_event("remove_user", status="failed", ip=admin_ip, details={"service": service, "username": username, "result": msg})
            elif action == 'update_expiry':
                service = params.get('service', [''])[0]
                username = params.get('username', [''])[0]
                days = params.get('days', [''])[0]
                ok, msg = perform_expiry_update(service, username, days)
                if ok:
                    success_msg = msg
                    log_admin_event("update_expiry", ip=admin_ip, details={"service": service, "username": username, "days": days, "result": msg})
                else:
                    error_msg = msg
                    log_admin_event("update_expiry", status="failed", ip=admin_ip, details={"service": service, "username": username, "days": days, "result": msg})
            elif action == 'update_create_expiry':
                service = params.get('service', [''])[0]
                days = params.get('days', [''])[0]
                if set_create_account_expiry(service, days):
                    success_msg = f"New account expiration updated for {service.upper()}."
                    log_admin_event("update_create_expiry", ip=admin_ip, details={"service": service, "days": days, "result": success_msg})
                else:
                    error_msg = "Failed to update new account expiration. Enter 1 to 3650 days."
                    log_admin_event("update_create_expiry", status="failed", ip=admin_ip, details={"service": service, "days": days, "result": error_msg})
            else:
                error_msg = "Unknown admin action."
                log_admin_event("unknown_admin_action", status="failed", ip=admin_ip, details={"action": action or "-", "result": error_msg})

            # Redirect with message to avoid resubmission on refresh
            if success_msg:
                dest = "/admin/?success=" + urllib.parse.quote(success_msg)
            elif error_msg:
                dest = "/admin/?error=" + urllib.parse.quote(error_msg)
            else:
                dest = "/admin/"
            self.send_response(303)
            self.send_header('Location', dest)
            self.end_headers()
            return

        self.send_response(200)
        self.send_header('Content-type','text/html')
        self.end_headers()
        dnstt_count = get_dnstt_user_count()
        vless_count = get_vless_user_count()
        hysteria_count = get_hysteria_user_count()
        # --- Top bar for /main/ removed; navigation consolidated into navbar/burger ---
        main_topbar_html = ""
        self.wfile.write(HTML_HEADER.encode())

        xff = self.headers.get('X-Forwarded-For') or self.headers.get('X-Real-IP') or ''
        if xff:
            client_ip = xff.split(',')[0].strip()
        else:
            client_ip = self.client_address[0]
        cooldown_left = is_on_cooldown(client_ip, path)

        # Only apply cooldown to account creation endpoints
        if self.path in ["/ssh/", "/vless/", "/hysteria/", "/openvpn/"]:
            if cooldown_left > 0:
                self.wfile.write(HTML_HEADER.encode())
                self.wfile.write(f"""
<div class="container">
  <div class="neo-box" style="max-width:500px;margin:0 auto;text-align:center;">
    <div class="success-msg" style="background:rgba(239,68,68,0.1);border-left:5px solid var(--error);color:var(--error);margin-bottom:1.2rem;">
      <i class="fa-solid fa-clock"></i>
      <div>
        Please wait a few minutes before creating another account.
      </div>
    </div>
    <a href="/main/" style="display:block;margin-top:1.5rem;text-decoration:none;">
      <button style="width:100%;max-width:400px;margin:0 auto;background:rgba(15, 23, 42, 0.6);border:1px solid var(--card-border);">
        <i class="fa-solid fa-arrow-left"></i> Back to Main
      </button>
    </a>
  </div>
</div>
""".encode())
                self.wfile.write(HTML_FOOTER.encode())
                return
            # --- Enforce daily per-service, per-server account creation limit (Philippine date) ---
            try:
                svc_map = {
                    '/ssh/': 'ssh',
                    '/vless/': 'vless',
                    '/hysteria/': 'hysteria',
                    '/openvpn/': 'openvpn'
                }
                svc_label_map = {
                    'ssh': 'SSH',
                    'vless': 'VLESS',
                    'hysteria': 'HYSTERIA',
                    'openvpn': 'OPENVPN'
                }
                svc = svc_map.get(path)
                limit_val = get_daily_account_limit()
                if svc and get_daily_created_count(svc) >= limit_val:
                    svc_label = svc_label_map.get(svc, svc.upper())
                    self.wfile.write(HTML_HEADER.encode())
                    self.wfile.write(f"""
<div class="container">
  <div class="neo-box" style="max-width:500px;margin:0 auto;text-align:center;">
    <div class="success-msg" style="background:rgba(239,68,68,0.1);border-left:5px solid var(--error);color:var(--error);margin-bottom:1.2rem;">
      <i class="fa-solid fa-circle-exclamation"></i>
      <div>
        Daily account creation limit reached for {svc_label} on this server ({limit_val}). Try again tomorrow (Philippine time).
      </div>
    </div>
    <a href="/main/" style="display:block;margin-top:1.5rem;text-decoration:none;">
      <button style="width:100%;max-width:400px;margin:0 auto;background:rgba(15, 23, 42, 0.6);border:1px solid var(--card-border);">
        <i class="fa-solid fa-arrow-left"></i> Back to Main
      </button>
    </a>
  </div>
</div>
""" .encode())
                    self.wfile.write(HTML_FOOTER.encode())
                    return
            except Exception:
                # on error reading counter, allow creation (fail-open)
                pass
            
        if path == "/ssh/":
            raw_username = params.get('username', [''])[0]
            password = params.get('password', [''])[0]
            error = None
            days = get_create_account_expiry('ssh')
            # --- Username checks (NO FUJI-) ---
            if not raw_username.strip() or not password:
                error = "Username and password are required."
            elif " " in raw_username:
                error = "Username cannot contain spaces."
            elif not re.match(r'^[a-zA-Z0-9_]+$', raw_username):
                error = "Username must be alphanumeric or underscore."
            elif len(raw_username) > 20 or len(password) > 32:
                error = "Username must be at most 20 characters and password at most 32 characters."
            elif len(password) < 4:
                error = "Password must be at least 4 characters."
            elif is_username_taken_ssh(f"FUJI-{raw_username}"):
                error = "Username already exists."
            if error:
                self.wfile.write(f"""
<div class="container">
  <div class="neo-box" style="max-width:500px;margin:0 auto;text-align:center;">
    <div class="success-msg" style="background:rgba(239,68,68,0.1);border-left:5px solid var(--error);color:var(--error);margin-bottom:1.2rem;">
      <i class="fa-solid fa-circle-xmark"></i>
      <div>{html.escape(error)}</div>
    </div>
    <form method='POST' action='/ssh/'>
      <div class="form-group">
        <label for="dnstt-username" class="form-label">
          <i class="fa-solid fa-user"></i> Username
        </label>
        <div class="form-input-container">
          <input name="username" id="dnstt-username" type="text" placeholder="Enter username" required="" pattern="[a-zA-Z0-9_]+" maxlength="20" value="{html.escape(raw_username)}">
        </div>
      </div>
      <div class="form-group">
        <label for="dnstt-password" class="form-label">
          <i class="fa-solid fa-key"></i> Password
        </label>
        <div class="form-input-container">
          <input name="password" id="dnstt-password" type="password" placeholder="Enter password" required="" minlength="4" maxlength="32" value="{html.escape(password)}">
        </div>
      </div>
      <button type='submit' style="width:100%;max-width:400px;margin:0 auto;">
        <i class="fa-solid fa-user-plus"></i> Create Account
      </button>
    </form>
    <a href="/main/" style="display:block;margin-top:1.5rem;text-decoration:none;">
      <button style="width:100%;max-width:400px;margin:0 auto;background:rgba(15, 23, 42, 0.6);border:1px solid var(--card-border);">
        <i class="fa-solid fa-arrow-left"></i> Back to Main
      </button>
    </a>
  </div>
</div>
""".encode())
                self.wfile.write(HTML_FOOTER.encode())
                return
            username = f"FUJI-{raw_username}"
            # --- User creation logic (only if no error) ---
            expiry_timestamp = int(time.time()) + days * 86400
            expiry_formatted = time.strftime("%b %d, %Y %I:%M:%S %p", time.localtime(expiry_timestamp))
            ip_addr = get_ipv4()
            nameserver = get_nameserver()
            public_key = get_public_key()
            try:
                os.makedirs('/var/lib/regular_users', exist_ok=True)
                with open(f'/var/lib/regular_users/{username}', 'w') as f:
                    f.write(str(expiry_timestamp))
                subprocess.call(['/usr/sbin/useradd', '-m', '-s', '/bin/false', username])
                result = subprocess.run(['/usr/sbin/chpasswd'], input=f"{username}:{password}".encode())
                if result.returncode != 0:
                    # Remove user if password set fails
                    subprocess.call(['/usr/sbin/userdel', '-r', username])
                    os.remove(f'/var/lib/regular_users/{username}')
                    self.wfile.write(f"<div>Error: Failed to set password for user.</div>".encode())
                    self.wfile.write(HTML_FOOTER.encode())
                    return
            except Exception as e:
                self.wfile.write(f"<div>Error: {html.escape(str(e))}</div>".encode())
                self.wfile.write(HTML_FOOTER.encode())
                return
            set_cooldown(client_ip, "/ssh/")
            # --- Schedule deletion with atd after configured duration ---
            if subprocess.call(['/usr/bin/which', 'at'], stdout=subprocess.DEVNULL) == 0:
                remove_cmd = (
                    f"/usr/bin/python3 -c 'import os; "
                    f"user=\"{username}\"; "
                    f"path=f\"/var/lib/regular_users/{{user}}\"; "
                    f"try: os.remove(path) "
                    f"except: pass; "
                    f"os.system(\"/usr/sbin/userdel -r %s\" % user)'"
                )
                subprocess.call(
                    f"echo \"{remove_cmd}\" | /usr/bin/at now + {days} days",
                    shell=True
                )
            # --- End schedule ---
            # --- Download info for SSH (was DNSTT) ---
            dnstt_txt = f"""SSH USER INFO

  Username: {username}
  Password: {password}
  Expires: {expiry_formatted} ({format_days_label(days)})
  IP: {ip_addr}
  Host: {get_domain()}
  Nameserver: {nameserver}
  Public Key: {public_key}

  PORTS
  SSH : 22, 80, 443
  SSL : 80, 443, 444
  SSH WS + SSL : 80, 443, 444
  SSH WS : 80, 443
  SQUID : 8080, 80, 443, 444
  DNSTT + WS + SSL : 80, 443, 444
  DNSTT + WS : 80, 443, 444
  """
            try:
              increment_daily_created_count('ssh')
            except Exception:
              pass

            self.wfile.write(
                f"""<div class="container">
    <div class="neo-box neo-box-accent1">
        <div class="success-msg">
          <i class="fa-solid fa-circle-check"></i>
          <div>Success! Your SSH account has been created.</div>
        </div>
        <div class="info-grid">
          <div>Username:</div><div>{html.escape(username)}</div>
          <div>Password:</div><div>{html.escape(password)}</div>
          <div>Expires:</div><div>{expiry_formatted} ({html.escape(format_days_label(days))})</div>
          <div>IP:</div><div>{html.escape(ip_addr)}</div>
          <div>Host:</div><div>{html.escape(get_domain())}</div>
          <div>Nameserver:</div><div>{html.escape(nameserver)}</div>
          <div>Public Key:</div>
          <div style="padding:0;margin:0;">
            <div class="link-box" style="margin:0 0 0 0;padding:0.8em 1em;">
              <div style="display:flex;align-items:center;gap:0.5em;">
                <input type="text" readonly value="{html.escape(public_key)}">
                <sl-copy-button value="{html.escape(public_key)}"></sl-copy-button>
              </div>
            </div>
          </div>
        </div>
        <div class="info-grid" style="margin-top:1.5em;">
          <div style="font-weight:600;">PORTS</div><div></div>
          <div>SSH:</div><div>22, 80, 443</div>
          <div>SSH SSL:</div><div>80, 443, 444</div>
          <div>SSH WS + SSL:</div><div>80, 443, 444</div>
          <div>SSH WS:</div><div>80, 443, 444</div>
          <div>SQUID:</div><div>8080, 80, 443, 444</div>
          <div>DNSTT + WS + SSL:</div><div>80, 443, 444</div>
          <div>DNSTT + WS:</div><div>80, 443, 444</div>
        </div>
        <button onclick="downloadTxt('ssh_user_{html.escape(username)}.txt', `{dnstt_txt}`)" style="width:100%;margin-top:1.5rem;">
          <i class="fa-solid fa-download"></i> Download Info
        </button>
        <a href='/main/'><button style="width:100%;margin-top:1rem;background:rgba(15, 23, 42, 0.6);border:1px solid var(--card-border);">
          <i class="fa-solid fa-arrow-left"></i> Back to Main
        </button></a>
    </div>
  </div>
  <script>
  function downloadTxt(filename, text) {{
    var element = document.createElement('a');
    element.setAttribute('href', 'data:text/plain;charset=utf-8,' + encodeURIComponent(text));
    element.setAttribute('download', filename);
    element.style.display = 'none';
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
  }}
  </script>
  """.encode())
        elif path == "/openvpn/":
            raw_username = params.get('username', [''])[0]
            password = params.get('password', [''])[0]
            days = get_create_account_expiry('openvpn')
            error = None
            if not raw_username.strip() or not password:
                error = "Username and password are required."
            elif " " in raw_username:
                error = "Username cannot contain spaces."
            elif not re.match(r'^[a-zA-Z0-9_]+$', raw_username):
                error = "Username must be alphanumeric or underscore."
            elif len(raw_username) > 20 or len(password) > 32:
                error = "Username must be at most 20 characters and password at most 32 characters."
            elif len(password) < 4:
                error = "Password must be at least 4 characters."
            elif is_username_taken_openvpn(raw_username):
                error = "Username already exists."
            if error:
                self.wfile.write(f"""
<div class="container">
  <div class="neo-box" style="max-width:500px;margin:0 auto;text-align:center;">
    <div class="success-msg" style="background:rgba(239,68,68,0.1);border-left:5px solid var(--error);color:var(--error);margin-bottom:1.2rem;">
      <i class="fa-solid fa-circle-xmark"></i>
      <div>{html.escape(error)}</div>
    </div>
    <form method='POST' action='/openvpn/'>
      <div class="form-group">
        <label for="openvpn-username" class="form-label">
          <i class="fa-solid fa-user"></i> Username
        </label>
        <div class="form-input-container">
          <input name="username" id="openvpn-username" type="text" placeholder="Enter username" required="" pattern="[a-zA-Z0-9_]+" maxlength="20" value="{html.escape(raw_username)}">
        </div>
      </div>
      <div class="form-group">
        <label for="openvpn-password" class="form-label">
          <i class="fa-solid fa-key"></i> Password
        </label>
        <div class="form-input-container">
          <input name="password" id="openvpn-password" type="password" placeholder="Enter password" required="" minlength="4" maxlength="32" value="{html.escape(password)}">
        </div>
      </div>
      <button type='submit' style="width:100%;max-width:400px;margin:0 auto;">
        <i class="fa-solid fa-user-plus"></i> Create Account
      </button>
    </form>
    <a href="/main/" style="display:block;margin-top:1.5rem;text-decoration:none;">
      <button style="width:100%;max-width:400px;margin:0 auto;background:rgba(15, 23, 42, 0.6);border:1px solid var(--card-border);">
        <i class="fa-solid fa-arrow-left"></i> Back to Main
      </button>
    </a>
  </div>
</div>
""".encode())
                self.wfile.write(HTML_FOOTER.encode())
                return
            # prefix username for storage and filepaths
            username = f"FUJI-{raw_username}"
            info, err = add_openvpn_user(username, password, days)
            if err:
                self.wfile.write(f"""
<div class="container">
  <div class="neo-box" style="max-width:500px;margin:0 auto;text-align:center;">
    <div class="success-msg" style="background:rgba(239,68,68,0.1);border-left:5px solid var(--error);color:var(--error);margin-bottom:1.2rem;">
      <i class="fa-solid fa-circle-xmark"></i>
      <div>{html.escape(err)}</div>
    </div>
    <form method='POST' action='/openvpn/'>
      <div class="form-group">
        <label for="openvpn-username" class="form-label">
          <i class="fa-solid fa-user"></i> Username
        </label>
        <div class="form-input-container">
          <input name="username" id="openvpn-username" type="text" placeholder="Enter username" required="" pattern="[a-zA-Z0-9_]+" maxlength="20" value="{html.escape(raw_username)}">
        </div>
      </div>
      <div class="form-group">
        <label for="openvpn-password" class="form-label">
          <i class="fa-solid fa-key"></i> Password
        </label>
        <div class="form-input-container">
          <input name="password" id="openvpn-password" type="password" placeholder="Enter password" required="" minlength="4" maxlength="32" value="{html.escape(password)}">
        </div>
      </div>
      <button type='submit' style="width:100%;max-width:400px;margin:0 auto;">
        <i class="fa-solid fa-user-plus"></i> Create Account
      </button>
    </form>
    <a href="/main/" style="display:block;margin-top:1.5rem;text-decoration:none;">
      <button style="width:100%;max-width:400px;margin:0 auto;background:rgba(15, 23, 42, 0.6);border:1px solid var(--card-border);">
        <i class="fa-solid fa-arrow-left"></i> Back to Main
      </button>
    </a>
  </div>
</div>
""".encode())
                self.wfile.write(HTML_FOOTER.encode())
                return
            set_cooldown(client_ip, "/openvpn/")
            try:
              increment_daily_created_count('openvpn')
            except Exception:
              pass
            # compute human-readable expiry and remaining days
            if days == 0:
                expiry_display = "never"
                days_display = "never"
            else:
                expiry_ts = int(time.time()) + days * 86400
                try:
                    expiry_display = time.strftime("%F", time.localtime(expiry_ts))
                except Exception:
                    expiry_display = str(expiry_ts)
                now_ts = int(time.time())
                if expiry_ts <= now_ts:
                    days_left = 0
                else:
                    days_left = (expiry_ts - now_ts) // 86400
                days_display = str(days_left)
            ovpn_filename = json.dumps(f"{info['username']}.ovpn")
            ovpn_content_js = json.dumps(info.get('ovpn_content', ''))
            download_link_js = json.dumps(info.get('download_link', ''))
            self.wfile.write(f"""
<div class="container">
  <div class="neo-box neo-box-accent1">
      <div class="success-msg">
        <i class="fa-solid fa-circle-check"></i>
        <div>Success! Your OpenVPN client has been created.</div>
      </div>
      <div class="info-grid">
        <div>Username:</div><div>{html.escape(info['username'])}</div>
        <div>Password:</div><div>{html.escape(info['password'])}</div>
        <div>IP:</div><div>{html.escape(info['SERVER_IP'] or '')}</div>
        <div>Host:</div><div>{html.escape(info['host_display'])}</div>
        <div>Nameserver:</div><div>{html.escape(info['nameserver'])}</div>
        <div>Public Key:</div><div>{html.escape(info['public_key'])}</div>
        <div>Expires:</div><div>{html.escape(info['expiry_display'])}</div>
        <div>Days Left:</div><div>{html.escape(info['days_display'])}</div>
      </div>
      <div style="text-align:center; margin-top:1em;">
          <button id="ovpn-download" style="width:100%;margin-top:1.5rem;" onclick="downloadOvpnFile()">
            <i class="fa-solid fa-download"></i> Download OVPN File
          </button>
      </div>
      <a href='/main/'><button style="width:100%;margin-top:1rem;background:rgba(15, 23, 42, 0.6);border:1px solid var(--card-border);">
        <i class="fa-solid fa-arrow-left"></i> Back to Main
      </button></a>
  </div>
</div>
<script>
  const ovpnFilename = {ovpn_filename};
  const ovpnContent = {ovpn_content_js};
  const ovpnDownloadLink = {download_link_js};
  function downloadOvpnFile() {{
    if (ovpnContent) {{
      const blob = new Blob([ovpnContent], {{ type: 'application/x-openvpn-profile' }});
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = ovpnFilename;
      document.body.appendChild(anchor);
      anchor.click();
      document.body.removeChild(anchor);
      setTimeout(function() {{ URL.revokeObjectURL(url); }}, 1000);
      return;
    }}
    if (ovpnDownloadLink) {{
      window.location.href = ovpnDownloadLink;
    }}
  }}
</script>
""".encode())
            return
        elif path == "/vless/":
            raw_username = params.get('username', [''])[0]
            bypass_option = params.get('bypass_option', [''])[0].strip()
            if bypass_option == "DITO_UNLI_SOCIAL":
                sni = "tiktok.jericoo.xyz"
                host_nontls = ""
            elif bypass_option == "SMART_POWER_ALL":
                sni = ""
                host_nontls = "gecko-sg.tiktokv.com"
            elif bypass_option == "GLOBE_GOSHARE":
                sni = ""
                host_nontls = "gecko-sg.tiktokv.com"
            # STS_NO_LOAD option removed; default mappings below
            else:
                sni = ""
                host_nontls = ""
            error = None
            if not raw_username:
                error = "Username is required."
            elif " " in raw_username or raw_username.strip() == "":
                error = "Username cannot be blank or contain spaces."
            elif not re.match(r'^[a-zA-Z0-9_]+$', raw_username):
                error = "Username must be alphanumeric or underscore."
            elif len(raw_username) > 20:
                error = "Username must be at most 20 characters."
            elif is_username_taken_vless(f"FUJI-{raw_username}"):
                error = "Username already exists."
            if error:
                username = raw_username
                bypass_option = "DITO_UNLI_SOCIAL" if sni == "tiktok.jericoo.xyz" else "SMART_POWER_ALL" if host_nontls == "gecko-sg.tiktokv.com" else "GLOBE_GOSHARE" if host_nontls == "gecko-sg.tiktokv.com" else ""
                self.wfile.write(f"""
<div class="container">
  <div class="neo-box" style="max-width:500px;margin:0 auto;text-align:center;">
    <div class="success-msg" style="background:rgba(239,68,68,0.1);border-left:5px solid var(--error);color:var(--error);margin-bottom:1.2rem;">
      <i class="fa-solid fa-circle-xmark"></i>
      <div>{html.escape(error)}</div>
    </div>
    <form method='POST' action='/vless/'>
      <div class="form-group">
        <label for="vless-username" class="form-label">
          <i class="fa-solid fa-user"></i> Username
        </label>
        <div class="form-input-container">
          <input name="username" id="vless-username" type="text" placeholder="Enter username" required="" pattern="[a-zA-Z0-9_]+" maxlength="10" value="{html.escape(username)}">
        </div>
      </div>
      <!-- Bypass Options Selection -->
      <div class="form-group">
        <label for="vless-bypass" class="form-label">
          <i class="fa-solid fa-shield-alt"></i> Bypass Options
        </label>
        <div class="form-input-container">
          <select name="bypass_option" id="vless-bypass" style="width:100%;max-width:400px;padding:12px 16px;border-radius:12px;background:rgba(15,23,42,0.6);color:var(--text-primary);border:1px solid var(--card-border);">
            <option value=""{" selected" if bypass_option == "" else ""}>Default</option>
            <option value="DITO_UNLI_SOCIAL"{" selected" if bypass_option == "DITO_UNLI_SOCIAL" else ""}>DITO UNLI SOCIAL | USE TLS</option>
            <option value="SMART_POWER_ALL"{" selected" if bypass_option == "SMART_POWER_ALL" else ""}>SMART POWER ALL | USE Non-TLS</option>
            <option value="GLOBE_GOSHARE"{" selected" if bypass_option == "GLOBE_GOSHARE" else ""}>GLOBE GOSHARE | USE Non-TLS</option>
          </select>
        </div>
      </div>
      <button type='submit' style="width:100%;max-width:400px;margin:0 auto;">
        <i class="fa-solid fa-user-plus"></i> Create Account
      </button>
    </form>
    <a href="/main/" style="display:block;margin-top:1.5rem;text-decoration:none;">
      <button style="width:100%;max-width:400px;margin:0 auto;background:rgba(15, 23, 42, 0.6);border:1px solid var(--card-border);">
        <i class="fa-solid fa-arrow-left"></i> Back to Main
      </button>
    </a>
  </div>
</div>
""".encode())
                self.wfile.write(HTML_FOOTER.encode())
                return
            username = f"FUJI-{raw_username}"
            set_cooldown(client_ip, "/vless/")
            # --- User creation logic (only if no error) ---
            days = get_create_account_expiry('vless')
            uuid_tls, uuid_nontls, err = add_vless_user(username, days)
            if err:
                self.wfile.write(f"""
<div class="container">
  <div class="neo-box" style="color:#fff;text-align:center;">
    <h2 class="section-title" style="color:#fff;">Error</h2>
    <div style="margin-bottom:1.5rem;">{html.escape(err)}</div>
    <a href='/main/'>
      <button type='button' style="width:100%;background:#222;color:#fff;font-weight:bold;border-radius:8px;padding:12px 0;font-size:1.1em;border:1.5px solid #fff;">Back to Main</button>
    </a>
  </div>
</div>
""".encode())
                self.wfile.write(HTML_FOOTER.encode())
            else:
                domain = get_domain()
                # --- SNI logic for TLS link ---
                sni_param = f"&sni={sni}" if sni else ""
                address = "tiktok.jericoo.xyz" if sni == "tiktok.jericoo.xyz" else domain
                link_tls = f"vless://{uuid_tls}@{address}:443?encryption=none&type=ws&security=tls&host={domain}&path=/vless{sni_param}#{username}"
                host_nontls_final = host_nontls if host_nontls else domain
                link_nontls = f"vless://{uuid_nontls}@{domain}:80?encryption=none&type=ws&host={host_nontls_final}&path=/vless#{username}"
                expiry_timestamp = int(time.time()) + (days * 86400)
                expiry_formatted = time.strftime("%b %d, %Y %I:%M:%S %p", time.localtime(expiry_timestamp))
                ip_addr = get_ipv4()
                nameserver = get_nameserver()
                public_key = get_public_key()
                vless_txt = f"""VLESS USER INFO

  Username: {username}
  Expires: {expiry_formatted} ({format_days_label(days)})
  Domain: {domain}
  IP: {ip_addr}
  Nameserver: {nameserver}
  Public Key: {public_key}

  VLESS WS TLS:
  {link_tls}

  VLESS WS Non-TLS:
  {link_nontls}
  """
                try:
                  increment_daily_created_count('vless')
                except Exception:
                  pass

                self.wfile.write(
                    f"""<div class="container">
    <div class="neo-box neo-box-accent1">
        <div class="success-msg">
          <i class="fa-solid fa-circle-check"></i>
          <div>Success! Your VLESS account has been created.</div>
        </div>
        <div class="info-grid">
          <div>Username:</div><div>{html.escape(username)}</div>
          <div>Expires:</div><div>{expiry_formatted} ({html.escape(format_days_label(days))})</div>
          <div>Domain:</div><div>{html.escape(domain)}</div>
          <div>IP:</div><div>{html.escape(ip_addr)}</div>
          <div>Nameserver:</div>
          <div>{html.escape(nameserver)}</div>
          <div>Public Key:</div>
          <div style="padding:0;margin:0;">
            <div class="link-box" style="margin:0 0 0 0;padding:0.8em 1em;">
              <div style="display:flex;align-items:center;gap:0.5em;">
                <input type="text" readonly value="{html.escape(public_key)}">
                <sl-copy-button value="{html.escape(public_key)}"></sl-copy-button>
              </div>
            </div>
          </div>
        </div>
                <div class="link-box">
          <div class="link-title tls"><img src="https://raw.githubusercontent.com/hahacrunchyrollls/logo-s/refs/heads/main/icon-v2ray.png" style="height:1.05em;vertical-align:middle;margin-right:0.4em;"> VLESS WS TLS 443</div>
          <div style="display:flex;align-items:center;gap:0.4em;">
            <input type="text" readonly value="{html.escape(link_tls)}">
            <sl-copy-button value="{html.escape(link_tls)}"></sl-copy-button>
          </div>
        </div>
        <div class="link-box">
          <div class="link-title tls"><img src="https://raw.githubusercontent.com/hahacrunchyrollls/logo-s/refs/heads/main/icon-v2ray.png" style="height:1.05em;vertical-align:middle;margin-right:0.4em;"> VLESS WS Non-TLS 80</div>
          <div style="display:flex;align-items:center;gap:0.4em;">
            <input type="text" readonly value="{html.escape(link_nontls)}">
            <sl-copy-button value="{html.escape(link_nontls)}"></sl-copy-button>
          </div>
        </div>
        <button onclick="downloadTxt('vless_user_{html.escape(username)}.txt', `{vless_txt}`)" style="width:100%;margin-top:1.5rem;">
          <i class="fa-solid fa-download"></i> Download Info
        </button>
        <a href='/main/'><button style="width:100%;margin-top:1rem;background:rgba(15, 23, 42, 0.6);border:1px solid var(--card-border);">
          <i class="fa-solid fa-arrow-left"></i> Back to Main
        </button></a>
    </div>
  </div>
  <script>
  function downloadTxt(filename, text) {{
    var element = document.createElement('a');
    element.setAttribute('href', 'data:text/plain;charset=utf-8,' + encodeURIComponent(text));
    element.setAttribute('download', filename);
    element.style.display = 'none';
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
  }}
  </script>
  """.encode())
        elif path == "/hysteria/":
            raw_username = params.get('username', [''])[0]
            password = params.get('password', [''])[0]
            error = None
            # --- Username checks (BEFORE user creation, NO FUJI-) ---
            if not raw_username or not password:
                error = "Username and password are required."
            elif " " in raw_username:
                error = "Username cannot contain spaces."
            elif not re.match(r'^[a-zA-Z0-9_]+$', raw_username):
                error = "Username must be alphanumeric or underscore."
            elif len(raw_username) > 20 or len(password) > 32:
                error = "Username must be at most 20 characters and password at most 32 characters."
            elif len(password) < 4:
                error = "Password must be at least 4 characters."
            elif is_username_taken_hysteria(f"FUJI-{raw_username}"):
                error = "Username already exists."
            if error:
                self.wfile.write(f"""
<div class="container">
  <div class="neo-box" style="max-width:500px;margin:0 auto;text-align:center;">
    <div class="success-msg" style="background:rgba(239,68,68,0.1);border-left:5px solid var(--error);color:var(--error);margin-bottom:1.2rem;">
      <i class="fa-solid fa-circle-xmark"></i>
      <div>{html.escape(error)}</div>
    </div>
    <form method='POST' action='/hysteria/'>
      <div class="form-group">
        <label for="hysteria-username" class="form-label">
          <i class="fa-solid fa-user"></i> Username
        </label>
        <div class="form-input-container">
          <input name="username" id="hysteria-username" type="text" placeholder="Enter username" required="" pattern="[a-zA-Z0-9_]+" maxlength="20" value="{html.escape(raw_username)}">
        </div>
      </div>
      <div class="form-group">
        <label for="hysteria-password" class="form-label">
          <i class="fa-solid fa-key"></i> Password
        </label>
        <div class="form-input-container">
          <input name="password" id="hysteria-password" type="password" placeholder="Enter password" required="" minlength="4" maxlength="32" value="{html.escape(password)}">
        </div>
      </div>
      <button type='submit' style="width:100%;max-width:400px;margin:0 auto;">
        <i class="fa-solid fa-user-plus"></i> Create Account
      </button>
    </form>
    <a href="/main/" style="display:block;margin-top:1.5rem;text-decoration:none;">
      <button style="width:100%;max-width:400px;margin:0 auto;background:rgba(15, 23, 42, 0.6);border:1px solid var(--card-border);">
        <i class="fa-solid fa-arrow-left"></i> Back to Main
      </button>
    </a>
  </div>
</div>
""".encode())
                self.wfile.write(HTML_FOOTER.encode())
                return
            set_cooldown(client_ip, "/hysteria/")
            username = f"FUJI-{raw_username}"  # Only add prefix for storage
            days = get_create_account_expiry('hysteria')
            ok, expiry_timestamp = add_hysteria_user(username, password, days)
            if not ok:
                self.wfile.write(f"""
<div class="container">
  <div class="neo-box" style="color:#fff;text-align:center;">
    <h2 class="section-title" style="color:#fff;">Error</h2>
    <div style="margin-bottom:1.5rem;">{html.escape(str(expiry_timestamp))}</div>
    <a href='/main/'>
      <button type='button' style="width:100%;background:#222;color:#fff;font-weight:bold;border-radius:8px;padding:12px 0;font-size:1.1em;border:1.5px solid #fff;">Back to Main</button>
    </a>
  </div>
</div>
""".encode())
                self.wfile.write(HTML_FOOTER.encode())
                return
            expiry_formatted = time.strftime("%b %d, %Y %I:%M:%S %p", time.localtime(expiry_timestamp))
            domain = get_domain()
            ip_addr = get_ipv4()
            obfs = get_hysteria_obfs()
            hysteria_url = build_hysteria_uri(username, password, domain, obfs)
            hysteria_txt = f"""HYSTERIA USER INFO

  Username: {username}
  Password: {password}
  Expires: {expiry_formatted} ({format_days_label(days)})
  Domain: {domain}
  IP: {ip_addr}
  Obfs: {obfs}

  Hysteria1 URL:
  {hysteria_url}
  """
            try:
              increment_daily_created_count('hysteria')
            except Exception:
              pass

            self.wfile.write(
                f"""<div class="container">
    <div class="neo-box neo-box-accent1">
        <div class="success-msg">
          <i class="fa-solid fa-circle-check"></i>
          <div>Success! Your Hysteria account has been created.</div>
        </div>
        <div class="info-grid">
          <div>Username:</div><div>{html.escape(username)}</div>
          <div>Password:</div><div>{html.escape(password)}</div>
          <div>Expires:</div><div>{expiry_formatted} ({html.escape(format_days_label(days))})</div>
          <div>Domain:</div><div>{html.escape(domain)}</div>
          <div>IP:</div><div>{html.escape(ip_addr)}</div>
          <div>Obfs:</div><div>{html.escape(obfs)}</div>
        </div>
        <div class="link-box">
          <div class="link-title tls"><img src="https://raw.githubusercontent.com/hahacrunchyrollls/logo-s/refs/heads/main/icon-hysteria.png" style="height:1.05em;vertical-align:middle;margin-right:0.4em;"> Hysteria1 URL</div>
          <div style="display:flex;align-items:center;gap:0.4em;">
            <input type="text" readonly value="{html.escape(hysteria_url, quote=True)}">
            <sl-copy-button value="{html.escape(hysteria_url, quote=True)}"></sl-copy-button>
          </div>
        </div>
        <button onclick="downloadTxt('hysteria_user_{html.escape(username)}.txt', `{hysteria_txt}`)" style="width:100%;margin-top:1.5rem;">
          <i class="fa-solid fa-download"></i> Download Info
        </button>
        <a href='/main/'><button style="width:100%;margin-top:1rem;background:rgba(15, 23, 42, 0.6);border:1px solid var(--card-border);">
          <i class="fa-solid fa-arrow-left"></i> Back to Main
        </button></a>
    </div>
  </div>
  <script>
  function downloadTxt(filename, text) {{
    var element = document.createElement('a');
    element.setAttribute('href', 'data:text/plain;charset=utf-8,' + encodeURIComponent(text));
    element.setAttribute('download', filename);
    element.style.display = 'none';
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
  }}
  </script>
  """.encode())


        if path == "/hostname-to-ip/":
            hostname = params.get('hostname', [''])[0].strip()
            import socket
            if not hostname:
                self.wfile.write('<div style="color:var(--error);margin-top:1em;">Please enter a hostname.</div>'.encode())
            else:
                try:
                    ip = socket.gethostbyname(hostname)
                    self.wfile.write(f"""
<div style="margin-top:1em;">
  <div style="color:var(--success);font-weight:600;">
    <i class="fa-solid fa-circle-check"></i> Hostname: <span style="color:var(--accent-color);">{html.escape(hostname)}</span>
  </div>
  <div style="margin-top:0.7em;">
    <span style="font-weight:600;">IP Address:</span>
    <span style="color:var(--primary-color);font-size:1.1em;">{html.escape(ip)}</span>
  </div>
</div>
""".encode())
                except Exception:
                    self.wfile.write(f'<div style="color:var(--error);margin-top:1em;"><i class="fa-solid fa-circle-xmark"></i> Could not resolve hostname: {html.escape(hostname)}</div>'.encode())
        elif path == "/ip-lookup/":
            ip = params.get('ip', [''])[0].strip()
            if not ip:
                ip = client_ip
            try:
                api = f"http://ip-api.com/json/{urllib.parse.quote(ip)}?fields=status,message,country,regionName,city,zip,lat,lon,isp,org,as,query,timezone,reverse,mobile,proxy,hosting"
                with urllib.request.urlopen(api, timeout=6) as resp:
                    data = json.load(resp)
            except Exception:
                self.wfile.write(f'<div style="color:var(--error);margin-top:1em;">Error contacting geolocation service for {html.escape(ip)}.</div>'.encode())
                self.wfile.write(HTML_FOOTER.encode())
                return
            if data.get('status') != 'success':
                msg = data.get('message', 'Lookup failed')
                self.wfile.write(f'<div style="color:var(--error);margin-top:1em;"><i class="fa-solid fa-circle-xmark"></i> Lookup failed for {html.escape(ip)}: {html.escape(msg)}</div>'.encode())
            else:
                country = data.get('country','-')
                region = data.get('regionName','-')
                city = data.get('city','-')
                zipc = data.get('zip','-')
                lat = data.get('lat','-')
                lon = data.get('lon','-')
                isp = data.get('isp','-')
                org = data.get('org','-')
                asn = data.get('as','-')
                timezone = data.get('timezone','-')
                query = data.get('query', ip)
                mobile = data.get('mobile', False)
                proxy = data.get('proxy', False)
                hosting = data.get('hosting', False)
                self.wfile.write(f"""
<div style="margin-top:1em;">
  <div style="color:var(--success);font-weight:600;"><i class="fa-solid fa-circle-check"></i> IP: <span style="color:var(--accent-color);">{html.escape(query)}</span></div>
  <div style="margin-top:0.8em;display:grid;grid-template-columns:1fr 1fr;gap:0.6rem;">
    <div class="link-box"><strong>Country:</strong> {html.escape(country)}</div>
    <div class="link-box"><strong>Region:</strong> {html.escape(region)}</div>
    <div class="link-box"><strong>City:</strong> {html.escape(city)}</div>
    <div class="link-box"><strong>ZIP:</strong> {html.escape(zipc)}</div>
    <div class="link-box"><strong>Latitude:</strong> {html.escape(str(lat))}</div>
    <div class="link-box"><strong>Longitude:</strong> {html.escape(str(lon))}</div>
    <div class="link-box"><strong>ISP:</strong> {html.escape(isp)}</div>
    <div class="link-box"><strong>Org:</strong> {html.escape(org)}</div>
    <div class="link-box"><strong>ASN:</strong> {html.escape(asn)}</div>
    <div class="link-box"><strong>Timezone:</strong> {html.escape(timezone)}</div>
    <div class="link-box"><strong>Mobile:</strong> {html.escape(str(bool(mobile)))}</div>
    <div class="link-box"><strong>Proxy:</strong> {html.escape(str(bool(proxy)))}</div>
    <div class="link-box"><strong>Hosting:</strong> {html.escape(str(bool(hosting)))}</div>
  </div>
</div>
""".encode())
        else:
            self.wfile.write(b"<div class='container'><div class='neo-box' style='text-align:center;'><h2>Unknown POST</h2></div></div>")
            self.wfile.write(HTML_FOOTER.encode())

VISIT_FILE = "/etc/visits"

# Ensure /etc/visits exists at startup
if not os.path.exists(VISIT_FILE):
    try:
        with open(VISIT_FILE, "w") as f:
            # Initial structure
            f.write(json.dumps({
                "total_visits": 0,
                "total_accounts": 0,
                "daily": {}
            }))
    except Exception:
        pass

def load_visit_data():
    try:
        with open(VISIT_FILE, "r") as f:
            data = json.load(f)
            # Ensure keys exist
            if "total_visits" not in data: data["total_visits"] = 0
            if "total_accounts" not in data: data["total_accounts"] = 0
            if "daily" not in data: data["daily"] = {}
            return data
    except Exception:
        return {"total_visits": 0, "total_accounts": 0, "daily": {}}

def cleanup_dnstt_expired_users():
    path = '/var/lib/regular_users'
    now = int(time.time())
    if not os.path.isdir(path):
        return
    for fname in os.listdir(path):
        fpath = os.path.join(path, fname)
        if os.path.isfile(fpath):
            try:
                with open(fpath, 'r') as f:
                    raw = f.read().strip()
                # tolerate files that contain extra text, take first integer found
                m = re.search(r'(\d+)', raw)
                if m:
                    expiry = int(m.group(1))
                else:
                    # if no timestamp found, treat as already expired
                    expiry = 0
                if expiry < now:
                    # Try to remove system user (ignore errors) then always remove the file
                    try:
                        subprocess.call(['/usr/sbin/userdel', '-r', fname])
                    except Exception as e:
                        logging.debug(f"cleanup_dnstt_expired_users: userdel failed for {fname}: {e}")
                    try:
                        os.remove(fpath)
                    except Exception as e:
                        logging.debug(f"cleanup_dnstt_expired_users: failed to remove {fpath}: {e}")
            except Exception as e:
                logging.debug(f"cleanup_dnstt_expired_users: error processing {fpath}: {e}")

def save_visit_data(data):
    try:
        with open(VISIT_FILE, "w") as f:
            json.dump(data, f)
    except Exception:
        pass

def update_today_stats(visit_inc, account_created):
    data = load_visit_data()
    today = datetime.now().strftime("%Y-%m-%d")
    # Update daily
    if today not in data["daily"]:
        data["daily"][today] = {"visits": 0, "accounts": 0}
    data["daily"][today]["visits"] += visit_inc
    data["daily"][today]["accounts"] = account_created
    # Update totals
    data["total_visits"] += visit_inc
    data["total_accounts"] = account_created
    # Keep only last 14 days
    keys = sorted(data["daily"].keys())[-14:]
    data["daily"] = {k: data["daily"][k] for k in keys}
    save_visit_data(data)
    return data


def get_cloud_icon_url():
    # Always use the provided cloud icon for main card
    return "https://raw.githubusercontent.com/hahacrunchyrollls/logo-s/refs/heads/main/CloudVPN.png"



def make_links_clickable(text):
    # Find URLs and wrap them in <a>
    url_pattern = r'(https?://[^\s]+)'
    return re.sub(url_pattern, r'<a href="\1" target="_blank" style="color:#06b6d4;text-decoration:underline;">\1</a>', text)


# --- Load visit count from file on startup ---
visit_data = load_visit_data()
visit_count = visit_data["total_visits"]

if __name__ == "__main__":
    try:
        with socketserver.TCPServer(('127.0.0.1', PORT), Handler) as httpd:
            print(f"Serving on port {PORT}")
            httpd.serve_forever()
    except Exception as e:
        logging.error(f"Server failed to start: {e}")
