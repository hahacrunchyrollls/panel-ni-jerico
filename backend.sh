#!/usr/bin/env bash
set -euo pipefail

APP_NAME="fuji-backend"
APP_DIR="/opt/fuji-backend"
GO_FILE="$APP_DIR/main.go"
BIN_FILE="/usr/local/bin/fuji-backend"
ENV_FILE="/etc/fuji-backend.env"
SERVICE_FILE="/etc/systemd/system/fuji-backend.service"
SERVICE_WANTS_LINK="/etc/systemd/system/multi-user.target.wants/fuji-backend.service"
ACTION="${1:-install}"

usage() {
  cat <<EOF
Usage: bash $0 [install|uninstall]

  install     Build and install the FUJI backend service.
  uninstall   Stop the FUJI backend service and remove its installed files.
EOF
}

safe_remove_file() {
  local path="$1"
  [[ -n "$path" && "$path" != "/" ]] || return 1
  rm -f -- "$path"
}

safe_remove_dir() {
  local path="$1"
  [[ -n "$path" && "$path" != "/" ]] || return 1
  rm -rf -- "$path"
}

remove_managed_at_jobs() {
  if ! command -v atq >/dev/null 2>&1 || ! command -v atrm >/dev/null 2>&1 || ! command -v at >/dev/null 2>&1; then
    return 0
  fi

  while read -r job_id _; do
    [[ -n "${job_id:-}" ]] || continue
    if at -c "$job_id" 2>/dev/null | grep -Fq "$BIN_FILE cleanup-"; then
      atrm "$job_id" 2>/dev/null || true
    fi
  done < <(atq 2>/dev/null || true)
}

uninstall_backend() {
  echo "Removing FUJI backend service and installed files..."

  remove_managed_at_jobs

  if command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now "$APP_NAME.service" >/dev/null 2>&1 || true
  fi

  safe_remove_file "$SERVICE_WANTS_LINK"
  safe_remove_file "$SERVICE_FILE"

  if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl reset-failed "$APP_NAME.service" >/dev/null 2>&1 || true
  fi

  safe_remove_file "$ENV_FILE"
  safe_remove_file "$BIN_FILE"
  safe_remove_dir "$APP_DIR"

  echo
  echo "Uninstall complete."
  echo "Removed service: $APP_NAME.service"
  echo "Removed files: $SERVICE_FILE, $ENV_FILE, $BIN_FILE, $APP_DIR"
  echo "Shared packages and shared services such as atd were left installed."
}

case "$ACTION" in
  install|"")
    ACTION="install"
    ;;
  uninstall|remove|--remove|--uninstall)
    ACTION="uninstall"
    ;;
  -h|--help|help)
    usage
    exit 0
    ;;
  *)
    echo "Unknown action: $ACTION" >&2
    usage >&2
    exit 1
    ;;
esac

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run this installer as root."
  exit 1
fi

install_packages() {
  if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y golang-go sqlite3 at curl openssl ca-certificates
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y golang sqlite sqlite-tools at curl openssl ca-certificates
  elif command -v yum >/dev/null 2>&1; then
    yum install -y golang sqlite at curl openssl ca-certificates
  else
    echo "Unsupported package manager. Install Go, sqlite3, at, curl, openssl manually."
    exit 1
  fi
}

generate_token() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 32
  else
    python3 - <<'PY'
import secrets
print(secrets.token_hex(32))
PY
  fi
}

server_ip() {
  hostname -I 2>/dev/null | awk '{print $1}'
}

if [[ "$ACTION" == "uninstall" ]]; then
  uninstall_backend
  exit 0
fi

install_packages
systemctl enable atd >/dev/null 2>&1 || systemctl enable at >/dev/null 2>&1 || true
systemctl start atd >/dev/null 2>&1 || systemctl start at >/dev/null 2>&1 || true

mkdir -p "$APP_DIR"

cat >"$GO_FILE" <<'EOF_GO_1'
package main

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type app struct {
	addr    string
	token   string
	domain  string
	tlsCert string
	tlsKey  string
	cooldownMu sync.Mutex
	cooldowns  map[string]time.Time
}

type createSSHRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Days     int    `json:"days"`
}

type createVLESSRequest struct {
	Username     string `json:"username"`
	Days         int    `json:"days"`
	BypassOption string `json:"bypass_option"`
}

type createHysteriaRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Days     int    `json:"days"`
}

type createOpenVPNRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Days     int    `json:"days"`
}

var usernameRegex = regexp.MustCompile(`^[A-Za-z0-9_]+$`)
const createCooldown = 10 * time.Minute

func main() {
	if len(os.Args) > 1 {
		if err := runCLI(os.Args[1:]); err != nil {
			log.Fatal(err)
		}
		return
	}

	a := &app{
		addr:    envOr("FUJI_API_ADDR", ":8787"),
		token:   envOr("FUJI_API_TOKEN", ""),
		domain:  strings.TrimSpace(envOr("FUJI_DOMAIN", readTrim("/etc/domain"))),
		tlsCert: strings.TrimSpace(envOr("FUJI_TLS_CERT", "")),
		tlsKey:  strings.TrimSpace(envOr("FUJI_TLS_KEY", "")),
		cooldowns: map[string]time.Time{},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", a.handleHealth)
	mux.HandleFunc("/status", a.withAuth(a.handleStatus))
	mux.HandleFunc("/create/ssh", a.withAuth(a.handleCreateSSH))
	mux.HandleFunc("/create/vless", a.withAuth(a.handleCreateVLESS))
	mux.HandleFunc("/create/hysteria", a.withAuth(a.handleCreateHysteria))
	mux.HandleFunc("/create/openvpn", a.withAuth(a.handleCreateOpenVPN))

	server := &http.Server{
		Addr:              a.addr,
		Handler:           withCORS(mux),
		ReadHeaderTimeout: 15 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
	}

	log.Printf("starting %s on %s", "fuji-backend", a.addr)
	if a.tlsCert != "" && a.tlsKey != "" {
		log.Fatal(server.ListenAndServeTLS(a.tlsCert, a.tlsKey))
	}
	log.Fatal(server.ListenAndServe())
}

func runCLI(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("missing cleanup arguments")
	}
	cmd := args[0]
	user := args[1]
	switch cmd {
	case "cleanup-ssh":
		return cleanupSSH(user)
	case "cleanup-vless":
		return cleanupVLESS(user)
	case "cleanup-hysteria":
		return cleanupHysteria(user)
	case "cleanup-openvpn":
		return cleanupOpenVPN(user)
	default:
		return fmt.Errorf("unknown cli command: %s", cmd)
	}
}

func envOr(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

func readTrim(path string) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *app) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		if a.token == "" || subtle.ConstantTimeCompare([]byte(token), []byte(a.token)) != 1 {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "unauthorized"})
			return
		}
		next(w, r)
	}
}

func clientIP(r *http.Request) string {
	forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-For"))
	if forwarded != "" {
		return strings.TrimSpace(strings.Split(forwarded, ",")[0])
	}
	realIP := strings.TrimSpace(r.Header.Get("X-Real-IP"))
	if realIP != "" {
		return realIP
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err == nil && host != "" {
		return host
	}
	return strings.TrimSpace(r.RemoteAddr)
}

func (a *app) createCooldownRemaining(ip string) time.Duration {
	if ip == "" {
		return 0
	}
	a.cooldownMu.Lock()
	defer a.cooldownMu.Unlock()
	now := time.Now()
	for key, until := range a.cooldowns {
		if !until.After(now) {
			delete(a.cooldowns, key)
		}
	}
	if until, ok := a.cooldowns[ip]; ok && until.After(now) {
		return time.Until(until).Round(time.Second)
	}
	return 0
}

func (a *app) enforceCreateCooldown(w http.ResponseWriter, r *http.Request) bool {
	remaining := a.createCooldownRemaining(clientIP(r))
	if remaining <= 0 {
		return false
	}
	writeJSON(w, http.StatusTooManyRequests, map[string]any{
		"ok":    false,
		"error": fmt.Sprintf("Please wait %s before creating another account.", remaining.String()),
	})
	return true
}

func (a *app) markCreateCooldown(r *http.Request) {
	ip := clientIP(r)
	if ip == "" {
		return
	}
	a.cooldownMu.Lock()
	defer a.cooldownMu.Unlock()
	a.cooldowns[ip] = time.Now().Add(createCooldown)
}

func (a *app) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "service": "fuji-backend"})
}

func (a *app) handleStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"cpu":     cpuPercent(),
		"load":    loadAverage(),
		"mem":     memoryStats(),
		"storage": storageStats(),
		"net":     networkStats(),
		"services": [][]any{
			{"SSH", serviceActive("ssh.service")},
			{"DNSTT", serviceActive("dnstt.service")},
			{"SQUID", serviceActive("squid.service")},
			{"WEBSOCKET", serviceActive("websocket.service")},
			{"SSL", serviceActive("multiplexer.service")},
			{"XRAY", serviceActive("xray.service")},
			{"BADVPN-UDPGW", serviceActive("badvpn-udpgw.service")},
			{"HYSTERIA", serviceActiveAny("hysteria-server.service", "hysteria-v1.service")},
			{"WIREGUARD", serviceActiveAny("wireguard.service", "wg-quick@wg0.service")},
			{"SLIPSTREAM", serviceActive("slipstream.service")},
			{"MULTIPLEXER", serviceActive("multiplexer.service")},
			{"OPENVPN", serviceActive("openvpn.service")},
		},
	})
}

func (a *app) handleCreateSSH(w http.ResponseWriter, r *http.Request) {
	if a.enforceCreateCooldown(w, r) {
		return
	}
	var req createSSHRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	result, err := a.createSSH(req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	a.markCreateCooldown(r)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "result": result})
}

func (a *app) handleCreateVLESS(w http.ResponseWriter, r *http.Request) {
	if a.enforceCreateCooldown(w, r) {
		return
	}
	var req createVLESSRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	result, err := a.createVLESS(req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	a.markCreateCooldown(r)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "result": result})
}

func (a *app) handleCreateHysteria(w http.ResponseWriter, r *http.Request) {
	if a.enforceCreateCooldown(w, r) {
		return
	}
	var req createHysteriaRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	result, err := a.createHysteria(req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	a.markCreateCooldown(r)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "result": result})
}

func (a *app) handleCreateOpenVPN(w http.ResponseWriter, r *http.Request) {
	if a.enforceCreateCooldown(w, r) {
		return
	}
	var req createOpenVPNRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	result, err := a.createOpenVPN(req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	a.markCreateCooldown(r)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "result": result})
}
EOF_GO_1
cat >>"$GO_FILE" <<'EOF_GO_2'

func decodeJSON(r *http.Request, dst any) error {
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return errors.New("empty request body")
	}
	return json.Unmarshal(body, dst)
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]any{"ok": false, "error": err.Error()})
}

func cpuPercent() float64 {
	i1, t1 := cpuSnapshot()
	time.Sleep(80 * time.Millisecond)
	i2, t2 := cpuSnapshot()
	if t2 <= t1 {
		return 0
	}
	return float64(int((100.0*(1.0-float64(i2-i1)/float64(t2-t1)))*100)) / 100
}

func cpuSnapshot() (uint64, uint64) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, 0
	}
	fields := strings.Fields(strings.SplitN(string(data), "\n", 2)[0])
	if len(fields) < 5 {
		return 0, 0
	}
	var total uint64
	for _, field := range fields[1:] {
		value, _ := strconv.ParseUint(field, 10, 64)
		total += value
	}
	idle, _ := strconv.ParseUint(fields[4], 10, 64)
	return idle, total
}

func loadAverage() []string {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return []string{"0.00", "0.00", "0.00"}
	}
	fields := strings.Fields(string(data))
	if len(fields) < 3 {
		return []string{"0.00", "0.00", "0.00"}
	}
	return fields[:3]
}

func memoryStats() map[string]uint64 {
	result := map[string]uint64{"total": 0, "used": 0, "available": 0}
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return result
	}
	values := map[string]uint64{}
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			value, _ := strconv.ParseUint(parts[1], 10, 64)
			values[strings.TrimSuffix(parts[0], ":")] = value
		}
	}
	total := values["MemTotal"]
	available := values["MemAvailable"]
	result["total"] = total / 1024
	result["available"] = available / 1024
	if total > available {
		result["used"] = (total - available) / 1024
	}
	return result
}

func storageStats() map[string]uint64 {
	result := map[string]uint64{"total": 0, "used": 0, "free": 0}
	var stat syscall.Statfs_t
	if err := syscall.Statfs("/", &stat); err != nil {
		return result
	}
	total := stat.Blocks * uint64(stat.Bsize) / (1024 * 1024)
	free := stat.Bavail * uint64(stat.Bsize) / (1024 * 1024)
	result["total"] = total
	result["free"] = free
	if total > free {
		result["used"] = total - free
	}
	return result
}

func networkStats() map[string]uint64 {
	result := map[string]uint64{"rx_bytes": 0, "tx_bytes": 0, "rx_rate": 0, "tx_rate": 0}
	data, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return result
	}
	for _, line := range strings.Split(string(data), "\n")[2:] {
		if !strings.Contains(line, ":") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if strings.TrimSpace(parts[0]) == "lo" {
			continue
		}
		fields := strings.Fields(parts[1])
		if len(fields) < 9 {
			continue
		}
		rx, _ := strconv.ParseUint(fields[0], 10, 64)
		tx, _ := strconv.ParseUint(fields[8], 10, 64)
		result["rx_bytes"] += rx
		result["tx_bytes"] += tx
	}
	return result
}

func serviceActive(unit string) bool {
	cmd := exec.Command("systemctl", "is-active", unit)
	out, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "active"
}

func serviceActiveAny(units ...string) bool {
	for _, unit := range units {
		if serviceActive(unit) {
			return true
		}
	}
	return false
}

func validateUsername(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("username is required")
	}
	if !usernameRegex.MatchString(raw) {
		return "", errors.New("username must be alphanumeric or underscore")
	}
	if len(raw) > 20 {
		return "", errors.New("username must be at most 20 characters")
	}
	return "FUJI-" + raw, nil
}

func validatePassword(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return errors.New("password is required")
	}
	if len(raw) < 4 || len(raw) > 32 {
		return errors.New("password must be 4 to 32 characters")
	}
	if strings.Contains(raw, "\n") {
		return errors.New("password cannot contain newlines")
	}
	return nil
}

func defaultDays(service string, value int) int {
	if value > 0 {
		return value
	}
	switch service {
	case "ssh", "hysteria":
		return 5
	case "vless", "openvpn":
		return 3
	default:
		return 3
	}
}

func currentDomain(a *app) string {
	if strings.TrimSpace(a.domain) != "" {
		return strings.TrimSpace(a.domain)
	}
	if domain := strings.TrimSpace(readTrim("/etc/domain")); domain != "" {
		return domain
	}
	return serverIP()
}

func serverIP() string {
	out, err := exec.Command("bash", "-lc", "hostname -I | awk '{print $1}'").Output()
	if err != nil {
		return "N/A"
	}
	return strings.TrimSpace(string(out))
}

func nameserver() string {
	value := strings.TrimSpace(readTrim("/etc/nameserver"))
	if value == "" {
		return "Not configured"
	}
	return value
}

func publicKey() string {
	value := strings.TrimSpace(readTrim("/etc/dnstt/server.pub"))
	if value == "" {
		return "Not configured"
	}
	return value
}

func restartService(unit string) error {
	cmd := exec.Command("systemctl", "restart", unit)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %s", err.Error(), strings.TrimSpace(string(output)))
	}
	return nil
}

func restartServiceAny(units ...string) error {
	var lastErr error
	for _, unit := range units {
		if err := restartService(unit); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	if lastErr != nil {
		return lastErr
	}
	return errors.New("no service units provided")
}

func scheduleCleanup(days int, command string) {
	if days < 1 {
		return
	}
	if _, err := exec.LookPath("at"); err != nil {
		return
	}
	_, _ = exec.Command("bash", "-lc", fmt.Sprintf("printf '%%s\n' %q | at now + %d days", command, days)).CombinedOutput()
}

func selfBinary() string {
	path, err := os.Executable()
	if err != nil || strings.TrimSpace(path) == "" {
		return "/usr/local/bin/fuji-backend"
	}
	return path
}

func cleanupSSH(username string) error {
	_ = os.Remove(filepath.Join("/var/lib/regular_users", username))
	_, _ = exec.Command("/usr/sbin/userdel", "-r", username).CombinedOutput()
	return nil
}

func cleanupVLESS(username string) error {
	configPath := "/etc/xray/config.json"
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}
	var config map[string]any
	if err := json.Unmarshal(raw, &config); err != nil {
		return err
	}
	inbounds, _ := config["inbounds"].([]any)
	for _, item := range inbounds {
		inbound, ok := item.(map[string]any)
		if !ok || fmt.Sprint(inbound["protocol"]) != "vless" {
			continue
		}
		settings, _ := inbound["settings"].(map[string]any)
		clients, _ := settings["clients"].([]any)
		filtered := make([]any, 0, len(clients))
		for _, clientItem := range clients {
			clientMap, ok := clientItem.(map[string]any)
			if !ok {
				continue
			}
			email := fmt.Sprint(clientMap["email"])
			if strings.Split(email, "|")[0] == username {
				continue
			}
			filtered = append(filtered, clientMap)
		}
		settings["clients"] = filtered
	}
	encoded, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(configPath, encoded, 0644); err != nil {
		return err
	}
	return restartService("xray.service")
}
EOF_GO_2
cat >>"$GO_FILE" <<'EOF_GO_3'

func cleanupHysteria(username string) error {
	_, _ = exec.Command("sqlite3", "/etc/hysteria/udpusers.db", fmt.Sprintf("DELETE FROM users WHERE username='%s';", strings.ReplaceAll(username, "'", "''"))).CombinedOutput()
	if err := updateHysteriaConfig(); err != nil {
		return err
	}
	return restartServiceAny("hysteria-server.service", "hysteria-v1.service")
}

func cleanupOpenVPN(username string) error {
	path := "/etc/openvpn/users.txt"
	raw, _ := os.ReadFile(path)
	lines := []string{}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, username+":") {
			continue
		}
		lines = append(lines, line)
	}
	_ = os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0644)
	_ = os.Remove(filepath.Join("/etc/openvpn", username+".ovpn"))
	return nil
}

func (a *app) createSSH(req createSSHRequest) (map[string]any, error) {
	username, err := validateUsername(req.Username)
	if err != nil {
		return nil, err
	}
	if err := validatePassword(req.Password); err != nil {
		return nil, err
	}
	if _, err := os.Stat(filepath.Join("/var/lib/regular_users", username)); err == nil {
		return nil, errors.New("username already exists")
	}
	days := defaultDays("ssh", req.Days)
	expiry := time.Now().Unix() + int64(days*86400)
	if err := os.MkdirAll("/var/lib/regular_users", 0755); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join("/var/lib/regular_users", username), []byte(strconv.FormatInt(expiry, 10)), 0644); err != nil {
		return nil, err
	}
	if out, err := exec.Command("/usr/sbin/useradd", "-m", "-s", "/bin/false", username).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("%s: %s", err.Error(), strings.TrimSpace(string(out)))
	}
	passCmd := exec.Command("/usr/sbin/chpasswd")
	passCmd.Stdin = strings.NewReader(username + ":" + req.Password + "\n")
	if out, err := passCmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("%s: %s", err.Error(), strings.TrimSpace(string(out)))
	}
	scheduleCleanup(days, fmt.Sprintf("%s cleanup-ssh %s", selfBinary(), username))
	return map[string]any{
		"service":    "ssh",
		"username":   username,
		"password":   req.Password,
		"expires_at": expiry,
		"domain":     currentDomain(a),
		"ip":         serverIP(),
		"nameserver": nameserver(),
		"public_key": publicKey(),
	}, nil
}

func (a *app) createVLESS(req createVLESSRequest) (map[string]any, error) {
	username, err := validateUsername(req.Username)
	if err != nil {
		return nil, err
	}
	days := defaultDays("vless", req.Days)
	configPath := "/etc/xray/config.json"
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	var config map[string]any
	if err := json.Unmarshal(raw, &config); err != nil {
		return nil, err
	}
	expiry := time.Now().Unix() + int64(days*86400)
	inbounds, _ := config["inbounds"].([]any)
	foundTLS := false
	foundNonTLS := false
	for _, item := range inbounds {
		inbound, ok := item.(map[string]any)
		if !ok || fmt.Sprint(inbound["protocol"]) != "vless" {
			continue
		}
		settings, _ := inbound["settings"].(map[string]any)
		clients, _ := settings["clients"].([]any)
		for _, clientItem := range clients {
			clientMap, ok := clientItem.(map[string]any)
			if !ok {
				continue
			}
			email := fmt.Sprint(clientMap["email"])
			if strings.Split(email, "|")[0] == username {
				return nil, errors.New("username already exists")
			}
		}
		client := map[string]any{"id": username, "level": 0, "email": fmt.Sprintf("%s|%d", username, expiry)}
		switch fmt.Sprint(inbound["port"]) {
		case "10001":
			settings["clients"] = append(clients, client)
			foundTLS = true
		case "10002":
			settings["clients"] = append(clients, client)
			foundNonTLS = true
		}
	}
	if !foundTLS || !foundNonTLS {
		return nil, errors.New("vless inbounds on port 10001 and 10002 not found")
	}
	encoded, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(configPath, encoded, 0644); err != nil {
		return nil, err
	}
	if err := restartService("xray.service"); err != nil {
		return nil, err
	}
	scheduleCleanup(days, fmt.Sprintf("%s cleanup-vless %s", selfBinary(), username))
	domain := currentDomain(a)
	sni := ""
	hostNonTLS := domain
	addressTLS := domain
	switch strings.TrimSpace(req.BypassOption) {
	case "DITO_UNLI_SOCIAL":
		sni = "tiktok.jericoo.xyz"
		addressTLS = sni
	case "SMART_POWER_ALL", "GLOBE_GOSHARE":
		hostNonTLS = "gecko-sg.tiktokv.com"
	}
	sniParam := ""
	if sni != "" {
		sniParam = "&sni=" + url.QueryEscape(sni)
	}
	linkTLS := fmt.Sprintf("vless://%s@%s:443?encryption=none&type=ws&security=tls&host=%s&path=/vless%s#%s", username, addressTLS, domain, sniParam, url.QueryEscape(username))
	linkNonTLS := fmt.Sprintf("vless://%s@%s:80?encryption=none&type=ws&host=%s&path=/vless#%s", username, domain, hostNonTLS, url.QueryEscape(username))
	return map[string]any{"service": "vless", "username": username, "expires_at": expiry, "domain": domain, "tls_link": linkTLS, "nontls_link": linkNonTLS}, nil
}

func (a *app) createHysteria(req createHysteriaRequest) (map[string]any, error) {
	username, err := validateUsername(req.Username)
	if err != nil {
		return nil, err
	}
	if err := validatePassword(req.Password); err != nil {
		return nil, err
	}
	days := defaultDays("hysteria", req.Days)
	dbPath := "/etc/hysteria/udpusers.db"
	safeUser := strings.ReplaceAll(username, "'", "''")
	safePass := strings.ReplaceAll(req.Password, "'", "''")
	_, _ = exec.Command("sqlite3", dbPath, "CREATE TABLE IF NOT EXISTS users (username TEXT, password TEXT, expiry INTEGER);").CombinedOutput()
	out, _ := exec.Command("sqlite3", dbPath, fmt.Sprintf("SELECT COUNT(*) FROM users WHERE username='%s';", safeUser)).CombinedOutput()
	if strings.TrimSpace(string(out)) != "" && strings.TrimSpace(string(out)) != "0" {
		return nil, errors.New("username already exists")
	}
	expiry := time.Now().Unix() + int64(days*86400)
	if output, err := exec.Command("sqlite3", dbPath, fmt.Sprintf("INSERT INTO users (username,password,expiry) VALUES ('%s','%s',%d);", safeUser, safePass, expiry)).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("%s: %s", err.Error(), strings.TrimSpace(string(output)))
	}
	if err := updateHysteriaConfig(); err != nil {
		return nil, err
	}
	if err := restartServiceAny("hysteria-server.service", "hysteria-v1.service"); err != nil {
		return nil, err
	}
	scheduleCleanup(days, fmt.Sprintf("%s cleanup-hysteria %s", selfBinary(), username))
	domain := currentDomain(a)
	obfs := hysteriaObfs()
	port := hysteriaPort()
	query := url.Values{}
	query.Set("protocol", "udp")
	query.Set("auth", username+":"+req.Password)
	query.Set("peer", domain)
	query.Set("insecure", "1")
	query.Set("upmbps", "100")
	query.Set("downmbps", "100")
	if obfs != "" && obfs != "N/A" {
		query.Set("obfs", "xplus")
		query.Set("obfsParam", obfs)
	}
	link := fmt.Sprintf("hysteria://%s:%s?%s#%s", domain, port, query.Encode(), url.QueryEscape(username))
	return map[string]any{"service": "hysteria", "username": username, "password": req.Password, "expires_at": expiry, "domain": domain, "obfs": obfs, "link": link}, nil
}

func (a *app) createOpenVPN(req createOpenVPNRequest) (map[string]any, error) {
	username, err := validateUsername(req.Username)
	if err != nil {
		return nil, err
	}
	if err := validatePassword(req.Password); err != nil {
		return nil, err
	}
	days := defaultDays("openvpn", req.Days)
	if err := os.MkdirAll("/etc/openvpn", 0755); err != nil {
		return nil, err
	}
	usersFile := "/etc/openvpn/users.txt"
	raw, _ := os.ReadFile(usersFile)
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), username+":") {
			return nil, errors.New("username already exists")
		}
	}
	expiry := time.Now().Unix() + int64(days*86400)
	handle, err := os.OpenFile(usersFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	defer handle.Close()
	if _, err := fmt.Fprintf(handle, "%s:%s:%d\n", username, req.Password, expiry); err != nil {
		return nil, err
	}
	host := currentDomain(a)
	if host == "" || host == "N/A" {
		host = serverIP()
	}
	caText := string(mustReadOptional("/etc/openvpn/certs/ca.crt"))
	content := fmt.Sprintf("# FUJI PANEL\nclient\ndev tun\nproto tcp\nremote %s 443\nremote-cert-tls server\nresolv-retry infinite\nconnect-retry 5\ncipher AES-128-GCM\nauth SHA256\nnobind\npersist-key\npersist-tun\nsetenv CLIENT_CERT 0\nverb 3\n<auth-user-pass>\n%s\n%s\n</auth-user-pass>\n<ca>\n%s\n</ca>\n", host, username, req.Password, caText)
	ovpnPath := filepath.Join("/etc/openvpn", username+".ovpn")
	if err := os.WriteFile(ovpnPath, []byte(content), 0644); err != nil {
		return nil, err
	}
	scheduleCleanup(days, fmt.Sprintf("%s cleanup-openvpn %s", selfBinary(), username))
	return map[string]any{"service": "openvpn", "username": username, "password": req.Password, "expires_at": expiry, "domain": host, "download_path": ovpnPath, "ovpn_content": content}, nil
}

func updateHysteriaConfig() error {
	now := time.Now().Unix()
	out, err := exec.Command("sqlite3", "-separator", "\t", "/etc/hysteria/udpusers.db", fmt.Sprintf("SELECT username,password FROM users WHERE expiry IS NULL OR expiry > %d;", now)).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s", err.Error(), strings.TrimSpace(string(out)))
	}
	passwords := []string{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.SplitN(line, "\t", 2)
		if len(parts) != 2 {
			continue
		}
		if parts[1] != "" {
			passwords = append(passwords, parts[1])
		}
		if parts[0] != "" && parts[1] != "" {
			passwords = append(passwords, parts[0]+":"+parts[1])
		}
	}
	sort.Strings(passwords)
	configPath := "/etc/hysteria/config.json"
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}
	var config map[string]any
	if err := json.Unmarshal(raw, &config); err != nil {
		return err
	}
	config["auth"] = map[string]any{"mode": "passwords", "config": passwords}
	encoded, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(configPath, encoded, 0644)
}

func hysteriaObfs() string {
	raw, err := os.ReadFile("/etc/hysteria/config.json")
	if err != nil {
		return "N/A"
	}
	var config map[string]any
	if json.Unmarshal(raw, &config) != nil {
		return "N/A"
	}
	obfs, ok := config["obfs"].(map[string]any)
	if !ok {
		return "N/A"
	}
	salamander, ok := obfs["salamander"].(map[string]any)
	if !ok {
		return "N/A"
	}
	return fmt.Sprint(salamander["password"])
}

func hysteriaPort() string {
	raw, err := os.ReadFile("/etc/hysteria/config.json")
	if err != nil {
		return "10000"
	}
	var config map[string]any
	if json.Unmarshal(raw, &config) != nil {
		return "10000"
	}
	listen := strings.TrimSpace(fmt.Sprint(config["listen"]))
	if idx := strings.LastIndex(listen, ":"); idx >= 0 {
		return strings.TrimPrefix(listen[idx:], ":")
	}
	if listen == "" {
		return "10000"
	}
	return strings.TrimPrefix(listen, ":")
}

func mustReadOptional(path string) []byte {
	data, _ := os.ReadFile(path)
	return data
}
EOF_GO_3

TOKEN="$(generate_token)"
DOMAIN_VALUE=""
if [[ -f /etc/domain ]]; then
  DOMAIN_VALUE="$(tr -d '\r\n' </etc/domain)"
fi

API_ADDR_VALUE="${FUJI_API_ADDR:-:8787}"
API_TOKEN_VALUE="${FUJI_API_TOKEN:-$TOKEN}"
DOMAIN_ENV_VALUE="${FUJI_DOMAIN:-$DOMAIN_VALUE}"
TLS_CERT_VALUE="${FUJI_TLS_CERT:-}"
TLS_KEY_VALUE="${FUJI_TLS_KEY:-}"

cat >"$ENV_FILE" <<EOF_ENV
FUJI_API_ADDR="$API_ADDR_VALUE"
FUJI_API_TOKEN="$API_TOKEN_VALUE"
FUJI_DOMAIN="$DOMAIN_ENV_VALUE"
FUJI_TLS_CERT="$TLS_CERT_VALUE"
FUJI_TLS_KEY="$TLS_KEY_VALUE"
EOF_ENV

go build -o "$BIN_FILE" "$GO_FILE"
chmod 0755 "$BIN_FILE"

cat >"$SERVICE_FILE" <<EOF_SERVICE
[Unit]
Description=FUJI Backend API
After=network.target

[Service]
Type=simple
EnvironmentFile=$ENV_FILE
ExecStart=$BIN_FILE
Restart=always
RestartSec=3
User=root
WorkingDirectory=$APP_DIR

[Install]
WantedBy=multi-user.target
EOF_SERVICE

systemctl daemon-reload
systemctl enable --now "$APP_NAME.service"

PORT_VALUE="$API_ADDR_VALUE"
PORT_VALUE="${PORT_VALUE##*:}"
HOST_VALUE="${DOMAIN_ENV_VALUE:-$(server_ip)}"
PROTO="http"
if [[ -n "$TLS_CERT_VALUE" && -n "$TLS_KEY_VALUE" ]]; then
  PROTO="https"
fi

echo
echo "Install complete."
echo "Service: $APP_NAME.service"
echo "Health: ${PROTO}://${HOST_VALUE}:${PORT_VALUE}/healthz"
echo "SERVER_API_URL=${PROTO}://${HOST_VALUE}:${PORT_VALUE}"
echo "SERVER_API_TOKEN=${API_TOKEN_VALUE}"
echo
echo "If you want HTTPS without nginx, set FUJI_TLS_CERT and FUJI_TLS_KEY in $ENV_FILE,"
echo "then restart the service:"
echo "systemctl restart $APP_NAME.service"
echo
echo "To uninstall later:"
echo "bash $0 uninstall"
