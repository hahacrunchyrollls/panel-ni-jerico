#!/usr/bin/env bash
rm -rf *
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

load_existing_env() {
  local existing_env_file="$1"
  [[ -f "$existing_env_file" ]] || return 0

  local input_api_addr="${FUJI_API_ADDR-}"
  local input_api_token="${FUJI_API_TOKEN-}"
  local input_domain="${FUJI_DOMAIN-}"
  local input_tls_cert="${FUJI_TLS_CERT-}"
  local input_tls_key="${FUJI_TLS_KEY-}"

  # shellcheck disable=SC1090
  source "$existing_env_file"

  if [[ -n "${input_api_addr}" ]]; then
    FUJI_API_ADDR="$input_api_addr"
  fi
  if [[ -n "${input_api_token}" ]]; then
    FUJI_API_TOKEN="$input_api_token"
  fi
  if [[ -n "${input_domain}" ]]; then
    FUJI_DOMAIN="$input_domain"
  fi
  if [[ -n "${input_tls_cert}" ]]; then
    FUJI_TLS_CERT="$input_tls_cert"
  fi
  if [[ -n "${input_tls_key}" ]]; then
    FUJI_TLS_KEY="$input_tls_key"
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
	trafficMu  sync.Mutex
	lastTraffic networkSnapshot
	panelMu sync.Mutex
}

type networkSnapshot struct {
	at time.Time
	rx uint64
	tx uint64
}

type panelConfig struct {
	DailyLimit         int              `json:"daily_limit"`
	CreateExpiry       map[string]int   `json:"create_expiry"`
	VLESSBypassOptions []map[string]any `json:"vless_bypass_options"`
	UpdatedAt          int64            `json:"updated_at"`
}

type panelState struct {
	TotalVisits   uint64             `json:"total_visits"`
	TotalAccounts uint64             `json:"total_accounts"`
	DailyDate     string             `json:"daily_date"`
	DailyCounts   map[string]map[string]uint64 `json:"daily_counts"`
	LastOnlineUsers uint64           `json:"last_online_users"`
	LastStatusTotalAccounts uint64   `json:"last_status_total_accounts"`
	UpdatedAt     int64              `json:"updated_at"`
}

type panelStateIncrementRequest struct {
	Amount uint64 `json:"amount"`
}

type panelStateDailyAccountRequest struct {
	Service   string `json:"service"`
	BackendID string `json:"backend_id"`
	Date      string `json:"date"`
	Amount    uint64 `json:"amount"`
}

type panelStateSummaryRequest struct {
	OnlineUsers         uint64 `json:"online_users"`
	StatusTotalAccounts uint64 `json:"status_total_accounts"`
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
	BypassConfig *vlessBypassConfig `json:"bypass_config"`
}

type vlessBypassEndpoint struct {
	Address string `json:"address"`
	Host    string `json:"host"`
	SNI     string `json:"sni"`
}

type vlessBypassConfig struct {
	Name   string              `json:"name"`
	TLS    vlessBypassEndpoint `json:"tls"`
	NonTLS vlessBypassEndpoint `json:"nontls"`
}

type createHysteriaRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Days     int    `json:"days"`
}

type createWireGuardRequest struct {
	Username string `json:"username"`
	Days     int    `json:"days"`
}

type createOpenVPNRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Days     int    `json:"days"`
}

type wireGuardConfig struct {
	InterfaceName string
	ConfigPath    string
	ClientsDir    string
	Params        map[string]string
}

type wireGuardCreateSettings struct {
	wireGuardConfig
	ServerPubKey    string
	ServerPubIP     string
	ServerPort      string
	ClientDNS       string
	AllowedIPs      string
	ServerIPv4      net.IP
	ServerIPv4Subnet *net.IPNet
}

type accountMutationRequest struct {
	Service  string `json:"service"`
	Username string `json:"username"`
	Days     int    `json:"days"`
}

type accountRecord struct {
	Service       string `json:"service"`
	Username      string `json:"username"`
	ExpiresAt     int64  `json:"expires_at"`
	Active        bool   `json:"active"`
	DaysRemaining int    `json:"days_remaining"`
}

type onlineSession struct {
	Service    string `json:"service"`
	Username   string `json:"username"`
	RemoteAddr string `json:"remote_addr,omitempty"`
	TTY        string `json:"tty,omitempty"`
	Source     string `json:"source,omitempty"`
}

type onlineUserSummary struct {
	SSHOnlineUsers     uint64          `json:"ssh_online_users"`
	OpenVPNOnlineUsers uint64          `json:"openvpn_online_users"`
	OnlineUsers        uint64          `json:"online_users"`
	Sessions           []onlineSession `json:"online_sessions"`
}

var usernameRegex = regexp.MustCompile(`^[A-Za-z0-9_]+$`)
var managedUsernameRegex = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
var sshdSessionUserRegex = regexp.MustCompile(`(?:^|/)?sshd:\s*([A-Za-z0-9_]+)(?:@|\s+\[)`)
const createCooldown = 10 * time.Minute
const panelConfigPath = "/etc/fuji-panel-config.json"
const panelStatePath = "/etc/fuji-panel-state.json"

func main() {
	if len(os.Args) > 1 {
		if err := runCLI(os.Args[1:]); err != nil {
			log.Fatal(err)
		}
		return
	}

	a := &app{
		addr:    envOr("FUJI_API_ADDR", ":67"),
		token:   envOr("FUJI_API_TOKEN", ""),
		domain:  strings.TrimSpace(envOr("FUJI_DOMAIN", readTrim("/etc/domain"))),
		tlsCert: strings.TrimSpace(envOr("FUJI_TLS_CERT", "")),
		tlsKey:  strings.TrimSpace(envOr("FUJI_TLS_KEY", "")),
		cooldowns: map[string]time.Time{},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", a.handleHealth)
	mux.HandleFunc("/panel-config", a.withAuth(a.handlePanelConfig))
	mux.HandleFunc("/panel-state", a.withAuth(a.handlePanelState))
	mux.HandleFunc("/panel-state/visit", a.withAuth(a.handlePanelStateVisit))
	mux.HandleFunc("/panel-state/account", a.withAuth(a.handlePanelStateAccount))
	mux.HandleFunc("/panel-state/daily-account", a.withAuth(a.handlePanelStateDailyAccount))
	mux.HandleFunc("/panel-state/summary", a.withAuth(a.handlePanelStateSummary))
	mux.HandleFunc("/status", a.withAuth(a.handleStatus))
	mux.HandleFunc("/create/ssh", a.withAuth(a.handleCreateSSH))
	mux.HandleFunc("/create/vless", a.withAuth(a.handleCreateVLESS))
	mux.HandleFunc("/create/hysteria", a.withAuth(a.handleCreateHysteria))
	mux.HandleFunc("/create/wireguard", a.withAuth(a.handleCreateWireGuard))
	mux.HandleFunc("/create/openvpn", a.withAuth(a.handleCreateOpenVPN))
	mux.HandleFunc("/accounts", a.withAuth(a.handleAccounts))
	mux.HandleFunc("/accounts/delete", a.withAuth(a.handleDeleteAccount))
	mux.HandleFunc("/accounts/update-expiry", a.withAuth(a.handleUpdateAccountExpiry))

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
	case "cleanup-wireguard":
		return cleanupWireGuard(user)
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

func panelLocalDate() string {
	return time.Now().UTC().Add(8 * time.Hour).Format("2006-01-02")
}

func normalizePanelDate(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return panelLocalDate()
	}
	if _, err := time.Parse("2006-01-02", value); err != nil {
		return panelLocalDate()
	}
	return value
}

func normalizePanelDailyCounts(raw map[string]map[string]uint64) map[string]map[string]uint64 {
	normalized := map[string]map[string]uint64{}
	for backendID, bucket := range raw {
		backendKey := strings.TrimSpace(backendID)
		if backendKey == "" {
			backendKey = "default"
		}
		cleanBucket := map[string]uint64{}
		for service, amount := range bucket {
			serviceKey := strings.TrimSpace(service)
			if serviceKey == "" || amount == 0 {
				continue
			}
			cleanBucket[serviceKey] = amount
		}
		if len(cleanBucket) > 0 {
			normalized[backendKey] = cleanBucket
		}
	}
	return normalized
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

func cooldownKey(protocol, ip string) string {
	return protocol + ":" + ip
}

func (a *app) createCooldownRemaining(protocol, ip string) time.Duration {
	if protocol == "" || ip == "" {
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
	if until, ok := a.cooldowns[cooldownKey(protocol, ip)]; ok && until.After(now) {
		return time.Until(until).Round(time.Second)
	}
	return 0
}

func (a *app) enforceCreateCooldown(w http.ResponseWriter, r *http.Request, protocol string) bool {
	remaining := a.createCooldownRemaining(protocol, clientIP(r))
	if remaining <= 0 {
		return false
	}
	writeJSON(w, http.StatusTooManyRequests, map[string]any{
		"ok":    false,
		"error": fmt.Sprintf("Please wait %s before creating another account.", remaining.String()),
	})
	return true
}

func (a *app) markCreateCooldown(r *http.Request, protocol string) {
	ip := clientIP(r)
	if protocol == "" || ip == "" {
		return
	}
	a.cooldownMu.Lock()
	defer a.cooldownMu.Unlock()
	a.cooldowns[cooldownKey(protocol, ip)] = time.Now().Add(createCooldown)
}

func (a *app) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "service": "fuji-backend"})
}

func (a *app) handlePanelConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "config": loadPanelConfig()})
		return
	case http.MethodPost:
		var req panelConfig
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		saved, err := savePanelConfig(req)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "config": saved})
		return
	default:
		w.Header().Set("Allow", "GET, POST")
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
	}
}

func (a *app) handlePanelState(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "state": loadPanelState()})
}

func (a *app) handlePanelStateVisit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	state, err := a.mutatePanelState(func(state *panelState) error {
		state.TotalVisits++
		return nil
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "state": state})
}

func (a *app) handlePanelStateAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req panelStateIncrementRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if req.Amount == 0 {
		req.Amount = 1
	}
	state, err := a.mutatePanelState(func(state *panelState) error {
		state.TotalAccounts += req.Amount
		return nil
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "state": state})
}

func (a *app) handlePanelStateDailyAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req panelStateDailyAccountRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	service := strings.TrimSpace(req.Service)
	if service == "" {
		writeError(w, http.StatusBadRequest, errors.New("service is required"))
		return
	}
	backendID := strings.TrimSpace(req.BackendID)
	if backendID == "" {
		backendID = "default"
	}
	if req.Amount == 0 {
		req.Amount = 1
	}
	req.Date = normalizePanelDate(req.Date)
	state, err := a.mutatePanelState(func(state *panelState) error {
		if normalizePanelDate(state.DailyDate) != req.Date {
			state.DailyDate = req.Date
			state.DailyCounts = map[string]map[string]uint64{}
		}
		if state.DailyCounts == nil {
			state.DailyCounts = map[string]map[string]uint64{}
		}
		bucket := state.DailyCounts[backendID]
		if bucket == nil {
			bucket = map[string]uint64{}
		}
		bucket[service] += req.Amount
		state.DailyCounts[backendID] = bucket
		return nil
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "state": state})
}

func (a *app) handlePanelStateSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req panelStateSummaryRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	state, err := a.mutatePanelState(func(state *panelState) error {
		state.LastOnlineUsers = req.OnlineUsers
		state.LastStatusTotalAccounts = req.StatusTotalAccounts
		return nil
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "state": state})
}

func (a *app) handleStatus(w http.ResponseWriter, r *http.Request) {
	online := onlineUsersSummary()
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                   true,
		"cpu":                  cpuPercent(),
		"load":                 loadAverage(),
		"mem":                  memoryStats(),
		"storage":              storageStats(),
		"net":                  a.networkStats(),
		"services":             serviceStatusEntries(),
		"ssh_online_users":     online.SSHOnlineUsers,
		"openvpn_online_users": online.OpenVPNOnlineUsers,
		"online_users":         online.OnlineUsers,
		"online_sessions":      online.Sessions,
		"total_accounts":       totalAccountsCount(),
	})
}

func (a *app) handleCreateSSH(w http.ResponseWriter, r *http.Request) {
	if a.enforceCreateCooldown(w, r, "ssh") {
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
	a.markCreateCooldown(r, "ssh")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "result": result})
}

func (a *app) handleCreateVLESS(w http.ResponseWriter, r *http.Request) {
	if a.enforceCreateCooldown(w, r, "vless") {
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
	a.markCreateCooldown(r, "vless")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "result": result})
}

func (a *app) handleCreateHysteria(w http.ResponseWriter, r *http.Request) {
	if a.enforceCreateCooldown(w, r, "hysteria") {
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
	a.markCreateCooldown(r, "hysteria")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "result": result})
}

func (a *app) handleCreateWireGuard(w http.ResponseWriter, r *http.Request) {
	if a.enforceCreateCooldown(w, r, "wireguard") {
		return
	}
	var req createWireGuardRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	result, err := a.createWireGuard(req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	a.markCreateCooldown(r, "wireguard")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "result": result})
}

func (a *app) handleCreateOpenVPN(w http.ResponseWriter, r *http.Request) {
	if a.enforceCreateCooldown(w, r, "openvpn") {
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
	a.markCreateCooldown(r, "openvpn")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "result": result})
}

func (a *app) handleAccounts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	accounts, err := listAllManagedAccounts()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "accounts": accounts, "total_accounts": len(accounts)})
}

func (a *app) handleDeleteAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req accountMutationRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	service, username, err := deleteManagedAccount(req.Service, req.Username)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "service": service, "username": username})
}

func (a *app) handleUpdateAccountExpiry(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req accountMutationRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	account, err := updateManagedAccountExpiry(req.Service, req.Username, req.Days)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "account": account})
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

func (a *app) networkStats() map[string]uint64 {
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
	now := time.Now()
	a.trafficMu.Lock()
	defer a.trafficMu.Unlock()
	if !a.lastTraffic.at.IsZero() {
		if delta := now.Sub(a.lastTraffic.at).Seconds(); delta > 0 {
			if result["rx_bytes"] >= a.lastTraffic.rx {
				result["rx_rate"] = uint64(float64(result["rx_bytes"]-a.lastTraffic.rx) / delta)
			}
			if result["tx_bytes"] >= a.lastTraffic.tx {
				result["tx_rate"] = uint64(float64(result["tx_bytes"]-a.lastTraffic.tx) / delta)
			}
		}
	}
	a.lastTraffic = networkSnapshot{at: now, rx: result["rx_bytes"], tx: result["tx_bytes"]}
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

func runningServiceUnits() []string {
	cmd := exec.Command("systemctl", "list-units", "--type=service", "--state=running", "--no-legend", "--plain", "--no-pager")
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	units := []string{}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		units = append(units, strings.ToLower(strings.TrimSpace(fields[0])))
	}
	return units
}

func matchesServiceUnit(unit string, patterns ...string) bool {
	normalizedUnit := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(unit, ".service")))
	for _, pattern := range patterns {
		normalizedPattern := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(pattern, ".service")))
		if normalizedPattern == "" {
			continue
		}
		if normalizedUnit == normalizedPattern || strings.HasPrefix(normalizedUnit, normalizedPattern+"@") || strings.Contains(normalizedUnit, normalizedPattern) {
			return true
		}
	}
	return false
}

func serviceRunning(units []string, patterns ...string) bool {
	for _, unit := range units {
		if matchesServiceUnit(unit, patterns...) {
			return true
		}
	}
	for _, pattern := range patterns {
		if strings.Contains(pattern, ".service") {
			if serviceActive(pattern) {
				return true
			}
		}
	}
	return false
}

func serviceStatusEntries() [][]any {
	units := runningServiceUnits()
	return [][]any{
		{"SSH", serviceRunning(units, "ssh.service", "sshd.service", "ssh", "sshd")},
		{"DNSTT", serviceRunning(units, "dnstt.service", "dnstt")},
		{"SQUID", serviceRunning(units, "squid.service", "squid")},
		{"WEBSOCKET", serviceRunning(units, "websocket.service", "websocket", "ws-stunnel", "ws-dropbear", "pythonws")},
		{"SSL", serviceRunning(units, "multiplexer.service", "stunnel4.service", "stunnel.service", "stunnel", "nginx.service", "haproxy.service")},
		{"XRAY", serviceRunning(units, "xray.service", "xray")},
		{"BADVPN-UDPGW", serviceRunning(units, "badvpn-udpgw.service", "badvpn-udpgw", "udpgw")},
		{"HYSTERIA", serviceRunning(units, "hysteria-server.service", "hysteria-v1.service", "hysteria.service", "hysteria")},
		{"WIREGUARD", serviceRunning(units, "wireguard.service", "wg-quick@wg0.service", "wg-quick", "wireguard")},
		{"SLIPSTREAM", serviceRunning(units, "slipstream.service", "slipstream")},
		{"MULTIPLEXER", serviceRunning(units, "multiplexer.service", "multiplexer")},
		{"OPENVPN", serviceRunning(units, "openvpn.service", "openvpn-server@server.service", "openvpn@server.service", "openvpn-server", "openvpn")},
	}
}

func regularSSHUsers() map[string]struct{} {
	entries, err := os.ReadDir("/var/lib/regular_users")
	if err != nil {
		return map[string]struct{}{}
	}
	users := map[string]struct{}{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		username := strings.TrimSpace(entry.Name())
		if username == "" {
			continue
		}
		users[username] = struct{}{}
	}
	return users
}

func openVPNManagedUsers() map[string]struct{} {
	raw, err := os.ReadFile("/etc/openvpn/users.txt")
	if err != nil {
		return map[string]struct{}{}
	}
	users := map[string]struct{}{}
	for _, line := range strings.Split(string(raw), "\n") {
		username, _, _, ok := parseOpenVPNUserLine(line)
		if !ok {
			continue
		}
		users[username] = struct{}{}
	}
	return users
}

func addOnlineUser(users map[string]struct{}, allowed map[string]struct{}, raw string) {
	username := strings.TrimSpace(raw)
	if !usernameRegex.MatchString(username) {
		return
	}
	if len(allowed) > 0 {
		if _, ok := allowed[username]; !ok {
			return
		}
	}
	users[username] = struct{}{}
}

func sshWhoSessions(allowed map[string]struct{}) []onlineSession {
	out, err := exec.Command("who").Output()
	if err != nil {
		return nil
	}
	sessions := []onlineSession{}
	for _, rawLine := range strings.Split(string(out), "\n") {
		fields := strings.Fields(rawLine)
		if len(fields) == 0 {
			continue
		}
		username := strings.TrimSpace(fields[0])
		if strings.EqualFold(username, "root") {
			continue
		}
		if !usernameRegex.MatchString(username) {
			continue
		}
		if len(allowed) > 0 {
			if _, ok := allowed[username]; !ok {
				continue
			}
		}
		tty := ""
		if len(fields) > 1 {
			tty = strings.TrimSpace(fields[1])
		}
		remoteAddr := ""
		line := strings.TrimSpace(rawLine)
		if start := strings.LastIndex(line, "("); start >= 0 && strings.HasSuffix(line, ")") {
			remoteAddr = strings.TrimSpace(line[start+1 : len(line)-1])
		}
		sessions = append(sessions, onlineSession{
			Service:    "ssh",
			Username:   username,
			RemoteAddr: remoteAddr,
			TTY:        tty,
			Source:     "who",
		})
	}
	return sessions
}

func sshdPrivSessions(allowed map[string]struct{}) []onlineSession {
	out, err := exec.Command("ps", "-eo", "args=").Output()
	if err != nil {
		return nil
	}
	sessions := []onlineSession{}
	for _, rawLine := range strings.Split(string(out), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || !strings.Contains(line, "sshd:") || !strings.Contains(line, "[priv]") {
			continue
		}
		match := sshdSessionUserRegex.FindStringSubmatch(line)
		if len(match) < 2 {
			continue
		}
		username := strings.TrimSpace(match[1])
		if username == "" || strings.EqualFold(username, "root") {
			continue
		}
		if len(allowed) > 0 {
			if _, ok := allowed[username]; !ok {
				continue
			}
		}
		sessions = append(sessions, onlineSession{
			Service:  "ssh",
			Username: username,
			Source:   "sshd",
		})
	}
	return sessions
}

func dropbearSessionCount() int {
	out, err := exec.Command("ps", "-eo", "comm=,args=").Output()
	if err != nil {
		return 0
	}
	total := 0
	for _, rawLine := range strings.Split(string(out), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if strings.TrimSpace(fields[0]) != "dropbear" {
			continue
		}
		total++
	}
	if total > 0 {
		total--
	}
	return total
}

func sshOnlineSummary() ([]onlineSession, uint64) {
	allowed := regularSSHUsers()
	whoSessions := sshWhoSessions(allowed)
	sshdSessions := sshdPrivSessions(allowed)
	usedWho := make([]bool, len(whoSessions))
	sessions := make([]onlineSession, 0, len(sshdSessions)+len(whoSessions))
	for _, session := range sshdSessions {
		enriched := session
		for index, whoSession := range whoSessions {
			if usedWho[index] || whoSession.Username != session.Username {
				continue
			}
			enriched.RemoteAddr = whoSession.RemoteAddr
			enriched.TTY = whoSession.TTY
			usedWho[index] = true
			break
		}
		sessions = append(sessions, enriched)
	}
	extraRemoteSessions := 0
	for index, whoSession := range whoSessions {
		if usedWho[index] || strings.TrimSpace(whoSession.RemoteAddr) == "" {
			continue
		}
		sessions = append(sessions, whoSession)
		extraRemoteSessions++
	}
	return sessions, uint64(len(sshdSessions) + extraRemoteSessions)
}

func openVPNStatusPaths() []string {
	paths := []string{
		"/etc/openvpn/openvpn-status.log",
		"/etc/openvpn/status.log",
		"/etc/openvpn/server/openvpn-status.log",
		"/etc/openvpn/server/status.log",
		"/var/log/openvpn-status.log",
	}
	for _, dir := range []string{"/etc/openvpn", "/etc/openvpn/server"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".conf") {
				continue
			}
			confPath := filepath.Join(dir, entry.Name())
			raw, err := os.ReadFile(confPath)
			if err != nil {
				continue
			}
			for _, rawLine := range strings.Split(string(raw), "\n") {
				line := strings.TrimSpace(rawLine)
				if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
					continue
				}
				fields := strings.Fields(line)
				if len(fields) < 2 || strings.ToLower(fields[0]) != "status" {
					continue
				}
				path := strings.Trim(strings.TrimSpace(fields[1]), "\"'")
				if path == "" {
					continue
				}
				if !filepath.IsAbs(path) {
					path = filepath.Join(dir, path)
				}
				paths = append(paths, path)
				break
			}
		}
	}
	seen := map[string]struct{}{}
	unique := make([]string, 0, len(paths))
	for _, path := range paths {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		unique = append(unique, path)
	}
	return unique
}

func openVPNStatusSessions(allowed map[string]struct{}) []onlineSession {
	sessions := []onlineSession{}
	for _, path := range openVPNStatusPaths() {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		inLegacyClientTable := false
		for _, rawLine := range strings.Split(string(raw), "\n") {
			line := strings.TrimSpace(rawLine)
			if line == "" {
				continue
			}
			switch {
			case strings.HasPrefix(line, "CLIENT_LIST,"):
				fields := strings.Split(line, ",")
				if len(fields) < 3 {
					continue
				}
				username := strings.TrimSpace(fields[1])
				if username == "" {
					continue
				}
				if len(allowed) > 0 {
					if _, ok := allowed[username]; !ok {
						continue
					}
				}
				sessions = append(sessions, onlineSession{
					Service:    "openvpn",
					Username:   username,
					RemoteAddr: strings.TrimSpace(fields[2]),
					Source:     "status",
				})
			case strings.HasPrefix(line, "Common Name,Real Address"):
				inLegacyClientTable = true
			case strings.HasPrefix(line, "ROUTING TABLE"), strings.HasPrefix(line, "GLOBAL STATS"), strings.HasPrefix(line, "END"):
				inLegacyClientTable = false
			case strings.HasPrefix(line, "OpenVPN CLIENT LIST"), strings.HasPrefix(line, "Updated,"), strings.HasPrefix(line, "TITLE,"), strings.HasPrefix(line, "TIME,"), strings.HasPrefix(line, "HEADER,CLIENT_LIST"):
				continue
			default:
				if !inLegacyClientTable {
					continue
				}
				fields := strings.Split(line, ",")
				if len(fields) < 2 {
					continue
				}
				username := strings.TrimSpace(fields[0])
				if username == "" {
					continue
				}
				if len(allowed) > 0 {
					if _, ok := allowed[username]; !ok {
						continue
					}
				}
				sessions = append(sessions, onlineSession{
					Service:    "openvpn",
					Username:   username,
					RemoteAddr: strings.TrimSpace(fields[1]),
					Source:     "status",
				})
			}
		}
	}
	return sessions
}

func openVPNTCPSocketSessions() []onlineSession {
	out, err := exec.Command("ss", "-tnp", "state", "established").Output()
	if err != nil {
		return nil
	}
	sessions := []onlineSession{}
	for _, rawLine := range strings.Split(string(out), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "Recv-Q") || !strings.Contains(line, "openvpn") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		remoteAddr := strings.TrimSpace(fields[4])
		if remoteAddr == "" || remoteAddr == "*" || strings.HasSuffix(remoteAddr, ":*") {
			continue
		}
		sessions = append(sessions, onlineSession{
			Service:    "openvpn",
			Username:   "Connected client",
			RemoteAddr: remoteAddr,
			Source:     "ss",
		})
	}
	return sessions
}

func openVPNOnlineSummary() ([]onlineSession, uint64) {
	allowed := openVPNManagedUsers()
	statusSessions := openVPNStatusSessions(allowed)
	if len(statusSessions) > 0 {
		return statusSessions, uint64(len(statusSessions))
	}
	socketSessions := openVPNTCPSocketSessions()
	return socketSessions, uint64(len(socketSessions))
}

func onlineUsersSummary() onlineUserSummary {
	sshSessions, sshCount := sshOnlineSummary()
	openVPNSessions, openVPNCount := openVPNOnlineSummary()
	sessions := make([]onlineSession, 0, len(sshSessions)+len(openVPNSessions))
	sessions = append(sessions, sshSessions...)
	sessions = append(sessions, openVPNSessions...)
	return onlineUserSummary{
		SSHOnlineUsers:     sshCount,
		OpenVPNOnlineUsers: openVPNCount,
		OnlineUsers:        sshCount + openVPNCount,
		Sessions:           sessions,
	}
}

func onlineUsersCount() uint64 {
	return onlineUsersSummary().OnlineUsers
}

func countSSHAccounts() uint64 {
	return uint64(len(regularSSHUsers()))
}

func countVLESSAccounts() uint64 {
	raw, err := os.ReadFile("/etc/xray/config.json")
	if err != nil {
		return 0
	}
	var config map[string]any
	if err := json.Unmarshal(raw, &config); err != nil {
		return 0
	}
	inbounds, _ := config["inbounds"].([]any)
	users := map[string]struct{}{}
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
			email := strings.TrimSpace(fmt.Sprint(clientMap["email"]))
			username := strings.TrimSpace(strings.SplitN(email, "|", 2)[0])
			if username == "" {
				username = strings.TrimSpace(fmt.Sprint(clientMap["id"]))
			}
			if username == "" {
				continue
			}
			users[username] = struct{}{}
		}
	}
	return uint64(len(users))
}

func countHysteriaAccounts() uint64 {
	now := time.Now().Unix()
	out, err := exec.Command(
		"sqlite3",
		"-noheader",
		"-batch",
		"/etc/hysteria/udpusers.db",
		fmt.Sprintf("SELECT COUNT(DISTINCT username) FROM users WHERE username IS NOT NULL AND username != '' AND (expiry IS NULL OR expiry > %d);", now),
	).Output()
	if err != nil {
		return 0
	}
	count, err := strconv.ParseUint(strings.TrimSpace(string(out)), 10, 64)
	if err != nil {
		return 0
	}
	return count
}

func countOpenVPNAccounts() uint64 {
	return uint64(len(openVPNManagedUsers()))
}

func countWireGuardAccounts() uint64 {
	accounts, err := listWireGuardAccounts()
	if err != nil {
		return 0
	}
	return uint64(len(accounts))
}

func totalAccountsCount() uint64 {
	return countSSHAccounts() + countVLESSAccounts() + countHysteriaAccounts() + countWireGuardAccounts() + countOpenVPNAccounts()
}

func normalizeManagedService(service string) string {
	switch strings.ToLower(strings.TrimSpace(service)) {
	case "ssh":
		return "ssh"
	case "vless":
		return "vless"
	case "hysteria":
		return "hysteria"
	case "wireguard", "wg":
		return "wireguard"
	case "openvpn":
		return "openvpn"
	default:
		return ""
	}
}

func normalizeManagedUsername(raw string) (string, error) {
	username := strings.TrimSpace(raw)
	if username == "" {
		return "", errors.New("username is required")
	}
	if len(username) > 64 || !managedUsernameRegex.MatchString(username) {
		return "", errors.New("invalid username")
	}
	return username, nil
}

func buildAccountRecord(service, username string, expiresAt int64) accountRecord {
	active := true
	daysRemaining := 0
	if expiresAt > 0 {
		remaining := time.Until(time.Unix(expiresAt, 0))
		active = remaining > 0
		if remaining > 0 {
			daysRemaining = int((remaining + (24*time.Hour - time.Second)) / (24 * time.Hour))
		}
	}
	return accountRecord{
		Service:       service,
		Username:      username,
		ExpiresAt:     expiresAt,
		Active:        active,
		DaysRemaining: daysRemaining,
	}
}

func sortAccountRecords(accounts []accountRecord) {
	serviceRank := map[string]int{"ssh": 0, "vless": 1, "hysteria": 2, "wireguard": 3, "openvpn": 4}
	sort.Slice(accounts, func(i, j int) bool {
		left := accounts[i]
		right := accounts[j]
		if serviceRank[left.Service] != serviceRank[right.Service] {
			return serviceRank[left.Service] < serviceRank[right.Service]
		}
		if left.Username != right.Username {
			return left.Username < right.Username
		}
		return left.ExpiresAt < right.ExpiresAt
	})
}

func parseOptionalUnix(raw string) int64 {
	value, _ := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	return value
}

func parseOpenVPNUserLine(line string) (string, string, int64, bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return "", "", 0, false
	}
	first := strings.Index(line, ":")
	last := strings.LastIndex(line, ":")
	if first <= 0 || last <= first {
		return "", "", 0, false
	}
	username := strings.TrimSpace(line[:first])
	if username == "" {
		return "", "", 0, false
	}
	password := line[first+1 : last]
	expiresAt := parseOptionalUnix(line[last+1:])
	return username, password, expiresAt, true
}

func listAllManagedAccounts() ([]accountRecord, error) {
	accounts := []accountRecord{}
	for _, service := range []string{"ssh", "vless", "hysteria", "wireguard", "openvpn"} {
		serviceAccounts, err := listManagedAccounts(service)
		if err != nil {
			return nil, err
		}
		accounts = append(accounts, serviceAccounts...)
	}
	sortAccountRecords(accounts)
	return accounts, nil
}

func listManagedAccounts(service string) ([]accountRecord, error) {
	switch normalizeManagedService(service) {
	case "ssh":
		return listSSHAccounts()
	case "vless":
		return listVLESSAccounts()
	case "hysteria":
		return listHysteriaAccounts()
	case "wireguard":
		return listWireGuardAccounts()
	case "openvpn":
		return listOpenVPNAccounts()
	default:
		return nil, errors.New("invalid service")
	}
}

func listSSHAccounts() ([]accountRecord, error) {
	entries, err := os.ReadDir("/var/lib/regular_users")
	if err != nil {
		if os.IsNotExist(err) {
			return []accountRecord{}, nil
		}
		return nil, err
	}
	accounts := []accountRecord{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		username := strings.TrimSpace(entry.Name())
		if username == "" {
			continue
		}
		expiresAt := int64(0)
		raw, err := os.ReadFile(filepath.Join("/var/lib/regular_users", entry.Name()))
		if err == nil {
			expiresAt = parseOptionalUnix(string(raw))
		}
		accounts = append(accounts, buildAccountRecord("ssh", username, expiresAt))
	}
	sortAccountRecords(accounts)
	return accounts, nil
}

func listVLESSAccounts() ([]accountRecord, error) {
	raw, err := os.ReadFile("/etc/xray/config.json")
	if err != nil {
		if os.IsNotExist(err) {
			return []accountRecord{}, nil
		}
		return nil, err
	}
	var config map[string]any
	if err := json.Unmarshal(raw, &config); err != nil {
		return nil, err
	}
	inbounds, _ := config["inbounds"].([]any)
	users := map[string]int64{}
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
			email := strings.TrimSpace(fmt.Sprint(clientMap["email"]))
			parts := strings.SplitN(email, "|", 2)
			username := strings.TrimSpace(parts[0])
			if username == "" {
				username = strings.TrimSpace(fmt.Sprint(clientMap["id"]))
			}
			if username == "" {
				continue
			}
			expiresAt := int64(0)
			if len(parts) == 2 {
				expiresAt = parseOptionalUnix(parts[1])
			}
			current, ok := users[username]
			if !ok || expiresAt > current {
				users[username] = expiresAt
			}
		}
	}
	accounts := make([]accountRecord, 0, len(users))
	for username, expiresAt := range users {
		accounts = append(accounts, buildAccountRecord("vless", username, expiresAt))
	}
	sortAccountRecords(accounts)
	return accounts, nil
}

func listHysteriaAccounts() ([]accountRecord, error) {
	dbPath := "/etc/hysteria/udpusers.db"
	if _, err := os.Stat(dbPath); err != nil {
		if os.IsNotExist(err) {
			return []accountRecord{}, nil
		}
		return nil, err
	}
	out, err := exec.Command(
		"sqlite3",
		"-separator",
		"\t",
		dbPath,
		"SELECT username,COALESCE(expiry,0) FROM users WHERE username IS NOT NULL AND username != '' ORDER BY username;",
	).CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(string(out))
		if strings.Contains(strings.ToLower(message), "no such table") {
			return []accountRecord{}, nil
		}
		return nil, fmt.Errorf("%s: %s", err.Error(), message)
	}
	accounts := []accountRecord{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.SplitN(line, "\t", 2)
		username := strings.TrimSpace(parts[0])
		if username == "" {
			continue
		}
		expiresAt := int64(0)
		if len(parts) == 2 {
			expiresAt = parseOptionalUnix(parts[1])
		}
		accounts = append(accounts, buildAccountRecord("hysteria", username, expiresAt))
	}
	sortAccountRecords(accounts)
	return accounts, nil
}

func listOpenVPNAccounts() ([]accountRecord, error) {
	raw, err := os.ReadFile("/etc/openvpn/users.txt")
	if err != nil {
		if os.IsNotExist(err) {
			return []accountRecord{}, nil
		}
		return nil, err
	}
	users := map[string]int64{}
	for _, line := range strings.Split(string(raw), "\n") {
		username, _, expiresAt, ok := parseOpenVPNUserLine(line)
		if !ok {
			continue
		}
		current, seen := users[username]
		if !seen || expiresAt > current {
			users[username] = expiresAt
		}
	}
	accounts := make([]accountRecord, 0, len(users))
	for username, expiresAt := range users {
		accounts = append(accounts, buildAccountRecord("openvpn", username, expiresAt))
	}
	sortAccountRecords(accounts)
	return accounts, nil
}

func deleteManagedAccount(service, username string) (string, string, error) {
	service = normalizeManagedService(service)
	if service == "" {
		return "", "", errors.New("invalid service")
	}
	normalizedUsername, err := normalizeManagedUsername(username)
	if err != nil {
		return "", "", err
	}
	accounts, err := listManagedAccounts(service)
	if err != nil {
		return "", "", err
	}
	found := false
	for _, account := range accounts {
		if account.Username == normalizedUsername {
			found = true
			break
		}
	}
	if !found {
		return "", "", errors.New("account not found")
	}
	removeScheduledCleanup(service, normalizedUsername)
	switch service {
	case "ssh":
		err = cleanupSSH(normalizedUsername)
	case "vless":
		err = cleanupVLESS(normalizedUsername)
	case "hysteria":
		err = cleanupHysteria(normalizedUsername)
	case "wireguard":
		err = cleanupWireGuard(normalizedUsername)
	case "openvpn":
		err = cleanupOpenVPN(normalizedUsername)
	}
	if err != nil {
		return "", "", err
	}
	return service, normalizedUsername, nil
}

func updateManagedAccountExpiry(service, username string, days int) (accountRecord, error) {
	service = normalizeManagedService(service)
	if service == "" {
		return accountRecord{}, errors.New("invalid service")
	}
	normalizedUsername, err := normalizeManagedUsername(username)
	if err != nil {
		return accountRecord{}, err
	}
	if days < 1 || days > 3650 {
		return accountRecord{}, errors.New("days must be between 1 and 3650")
	}
	expiresAt := time.Now().Add(time.Duration(days) * 24 * time.Hour).Unix()
	switch service {
	case "ssh":
		err = updateSSHExpiry(normalizedUsername, expiresAt)
	case "vless":
		err = updateVLESSExpiry(normalizedUsername, expiresAt)
	case "hysteria":
		err = updateHysteriaExpiry(normalizedUsername, expiresAt)
	case "wireguard":
		err = updateWireGuardExpiry(normalizedUsername, expiresAt)
	case "openvpn":
		err = updateOpenVPNExpiry(normalizedUsername, expiresAt)
	}
	if err != nil {
		return accountRecord{}, err
	}
	scheduleManagedCleanup(service, normalizedUsername, expiresAt)
	accounts, err := listManagedAccounts(service)
	if err != nil {
		return buildAccountRecord(service, normalizedUsername, expiresAt), nil
	}
	for _, account := range accounts {
		if account.Username == normalizedUsername {
			return account, nil
		}
	}
	return buildAccountRecord(service, normalizedUsername, expiresAt), nil
}

func updateSSHExpiry(username string, expiresAt int64) error {
	path := filepath.Join("/var/lib/regular_users", username)
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return errors.New("account not found")
		}
		return err
	}
	return os.WriteFile(path, []byte(strconv.FormatInt(expiresAt, 10)), 0644)
}

func updateVLESSExpiry(username string, expiresAt int64) error {
	configPath := "/etc/xray/config.json"
	raw, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return errors.New("account not found")
		}
		return err
	}
	var config map[string]any
	if err := json.Unmarshal(raw, &config); err != nil {
		return err
	}
	inbounds, _ := config["inbounds"].([]any)
	found := false
	for _, item := range inbounds {
		inbound, ok := item.(map[string]any)
		if !ok || fmt.Sprint(inbound["protocol"]) != "vless" {
			continue
		}
		settings, _ := inbound["settings"].(map[string]any)
		clients, _ := settings["clients"].([]any)
		for index, clientItem := range clients {
			clientMap, ok := clientItem.(map[string]any)
			if !ok {
				continue
			}
			email := fmt.Sprint(clientMap["email"])
			parts := strings.SplitN(email, "|", 2)
			currentUsername := strings.TrimSpace(parts[0])
			if currentUsername == "" {
				currentUsername = strings.TrimSpace(fmt.Sprint(clientMap["id"]))
			}
			if currentUsername != username {
				continue
			}
			clientMap["email"] = fmt.Sprintf("%s|%d", username, expiresAt)
			clients[index] = clientMap
			found = true
		}
		settings["clients"] = clients
	}
	if !found {
		return errors.New("account not found")
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

func updateHysteriaExpiry(username string, expiresAt int64) error {
	dbPath := "/etc/hysteria/udpusers.db"
	if _, err := os.Stat(dbPath); err != nil {
		if os.IsNotExist(err) {
			return errors.New("account not found")
		}
		return err
	}
	safeUser := strings.ReplaceAll(username, "'", "''")
	out, err := exec.Command("sqlite3", dbPath, fmt.Sprintf("SELECT COUNT(*) FROM users WHERE username='%s';", safeUser)).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s", err.Error(), strings.TrimSpace(string(out)))
	}
	if strings.TrimSpace(string(out)) == "" || strings.TrimSpace(string(out)) == "0" {
		return errors.New("account not found")
	}
	if output, err := exec.Command("sqlite3", dbPath, fmt.Sprintf("UPDATE users SET expiry=%d WHERE username='%s';", expiresAt, safeUser)).CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %s", err.Error(), strings.TrimSpace(string(output)))
	}
	if err := updateHysteriaConfig(); err != nil {
		return err
	}
	return restartServiceAny("hysteria-server.service", "hysteria-v1.service")
}

func updateOpenVPNExpiry(username string, expiresAt int64) error {
	path := "/etc/openvpn/users.txt"
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return errors.New("account not found")
		}
		return err
	}
	lines := []string{}
	found := false
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		currentUsername, password, _, ok := parseOpenVPNUserLine(line)
		if !ok {
			lines = append(lines, line)
			continue
		}
		if currentUsername != username {
			lines = append(lines, line)
			continue
		}
		lines = append(lines, fmt.Sprintf("%s:%s:%d", username, password, expiresAt))
		found = true
	}
	if !found {
		return errors.New("account not found")
	}
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0644)
}

func wireGuardParamFiles(interfaceName string) []string {
	return []string{
		"/etc/wireguard/params",
		filepath.Join("/etc/wireguard", interfaceName+".params"),
		filepath.Join("/etc/wireguard", interfaceName+".env"),
	}
}

func parseKeyValueFile(raw string) map[string]string {
	values := map[string]string{}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		if key == "" {
			continue
		}
		value := strings.TrimSpace(parts[1])
		value = strings.Trim(value, `"'`)
		values[key] = value
	}
	return values
}

func readKeyValueFile(path string) map[string]string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return map[string]string{}
	}
	return parseKeyValueFile(string(raw))
}

func loadWireGuardConfig() wireGuardConfig {
	interfaceName := strings.TrimSpace(envOr("FUJI_WIREGUARD_INTERFACE", ""))
	if interfaceName == "" {
		interfaceName = "wg0"
	}
	params := map[string]string{}
	loadParams := func(iface string) map[string]string {
		loaded := map[string]string{}
		for _, path := range wireGuardParamFiles(iface) {
			for key, value := range readKeyValueFile(path) {
				loaded[key] = value
			}
		}
		return loaded
	}
	params = loadParams(interfaceName)
	if strings.TrimSpace(envOr("FUJI_WIREGUARD_INTERFACE", "")) == "" {
		if nic := strings.TrimSpace(params["SERVER_WG_NIC"]); nic != "" && nic != interfaceName {
			interfaceName = nic
			params = loadParams(interfaceName)
		}
	}
	configPath := strings.TrimSpace(envOr("FUJI_WIREGUARD_CONFIG", ""))
	if configPath == "" {
		configPath = filepath.Join("/etc/wireguard", interfaceName+".conf")
	}
	clientsDir := strings.TrimSpace(envOr("FUJI_WIREGUARD_CLIENT_DIR", ""))
	if clientsDir == "" {
		for _, key := range []string{"WIREGUARD_CLIENT_DIR", "WG_CLIENT_DIR", "CLIENT_CONFIG_DIR"} {
			if value := strings.TrimSpace(params[key]); value != "" {
				clientsDir = value
				break
			}
		}
	}
	if clientsDir == "" {
		clientsDir = filepath.Join("/etc/wireguard", "clients")
	}
	return wireGuardConfig{
		InterfaceName: interfaceName,
		ConfigPath:    configPath,
		ClientsDir:    clientsDir,
		Params:        params,
	}
}

func parseWireGuardInterfaceValue(raw []byte, key string) string {
	inInterface := false
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if idx := strings.Index(trimmed, "#"); idx >= 0 {
			trimmed = strings.TrimSpace(trimmed[:idx])
		}
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			inInterface = strings.EqualFold(strings.Trim(trimmed, "[]"), "Interface")
			continue
		}
		if !inInterface {
			continue
		}
		parts := strings.SplitN(trimmed, "=", 2)
		if len(parts) != 2 {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(parts[0]), key) {
			return strings.TrimSpace(parts[1])
		}
	}
	return ""
}

func splitCSVValues(raw string) []string {
	values := []string{}
	for _, part := range strings.Split(raw, ",") {
		value := strings.TrimSpace(part)
		if value != "" {
			values = append(values, value)
		}
	}
	return values
}

func parseFirstIPv4CIDR(raw string) (net.IP, *net.IPNet, error) {
	for _, value := range splitCSVValues(raw) {
		ip, network, err := net.ParseCIDR(value)
		if err != nil {
			continue
		}
		if ipv4 := ip.To4(); ipv4 != nil {
			network.IP = network.IP.To4()
			return ipv4, network, nil
		}
	}
	return nil, nil, errors.New("no IPv4 CIDR found")
}

func parseFirstIPv4Subnet(raw string) (*net.IPNet, error) {
	for _, value := range splitCSVValues(raw) {
		_, network, err := net.ParseCIDR(value)
		if err != nil {
			continue
		}
		if ipv4 := network.IP.To4(); ipv4 != nil {
			network.IP = ipv4
			return network, nil
		}
	}
	return nil, errors.New("no IPv4 subnet found")
}

func deriveWireGuardPublicKey(privateKey string) string {
	privateKey = strings.TrimSpace(privateKey)
	if privateKey == "" {
		return ""
	}
	cmd := exec.Command("wg", "pubkey")
	cmd.Stdin = strings.NewReader(privateKey + "\n")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}

func wireGuardDefaultDNS() string {
	if value := strings.TrimSpace(readTrim("/etc/nameserver")); value != "" {
		return value
	}
	raw, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "nameserver" {
			return strings.TrimSpace(fields[1])
		}
	}
	return ""
}

func loadWireGuardCreateSettings(a *app) (*wireGuardCreateSettings, error) {
	cfg := loadWireGuardConfig()
	raw, err := os.ReadFile(cfg.ConfigPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("wireguard config not found at %s", cfg.ConfigPath)
		}
		return nil, err
	}
	settings := &wireGuardCreateSettings{
		wireGuardConfig: cfg,
		ServerPort:      "51820",
		AllowedIPs:      "0.0.0.0/0, ::/0",
	}
	if value := strings.TrimSpace(cfg.Params["SERVER_PUB_KEY"]); value != "" {
		settings.ServerPubKey = value
	}
	if settings.ServerPubKey == "" {
		if output, err := exec.Command("wg", "show", cfg.InterfaceName, "public-key").CombinedOutput(); err == nil {
			settings.ServerPubKey = strings.TrimSpace(string(output))
		}
	}
	if settings.ServerPubKey == "" {
		settings.ServerPubKey = deriveWireGuardPublicKey(parseWireGuardInterfaceValue(raw, "PrivateKey"))
	}
	if settings.ServerPubKey == "" {
		return nil, errors.New("wireguard server public key is not configured")
	}
	if value := strings.TrimSpace(cfg.Params["SERVER_PUB_IP"]); value != "" {
		settings.ServerPubIP = value
	} else {
		settings.ServerPubIP = currentDomain(a)
		if settings.ServerPubIP == "" || settings.ServerPubIP == "N/A" {
			settings.ServerPubIP = serverIP()
		}
	}
	if value := strings.TrimSpace(cfg.Params["SERVER_PORT"]); value != "" {
		settings.ServerPort = value
	} else if value := strings.TrimSpace(parseWireGuardInterfaceValue(raw, "ListenPort")); value != "" {
		settings.ServerPort = value
	}
	if value := strings.TrimSpace(cfg.Params["ALLOWED_IPS"]); value != "" {
		settings.AllowedIPs = value
	}
	if value := strings.TrimSpace(cfg.Params["CLIENT_DNS_1"]); value != "" {
		settings.ClientDNS = value
	} else {
		settings.ClientDNS = wireGuardDefaultDNS()
	}
	if ip, network, err := parseFirstIPv4CIDR(strings.TrimSpace(cfg.Params["SERVER_WG_IPV4"])); err == nil {
		settings.ServerIPv4 = ip
		settings.ServerIPv4Subnet = network
	}
	if settings.ServerIPv4 == nil || settings.ServerIPv4Subnet == nil {
		if ip, network, err := parseFirstIPv4CIDR(parseWireGuardInterfaceValue(raw, "Address")); err == nil {
			settings.ServerIPv4 = ip
			settings.ServerIPv4Subnet = network
		}
	}
	if subnetValue := strings.TrimSpace(cfg.Params["SERVER_WG_IPV4_SUBNET"]); subnetValue != "" {
		network, err := parseFirstIPv4Subnet(subnetValue)
		if err != nil {
			return nil, fmt.Errorf("invalid wireguard subnet: %w", err)
		}
		settings.ServerIPv4Subnet = network
	}
	if settings.ServerIPv4 == nil || settings.ServerIPv4Subnet == nil {
		return nil, errors.New("wireguard IPv4 subnet is not configured")
	}
	return settings, nil
}

func wireGuardClientConfPath(cfg wireGuardConfig, username string) string {
	return filepath.Join(cfg.ClientsDir, username+".conf")
}

func wireGuardClientMetaPath(cfg wireGuardConfig, username string) string {
	return filepath.Join(cfg.ClientsDir, username+".meta")
}

func wireGuardClientQRPath(cfg wireGuardConfig, username string) string {
	return filepath.Join(cfg.ClientsDir, username+".png")
}

func wireGuardClientExists(cfg wireGuardConfig, username string) bool {
	if _, err := os.Stat(wireGuardClientMetaPath(cfg, username)); err == nil {
		return true
	}
	raw, err := os.ReadFile(cfg.ConfigPath)
	if err != nil {
		return false
	}
	return strings.Contains(string(raw), "# BEGIN_PEER "+username)
}

func wireGuardNextIPv4(ip net.IP) net.IP {
	next := append(net.IP(nil), ip.To4()...)
	for i := len(next) - 1; i >= 0; i-- {
		next[i]++
		if next[i] != 0 {
			break
		}
	}
	return next
}

func wireGuardBroadcastIPv4(network *net.IPNet) net.IP {
	broadcast := append(net.IP(nil), network.IP.To4()...)
	mask := network.Mask
	for i := range broadcast {
		broadcast[i] |= ^mask[i]
	}
	return broadcast
}

func wireGuardUsedIPv4s(settings *wireGuardCreateSettings, raw []byte) map[string]struct{} {
	used := map[string]struct{}{}
	if settings.ServerIPv4 != nil {
		used[settings.ServerIPv4.String()] = struct{}{}
	}
	for _, line := range strings.Split(string(raw), "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), "=", 2)
		if len(parts) != 2 || !strings.EqualFold(strings.TrimSpace(parts[0]), "AllowedIPs") {
			continue
		}
		for _, candidate := range splitCSVValues(parts[1]) {
			ip, _, err := net.ParseCIDR(candidate)
			if err != nil {
				continue
			}
			if ipv4 := ip.To4(); ipv4 != nil {
				used[ipv4.String()] = struct{}{}
			}
		}
	}
	entries, err := os.ReadDir(settings.ClientsDir)
	if err != nil {
		return used
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".meta") {
			continue
		}
		meta := readKeyValueFile(filepath.Join(settings.ClientsDir, entry.Name()))
		if clientIP := strings.TrimSpace(meta["CLIENT_IPV4"]); clientIP != "" {
			used[clientIP] = struct{}{}
		}
	}
	return used
}

func wireGuardNextClientIPv4(settings *wireGuardCreateSettings, raw []byte) (string, error) {
	used := wireGuardUsedIPv4s(settings, raw)
	networkIP := settings.ServerIPv4Subnet.IP.Mask(settings.ServerIPv4Subnet.Mask).To4()
	if networkIP == nil {
		return "", errors.New("wireguard IPv4 subnet is invalid")
	}
	broadcast := wireGuardBroadcastIPv4(settings.ServerIPv4Subnet)
	for candidate := wireGuardNextIPv4(networkIP); settings.ServerIPv4Subnet.Contains(candidate); candidate = wireGuardNextIPv4(candidate) {
		if candidate.Equal(networkIP) || candidate.Equal(broadcast) {
			continue
		}
		if _, exists := used[candidate.String()]; exists {
			continue
		}
		return candidate.String(), nil
	}
	return "", fmt.Errorf("no free WireGuard client IP is available in %s", settings.ServerIPv4Subnet.String())
}

func wireGuardClientConfigContent(settings *wireGuardCreateSettings, privateKey, psk, clientIPv4 string) string {
	lines := []string{
		"[Interface]",
		"PrivateKey = " + privateKey,
		"Address = " + clientIPv4 + "/32",
	}
	if strings.TrimSpace(settings.ClientDNS) != "" {
		lines = append(lines, "DNS = "+strings.TrimSpace(settings.ClientDNS))
	}
	lines = append(lines,
		"",
		"[Peer]",
		"PublicKey = "+settings.ServerPubKey,
		"PresharedKey = "+psk,
		"AllowedIPs = "+settings.AllowedIPs,
		"Endpoint = "+net.JoinHostPort(settings.ServerPubIP, settings.ServerPort),
	)
	return strings.Join(lines, "\n") + "\n"
}

func wireGuardMetaContent(username, clientIPv4, publicKey, confPath, qrPath string, createdAt, expiresAt int64) string {
	return strings.Join([]string{
		"CLIENT_NAME=" + username,
		"CLIENT_IPV4=" + clientIPv4,
		"CLIENT_PUBLIC_KEY=" + publicKey,
		"CLIENT_CONFIG=" + confPath,
		"CLIENT_QR=" + qrPath,
		"CREATED_AT=" + strconv.FormatInt(createdAt, 10),
		"EXPIRES_AT=" + strconv.FormatInt(expiresAt, 10),
		"",
	}, "\n")
}

func wireGuardAddPeerBlock(raw []byte, username, publicKey, psk, clientIPv4 string) []byte {
	trimmed := strings.TrimRight(string(raw), "\r\n")
	peerBlock := fmt.Sprintf("# BEGIN_PEER %s\n[Peer]\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = %s/32\n# END_PEER %s\n", username, publicKey, psk, clientIPv4, username)
	if trimmed == "" {
		return []byte(peerBlock)
	}
	return []byte(trimmed + "\n\n" + peerBlock)
}

func wireGuardRemovePeerBlock(raw []byte, username string) ([]byte, bool) {
	text := string(raw)
	startMarker := "# BEGIN_PEER " + username
	endMarker := "# END_PEER " + username
	start := strings.Index(text, startMarker)
	if start < 0 {
		return raw, false
	}
	endOffset := strings.Index(text[start:], endMarker)
	if endOffset < 0 {
		return raw, false
	}
	end := start + endOffset + len(endMarker)
	for end < len(text) && (text[end] == '\n' || text[end] == '\r') {
		end++
	}
	before := strings.TrimRight(text[:start], "\r\n")
	after := strings.TrimLeft(text[end:], "\r\n")
	switch {
	case before == "" && after == "":
		return []byte{}, true
	case before == "":
		return []byte(after + "\n"), true
	case after == "":
		return []byte(before + "\n"), true
	default:
		return []byte(before + "\n\n" + after + "\n"), true
	}
}

func wireGuardGenerateQR(path, content string) {
	if _, err := exec.LookPath("qrencode"); err != nil {
		return
	}
	cmd := exec.Command("qrencode", "-o", path, "-t", "PNG")
	cmd.Stdin = strings.NewReader(content)
	_ = cmd.Run()
}

func wireGuardApplyPeerRuntime(settings *wireGuardCreateSettings, publicKey, psk, clientIPv4 string) {
	if _, err := exec.LookPath("wg"); err != nil {
		return
	}
	handle, err := os.CreateTemp("", "fuji-wg-peer-*.conf")
	if err != nil {
		return
	}
	tmpPath := handle.Name()
	_ = handle.Close()
	defer os.Remove(tmpPath)
	content := fmt.Sprintf("[Peer]\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = %s/32\n", publicKey, psk, clientIPv4)
	if err := os.WriteFile(tmpPath, []byte(content), 0600); err != nil {
		return
	}
	_, _ = exec.Command("wg", "addconf", settings.InterfaceName, tmpPath).CombinedOutput()
}

func listWireGuardAccounts() ([]accountRecord, error) {
	cfg := loadWireGuardConfig()
	entries, err := os.ReadDir(cfg.ClientsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []accountRecord{}, nil
		}
		return nil, err
	}
	accounts := []accountRecord{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".meta") {
			continue
		}
		meta := readKeyValueFile(filepath.Join(cfg.ClientsDir, entry.Name()))
		username := strings.TrimSpace(meta["CLIENT_NAME"])
		if username == "" {
			username = strings.TrimSuffix(entry.Name(), ".meta")
		}
		if username == "" {
			continue
		}
		expiresAt := parseOptionalUnix(meta["EXPIRES_AT"])
		accounts = append(accounts, buildAccountRecord("wireguard", username, expiresAt))
	}
	sortAccountRecords(accounts)
	return accounts, nil
}

func updateWireGuardExpiry(username string, expiresAt int64) error {
	cfg := loadWireGuardConfig()
	metaPath := wireGuardClientMetaPath(cfg, username)
	if _, err := os.Stat(metaPath); err != nil {
		if os.IsNotExist(err) {
			return errors.New("account not found")
		}
		return err
	}
	meta := readKeyValueFile(metaPath)
	clientIP := strings.TrimSpace(meta["CLIENT_IPV4"])
	publicKey := strings.TrimSpace(meta["CLIENT_PUBLIC_KEY"])
	confPath := strings.TrimSpace(meta["CLIENT_CONFIG"])
	if confPath == "" {
		confPath = wireGuardClientConfPath(cfg, username)
	}
	qrPath := strings.TrimSpace(meta["CLIENT_QR"])
	if qrPath == "" {
		qrPath = wireGuardClientQRPath(cfg, username)
	}
	createdAt := parseOptionalUnix(meta["CREATED_AT"])
	if createdAt == 0 {
		createdAt = time.Now().Unix()
	}
	content := wireGuardMetaContent(username, clientIP, publicKey, confPath, qrPath, createdAt, expiresAt)
	if err := os.WriteFile(metaPath, []byte(content), 0600); err != nil {
		return err
	}
	return os.Chmod(metaPath, 0600)
}

func cleanupWireGuard(username string) error {
	cfg := loadWireGuardConfig()
	meta := readKeyValueFile(wireGuardClientMetaPath(cfg, username))
	if raw, err := os.ReadFile(cfg.ConfigPath); err == nil {
		if updated, removed := wireGuardRemovePeerBlock(raw, username); removed {
			if err := os.WriteFile(cfg.ConfigPath, updated, 0644); err != nil {
				return err
			}
		}
	}
	if publicKey := strings.TrimSpace(meta["CLIENT_PUBLIC_KEY"]); publicKey != "" {
		_, _ = exec.Command("wg", "set", cfg.InterfaceName, "peer", publicKey, "remove").CombinedOutput()
	}
	_ = os.Remove(wireGuardClientConfPath(cfg, username))
	_ = os.Remove(wireGuardClientMetaPath(cfg, username))
	_ = os.Remove(wireGuardClientQRPath(cfg, username))
	return nil
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

func defaultPanelConfig() panelConfig {
	return panelConfig{
		DailyLimit: 30,
		CreateExpiry: map[string]int{
			"ssh":      5,
			"vless":    3,
			"hysteria": 5,
			"wireguard": 2,
			"openvpn":  3,
		},
		VLESSBypassOptions: []map[string]any{},
	}
}

func defaultPanelState() panelState {
	return panelState{
		DailyDate:   panelLocalDate(),
		DailyCounts: map[string]map[string]uint64{},
	}
}

func normalizePanelState(state panelState) panelState {
	normalized := defaultPanelState()
	normalized.TotalVisits = state.TotalVisits
	normalized.TotalAccounts = state.TotalAccounts
	normalized.LastOnlineUsers = state.LastOnlineUsers
	normalized.LastStatusTotalAccounts = state.LastStatusTotalAccounts
	normalized.DailyDate = normalizePanelDate(state.DailyDate)
	if normalized.DailyDate != panelLocalDate() {
		normalized.DailyDate = panelLocalDate()
		normalized.DailyCounts = map[string]map[string]uint64{}
	} else {
		normalized.DailyCounts = normalizePanelDailyCounts(state.DailyCounts)
	}
	if state.UpdatedAt > 0 {
		normalized.UpdatedAt = state.UpdatedAt
	}
	return normalized
}

func loadPanelState() panelState {
	raw, err := os.ReadFile(panelStatePath)
	if err != nil {
		return defaultPanelState()
	}
	var state panelState
	if err := json.Unmarshal(raw, &state); err != nil {
		return defaultPanelState()
	}
	return normalizePanelState(state)
}

func savePanelState(state panelState) (panelState, error) {
	normalized := normalizePanelState(state)
	normalized.UpdatedAt = time.Now().Unix()
	if err := os.MkdirAll(filepath.Dir(panelStatePath), 0755); err != nil {
		return normalized, err
	}
	raw, err := json.Marshal(normalized)
	if err != nil {
		return normalized, err
	}
	tmpPath := panelStatePath + ".tmp"
	if err := os.WriteFile(tmpPath, raw, 0644); err != nil {
		return normalized, err
	}
	if err := os.Rename(tmpPath, panelStatePath); err != nil {
		_ = os.Remove(tmpPath)
		return normalized, err
	}
	return normalized, nil
}

func (a *app) mutatePanelState(update func(*panelState) error) (panelState, error) {
	a.panelMu.Lock()
	defer a.panelMu.Unlock()
	state := loadPanelState()
	if err := update(&state); err != nil {
		return state, err
	}
	return savePanelState(state)
}

func normalizePanelConfig(cfg panelConfig) panelConfig {
	normalized := defaultPanelConfig()
	if cfg.DailyLimit > 0 {
		normalized.DailyLimit = cfg.DailyLimit
	}
	if normalized.DailyLimit < 1 {
		normalized.DailyLimit = 1
	}
	if normalized.DailyLimit > 999 {
		normalized.DailyLimit = 999
	}
	if cfg.CreateExpiry != nil {
		for service, fallback := range normalized.CreateExpiry {
			value := cfg.CreateExpiry[service]
			if value < 1 {
				value = fallback
			}
			if value > 3650 {
				value = 3650
			}
			normalized.CreateExpiry[service] = value
		}
	}
	if cfg.VLESSBypassOptions != nil {
		normalized.VLESSBypassOptions = cfg.VLESSBypassOptions
	}
	if cfg.UpdatedAt > 0 {
		normalized.UpdatedAt = cfg.UpdatedAt
	}
	return normalized
}

func loadPanelConfig() panelConfig {
	raw, err := os.ReadFile(panelConfigPath)
	if err != nil {
		return defaultPanelConfig()
	}
	var cfg panelConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return defaultPanelConfig()
	}
	return normalizePanelConfig(cfg)
}

func savePanelConfig(cfg panelConfig) (panelConfig, error) {
	normalized := normalizePanelConfig(cfg)
	normalized.UpdatedAt = time.Now().Unix()
	if err := os.MkdirAll(filepath.Dir(panelConfigPath), 0755); err != nil {
		return normalized, err
	}
	raw, err := json.Marshal(normalized)
	if err != nil {
		return normalized, err
	}
	tmpPath := panelConfigPath + ".tmp"
	if err := os.WriteFile(tmpPath, raw, 0644); err != nil {
		return normalized, err
	}
	if err := os.Rename(tmpPath, panelConfigPath); err != nil {
		_ = os.Remove(tmpPath)
		return normalized, err
	}
	return normalized, nil
}

func defaultDays(service string, value int) int {
	if value > 0 {
		return value
	}
	if configured := loadPanelConfig().CreateExpiry[strings.ToLower(strings.TrimSpace(service))]; configured > 0 {
		return configured
	}
	switch service {
	case "ssh", "hysteria":
		return 5
	case "wireguard":
		return 2
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

func fallbackBypassValue(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return strings.TrimSpace(fallback)
	}
	return value
}

func buildHysteriaHTTPInjectorLink(host, port, username, password, sni, obfs string) string {
	link := &url.URL{
		Scheme:   "hy2",
		User:     url.UserPassword(username, password),
		Host:     net.JoinHostPort(host, port),
		Fragment: username,
	}
	query := url.Values{}
	query.Set("sni", fallbackBypassValue(sni, host))
	query.Set("insecure", "1")
	if strings.TrimSpace(obfs) != "" && strings.TrimSpace(obfs) != "N/A" {
		query.Set("obfs", "salamander")
		query.Set("obfs-password", strings.TrimSpace(obfs))
	}
	link.RawQuery = query.Encode()
	return link.String()
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
	scheduleCleanupAt(time.Now().Add(time.Duration(days)*24*time.Hour).Unix(), command)
}

func scheduleCleanupAt(expiresAt int64, command string) {
	if expiresAt <= time.Now().Unix() {
		return
	}
	if _, err := exec.LookPath("at"); err != nil {
		return
	}
	runAt := time.Unix(expiresAt, 0).Format("200601021504")
	_, _ = exec.Command("bash", "-lc", fmt.Sprintf("printf '%%s\n' %q | at -t %s", command, runAt)).CombinedOutput()
}

func managedCleanupCommand(service, username string) string {
	return fmt.Sprintf("%s cleanup-%s %s", selfBinary(), service, username)
}

func removeScheduledCleanup(service, username string) {
	if _, err := exec.LookPath("atq"); err != nil {
		return
	}
	if _, err := exec.LookPath("atrm"); err != nil {
		return
	}
	if _, err := exec.LookPath("at"); err != nil {
		return
	}
	target := managedCleanupCommand(service, username)
	out, err := exec.Command("atq").Output()
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		jobID := fields[0]
		script, err := exec.Command("at", "-c", jobID).CombinedOutput()
		if err != nil {
			continue
		}
		if strings.Contains(string(script), target) {
			_, _ = exec.Command("atrm", jobID).CombinedOutput()
		}
	}
}

func scheduleManagedCleanup(service, username string, expiresAt int64) {
	removeScheduledCleanup(service, username)
	scheduleCleanupAt(expiresAt, managedCleanupCommand(service, username))
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
	scheduleManagedCleanup("ssh", username, expiry)
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
	scheduleManagedCleanup("vless", username, expiry)
	domain := currentDomain(a)
	tlsAddress := domain
	tlsHost := domain
	tlsSNI := domain
	nonTLSAddress := domain
	nonTLSHost := domain
	if req.BypassConfig != nil {
		tlsAddress = fallbackBypassValue(req.BypassConfig.TLS.Address, domain)
		tlsHost = fallbackBypassValue(req.BypassConfig.TLS.Host, domain)
		tlsSNI = fallbackBypassValue(req.BypassConfig.TLS.SNI, domain)
		nonTLSAddress = fallbackBypassValue(req.BypassConfig.NonTLS.Address, domain)
		nonTLSHost = fallbackBypassValue(req.BypassConfig.NonTLS.Host, domain)
	} else {
		switch strings.TrimSpace(req.BypassOption) {
		case "DITO_UNLI_SOCIAL":
			tlsSNI = "tiktok.jericoo.xyz"
			tlsAddress = tlsSNI
		case "SMART_POWER_ALL", "GLOBE_GOSHARE":
			nonTLSHost = "gecko-sg.tiktokv.com"
		}
	}
	sniParam := ""
	if tlsSNI != "" {
		sniParam = "&sni=" + url.QueryEscape(tlsSNI)
	}
	linkTLS := fmt.Sprintf("vless://%s@%s:443?encryption=none&type=ws&security=tls&host=%s&path=/vless%s#%s", username, tlsAddress, url.QueryEscape(tlsHost), sniParam, url.QueryEscape(username))
	linkNonTLS := fmt.Sprintf("vless://%s@%s:80?encryption=none&type=ws&host=%s&path=/vless#%s", username, nonTLSAddress, url.QueryEscape(nonTLSHost), url.QueryEscape(username))
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
	scheduleManagedCleanup("hysteria", username, expiry)
	domain := currentDomain(a)
	obfs := hysteriaObfs()
	port := hysteriaPort()
	injectorLink := buildHysteriaHTTPInjectorLink(domain, port, username, req.Password, domain, obfs)
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
	legacyLink := fmt.Sprintf("hysteria://%s:%s?%s#%s", domain, port, query.Encode(), url.QueryEscape(username))
	return map[string]any{
		"service":      "hysteria",
		"username":     username,
		"password":     req.Password,
		"expires_at":   expiry,
		"domain":       domain,
		"obfs":         obfs,
		"link":         injectorLink,
		"legacy_link":  legacyLink,
		"link_profile": "http_injector",
	}, nil
}

func (a *app) createWireGuard(req createWireGuardRequest) (map[string]any, error) {
	username, err := validateUsername(req.Username)
	if err != nil {
		return nil, err
	}
	settings, err := loadWireGuardCreateSettings(a)
	if err != nil {
		return nil, err
	}
	if wireGuardClientExists(settings.wireGuardConfig, username) {
		return nil, errors.New("username already exists")
	}
	rawConfig, err := os.ReadFile(settings.ConfigPath)
	if err != nil {
		return nil, err
	}
	clientIPv4, err := wireGuardNextClientIPv4(settings, rawConfig)
	if err != nil {
		return nil, err
	}
	privateKeyOutput, err := exec.Command("wg", "genkey").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s: %s", err.Error(), strings.TrimSpace(string(privateKeyOutput)))
	}
	clientPrivateKey := strings.TrimSpace(string(privateKeyOutput))
	if clientPrivateKey == "" {
		return nil, errors.New("failed to generate wireguard private key")
	}
	clientPublicKey := deriveWireGuardPublicKey(clientPrivateKey)
	if clientPublicKey == "" {
		return nil, errors.New("failed to derive wireguard public key")
	}
	pskOutput, err := exec.Command("wg", "genpsk").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s: %s", err.Error(), strings.TrimSpace(string(pskOutput)))
	}
	clientPSK := strings.TrimSpace(string(pskOutput))
	if clientPSK == "" {
		return nil, errors.New("failed to generate wireguard preshared key")
	}
	if err := os.MkdirAll(settings.ClientsDir, 0755); err != nil {
		return nil, err
	}
	if err := os.WriteFile(settings.ConfigPath, wireGuardAddPeerBlock(rawConfig, username, clientPublicKey, clientPSK, clientIPv4), 0644); err != nil {
		return nil, err
	}
	days := defaultDays("wireguard", req.Days)
	expiry := time.Now().Unix() + int64(days*86400)
	clientConfig := wireGuardClientConfigContent(settings, clientPrivateKey, clientPSK, clientIPv4)
	confPath := wireGuardClientConfPath(settings.wireGuardConfig, username)
	metaPath := wireGuardClientMetaPath(settings.wireGuardConfig, username)
	qrPath := wireGuardClientQRPath(settings.wireGuardConfig, username)
	if err := os.WriteFile(confPath, []byte(clientConfig), 0600); err != nil {
		return nil, err
	}
	metaContent := wireGuardMetaContent(username, clientIPv4, clientPublicKey, confPath, qrPath, time.Now().Unix(), expiry)
	if err := os.WriteFile(metaPath, []byte(metaContent), 0600); err != nil {
		return nil, err
	}
	_ = os.Chmod(confPath, 0600)
	_ = os.Chmod(metaPath, 0600)
	wireGuardGenerateQR(qrPath, clientConfig)
	wireGuardApplyPeerRuntime(settings, clientPublicKey, clientPSK, clientIPv4)
	scheduleManagedCleanup("wireguard", username, expiry)
	return map[string]any{
		"service":        "wireguard",
		"username":       username,
		"expires_at":     expiry,
		"domain":         settings.ServerPubIP,
		"endpoint":       net.JoinHostPort(settings.ServerPubIP, settings.ServerPort),
		"client_ip":      clientIPv4 + "/32",
		"config_path":    confPath,
		"config_content": clientConfig,
		"qr_path":        qrPath,
	}, nil
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
	content := fmt.Sprintf("# FUJI VPN\nclient\ndev tun\nproto tcp\nremote %s 443\nremote-cert-tls server\nresolv-retry infinite\nconnect-retry 5\ncipher AES-128-GCM\nauth SHA256\nnobind\npersist-key\npersist-tun\nsetenv CLIENT_CERT 0\nverb 3\n<auth-user-pass>\n%s\n%s\n</auth-user-pass>\n<ca>\n%s\n</ca>\n", host, username, req.Password, caText)
	ovpnPath := filepath.Join("/etc/openvpn", username+".ovpn")
	if err := os.WriteFile(ovpnPath, []byte(content), 0644); err != nil {
		return nil, err
	}
	scheduleManagedCleanup("openvpn", username, expiry)
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
	for _, key := range []string{"obfs-password", "obfs_password", "obfsPassword"} {
		if value := strings.TrimSpace(fmt.Sprint(config[key])); value != "" && value != "<nil>" {
			return value
		}
	}
	obfs, ok := config["obfs"].(map[string]any)
	if !ok {
		if value := strings.TrimSpace(fmt.Sprint(config["obfs"])); value != "" && value != "<nil>" && value != "map[]" {
			return value
		}
		return "N/A"
	}
	if value := strings.TrimSpace(fmt.Sprint(obfs["password"])); value != "" && value != "<nil>" {
		return value
	}
	if value := strings.TrimSpace(fmt.Sprint(obfs["config"])); value != "" && value != "<nil>" {
		return value
	}
	salamander, ok := obfs["salamander"].(map[string]any)
	if ok {
		if value := strings.TrimSpace(fmt.Sprint(salamander["password"])); value != "" && value != "<nil>" {
			return value
		}
	}
	return "N/A"
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

load_existing_env "$ENV_FILE"
TOKEN=""
DOMAIN_VALUE=""
if [[ -f /etc/domain ]]; then
  DOMAIN_VALUE="$(tr -d '\r\n' </etc/domain)"
fi

API_ADDR_VALUE="${FUJI_API_ADDR:-:67}"
API_TOKEN_VALUE="${FUJI_API_TOKEN:-}"
if [[ -z "$API_TOKEN_VALUE" ]]; then
  TOKEN="$(generate_token)"
  API_TOKEN_VALUE="$TOKEN"
fi
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
