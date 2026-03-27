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

type createOpenVPNRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Days     int    `json:"days"`
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
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":             true,
		"cpu":            cpuPercent(),
		"load":           loadAverage(),
		"mem":            memoryStats(),
		"storage":        storageStats(),
		"net":            a.networkStats(),
		"services":       serviceStatusEntries(),
		"online_users":   onlineUsersCount(),
		"total_accounts": totalAccountsCount(),
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

func onlineUsersCount() uint64 {
	allowed := regularSSHUsers()
	users := map[string]struct{}{}

	if out, err := exec.Command("who").Output(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			addOnlineUser(users, allowed, fields[0])
		}
	}

	if out, err := exec.Command("ps", "-eo", "args=").Output(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			match := sshdSessionUserRegex.FindStringSubmatch(strings.TrimSpace(line))
			if len(match) < 2 {
				continue
			}
			addOnlineUser(users, allowed, match[1])
		}
	}

	return uint64(len(users))
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
	raw, err := os.ReadFile("/etc/openvpn/users.txt")
	if err != nil {
		return 0
	}
	users := map[string]struct{}{}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		username := strings.TrimSpace(strings.SplitN(line, ":", 2)[0])
		if username == "" {
			continue
		}
		users[username] = struct{}{}
	}
	return uint64(len(users))
}

func totalAccountsCount() uint64 {
	return countSSHAccounts() + countVLESSAccounts() + countHysteriaAccounts() + countOpenVPNAccounts()
}

func normalizeManagedService(service string) string {
	switch strings.ToLower(strings.TrimSpace(service)) {
	case "ssh":
		return "ssh"
	case "vless":
		return "vless"
	case "hysteria":
		return "hysteria"
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
	serviceRank := map[string]int{"ssh": 0, "vless": 1, "hysteria": 2, "openvpn": 3}
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
	for _, service := range []string{"ssh", "vless", "hysteria", "openvpn"} {
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
