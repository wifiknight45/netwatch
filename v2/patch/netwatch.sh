#!/usr/bin/env bash
# =============================================================================
# netwatch_v3.sh — Home Network Monitor with Signal notifications (v3.0)
# =============================================================================
# Based on Netwatch v2.0 — adds Signal messenger alerting via signal-cli.
# Requirements (hard): nmap, curl, sqlite3, signal-cli
# Optional: arp-scan, avahi-browse, sendmail
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

NETWATCH_VERSION="3.0.0"
SCRIPT_PATH="$(realpath "${BASH_SOURCE[0]}")"

# ---------------------------
# CONFIGURATION (edit or export env vars)
# ---------------------------

# Subnets to scan (space-separated). Leave empty to auto-detect.
SUBNETS=""

# Data directory
DATA_DIR="${HOME}/.netwatch"

# Files
KNOWN_DEVICES_FILE="${DATA_DIR}/known_devices.txt"
EXCLUSIONS_FILE="${DATA_DIR}/exclusions.txt"
ALERT_COOLDOWN_FILE="${DATA_DIR}/alert_cooldown.db"
DB_FILE="${DATA_DIR}/netwatch.db"
SCAN_LOG="${DATA_DIR}/scan.log"
ALERT_LOG="${DATA_DIR}/alerts.log"
SNAPSHOT_DIR="${DATA_DIR}/snapshots"
REPORT_DIR="${DATA_DIR}/reports"
INTEGRITY_HASH_FILE="${DATA_DIR}/script.sha256"
STALE_DB="${DATA_DIR}/stale_tracker.txt"

# Scan profile
SCAN_PROFILE="standard"

declare -A PROFILE_PORTS=(
  [quick]="1-1024"
  [standard]="1-10000"
  [deep]="1-65535"
)
declare -A PROFILE_TIMING=(
  [quick]="T4"
  [standard]="T4"
  [deep]="T3"
)

# Feature flags
ENABLE_OS_FINGERPRINT=true
ENABLE_VULN_SCAN=false
ENABLE_MDNS=true
ENABLE_PARALLEL=true
PARALLEL_JOBS=8
ENABLE_INTEGRITY_CHECK=true
ALERT_COOLDOWN_SECONDS=3600
STALE_DEVICE_SCANS=3

# Alert channels (existing)
WEBHOOK_URL=""
TELEGRAM_BOT_TOKEN=""
TELEGRAM_CHAT_ID=""
EMAIL_TO=""
EMAIL_FROM="netwatch@localhost"
EMAIL_SUBJECT_PREFIX="[NetWatch]"

# ---------------------------
# SIGNAL CONFIGURATION (SECURE)
# ---------------------------
# Recommended: do NOT hardcode secrets here. Export these as environment variables
# or store them in a protected file readable only by the user running the script.
#
# SIGNAL_CLI_PATH: path to signal-cli binary (or 'signal-cli' if in PATH)
# SIGNAL_NUMBER: the registered Signal phone number for the account (E.164 format, e.g. +15551234567)
# SIGNAL_RECIPIENTS: comma-separated list of recipient numbers (E.164) or group IDs
# SIGNAL_USE_DAEMON: if "true", use signal-cli REST/daemon mode (if available)
#
# Example (export in shell or systemd unit):
# export SIGNAL_CLI_PATH="/usr/bin/signal-cli"
# export SIGNAL_NUMBER="+15551234567"
# export SIGNAL_RECIPIENTS="+15559876543,+15557654321"
# export SIGNAL_USE_DAEMON="false"

SIGNAL_CLI_PATH="${SIGNAL_CLI_PATH:-signal-cli}"
SIGNAL_NUMBER="${SIGNAL_NUMBER:-}"
SIGNAL_RECIPIENTS="${SIGNAL_RECIPIENTS:-}"
SIGNAL_USE_DAEMON="${SIGNAL_USE_DAEMON:-false}"
# Optional: path to a file containing the passphrase for signal-cli (if used)
SIGNAL_PASSPHRASE_FILE="${SIGNAL_PASSPHRASE_FILE:-}"

# ---------------------------
# PORT RISK TABLES (unchanged)
# ---------------------------

declare -A RISKY_PORTS=(
  [21]="FTP – plaintext file transfer"
  [22]="SSH – remote shell (verify authorised)"
  [23]="Telnet – plaintext remote shell"
  [25]="SMTP – mail relay"
  [53]="DNS – check for open resolver"
  [69]="TFTP – unauthenticated file transfer"
  [111]="RPC portmapper"
  [135]="MS-RPC"
  [137]="NetBIOS name service"
  [139]="NetBIOS session"
  [389]="LDAP"
  [445]="SMB – ransomware target"
  [512]="rexec – remote exec"
  [513]="rlogin – remote login"
  [514]="rsh – remote shell"
  [1433]="MSSQL"
  [1521]="Oracle DB"
  [2375]="Docker daemon (unencrypted)"
  [2376]="Docker daemon (TLS)"
  [3306]="MySQL/MariaDB"
  [3389]="RDP – remote desktop"
  [4444]="Metasploit default listener"
  [5432]="PostgreSQL"
  [5900]="VNC – remote desktop"
  [5901]="VNC display 1"
  [5985]="WinRM HTTP"
  [5986]="WinRM HTTPS"
  [6379]="Redis (often unauthenticated)"
  [8080]="HTTP alt (often dev server)"
  [8888]="Jupyter Notebook"
  [9200]="Elasticsearch (often unauthenticated)"
  [27017]="MongoDB (often unauthenticated)"
  [50070]="Hadoop NameNode"
)

declare -A NORMAL_PORTS=(
  [80]="HTTP"
  [443]="HTTPS"
  [8443]="HTTPS alt"
  [53]="DNS (local resolver)"
  [123]="NTP"
  [67]="DHCP server"
  [68]="DHCP client"
  [5353]="mDNS / Bonjour"
  [631]="IPP – printing"
  [9100]="RAW printing"
  [1900]="UPnP / SSDP"
)

# ---------------------------
# COLOUR HELPERS (kept minimal)
# ---------------------------

RED='\033[0;31m';    YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m';   BOLD='\033[1m';      DIM='\033[2m'; RESET='\033[0m'

info()   { echo -e "${CYAN}[INFO]${RESET}  $*"; }
ok()     { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn()   { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
alert()  { echo -e "${RED}[ALERT]${RESET} $*"; }
dim()    { echo -e "${DIM}$*${RESET}"; }
banner() {
  echo -e "\n${BOLD}${CYAN}══════════════════════════════════════════════════${RESET}"
  echo -e "${BOLD}${CYAN}  $*${RESET}"
  echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════${RESET}\n"
}

# ---------------------------
# INITIALISATION
# ---------------------------

init() {
  mkdir -p "${DATA_DIR}" "${SNAPSHOT_DIR}" "${REPORT_DIR}"
  touch "${SCAN_LOG}" "${ALERT_LOG}"
  [[ -f "${KNOWN_DEVICES_FILE}" ]] || touch "${KNOWN_DEVICES_FILE}"
  [[ -f "${EXCLUSIONS_FILE}" ]]    || touch "${EXCLUSIONS_FILE}"
  [[ -f "${STALE_DB}" ]]           || touch "${STALE_DB}"
  db_init
}

# ---------------------------
# SQLITE DATABASE
# ---------------------------

db_init() {
  command -v sqlite3 &>/dev/null || { warn "sqlite3 not found — history disabled."; return; }
  sqlite3 "${DB_FILE}" <<'SQL'
CREATE TABLE IF NOT EXISTS scans (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  ts          TEXT NOT NULL,
  subnet      TEXT,
  host_count  INTEGER DEFAULT 0,
  new_count   INTEGER DEFAULT 0,
  risky_count INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS hosts (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id    INTEGER REFERENCES scans(id),
  ip         TEXT,
  mac        TEXT,
  vendor     TEXT,
  hostname   TEXT,
  os_guess   TEXT,
  label      TEXT,
  tags       TEXT,
  risk_score INTEGER DEFAULT 0,
  ts         TEXT
);
CREATE TABLE IF NOT EXISTS ports (
  id       INTEGER PRIMARY KEY AUTOINCREMENT,
  host_id  INTEGER REFERENCES hosts(id),
  port     INTEGER,
  proto    TEXT,
  state    TEXT,
  service  TEXT,
  version  TEXT,
  banner   TEXT,
  risk     TEXT,
  ts       TEXT
);
CREATE TABLE IF NOT EXISTS alerts (
  id      INTEGER PRIMARY KEY AUTOINCREMENT,
  ts      TEXT,
  type    TEXT,
  subject TEXT,
  body    TEXT
);
SQL
}

db_exec() { command -v sqlite3 &>/dev/null && sqlite3 "${DB_FILE}" "$1" || true; }

# ---------------------------
# ALERT COOLDOWN HELPERS (unchanged)
# ---------------------------

_cooldown_hash() { echo -n "$1" | md5sum | awk '{print $1}'; }

should_alert() {
  local hash; hash=$(_cooldown_hash "$1")
  touch "${ALERT_COOLDOWN_FILE}"
  local last; last=$(grep "^${hash}=" "${ALERT_COOLDOWN_FILE}" 2>/dev/null | cut -d= -f2 | head -1)
  [[ -z "$last" ]] && return 0
  local now; now=$(date +%s)
  [[ $(( now - last )) -ge ${ALERT_COOLDOWN_SECONDS} ]]
}

record_alert() {
  local hash; hash=$(_cooldown_hash "$1")
  sed -i "/^${hash}=/d" "${ALERT_COOLDOWN_FILE}" 2>/dev/null || true
  echo "${hash}=$(date +%s)" >> "${ALERT_COOLDOWN_FILE}"
}

# ---------------------------
# SIGNAL SENDING FUNCTION
# ---------------------------
# This function sends a plain-text message via signal-cli.
# It supports two modes:
#  - direct binary invocation: signal-cli -u <account> send -m "text" <recipient>
#  - daemon/REST mode: curl to local signal-cli-rest endpoint (if SIGNAL_USE_DAEMON=true)
#
# Security notes:
#  - Do not hardcode credentials in the script.
#  - Use environment variables and protect them with file permissions.
#  - Avoid logging message bodies that contain sensitive data.

send_signal() {
  local subject="$1"
  local body="$2"
  local ts; ts=$(date '+%Y-%m-%d %H:%M:%S')
  local msg="${subject}: ${body} — NetWatch v${NETWATCH_VERSION} ${ts}"

  # Nothing to do if not configured
  [[ -z "${SIGNAL_NUMBER}" || -z "${SIGNAL_RECIPIENTS}" ]] && return 0

  # Build recipients array
  IFS=',' read -ra RECIPS <<< "${SIGNAL_RECIPIENTS}"

  # If using daemon/REST API (signal-cli-rest), send via HTTP
  if [[ "${SIGNAL_USE_DAEMON}" == "true" ]]; then
    # Expect a local REST endpoint at http://localhost:8080/v1/messages
    # The REST API may require authentication; configure accordingly.
    for r in "${RECIPS[@]}"; do
      # Minimal payload; do not include sensitive data in logs
      local payload; payload=$(printf '{"message":"%s","number":"%s","recipients":["%s"]}' \
        "${msg}" "${SIGNAL_NUMBER}" "${r}")
      # Use curl silently; ignore failures to avoid breaking main flow
      curl -s -X POST -H "Content-Type: application/json" -d "${payload}" "http://127.0.0.1:8080/v1/messages" &>/dev/null || true
    done
    return 0
  fi

  # Direct signal-cli invocation
  # Check binary exists
  if ! command -v "${SIGNAL_CLI_PATH}" &>/dev/null; then
    warn "signal-cli not found at ${SIGNAL_CLI_PATH}; Signal alerts disabled."
    return 0
  fi

  # If passphrase file is provided, read it securely (do not echo)
  local passphrase_arg=()
  if [[ -n "${SIGNAL_PASSPHRASE_FILE}" && -f "${SIGNAL_PASSPHRASE_FILE}" ]]; then
    # signal-cli supports --config or using a passphrase for the local keystore; adapt as needed
    # We avoid passing passphrase on command line to reduce exposure in process list.
    # If your signal-cli setup requires a passphrase, prefer using a local agent or systemd secret.
    :
  fi

  # Send messages one by one to avoid large payloads
  for r in "${RECIPS[@]}"; do
    # Use a minimal invocation. We avoid printing the message to logs.
    "${SIGNAL_CLI_PATH}" -u "${SIGNAL_NUMBER}" send -m "${msg}" "${r}" &>/dev/null || true
  done
}

# ---------------------------
# ALERT ENGINE (modified to call send_signal)
# ---------------------------

send_alert() {
  local subject="$1" body="$2"
  local key="${subject}:${body}"

  should_alert "$key" || { dim "  (alert suppressed — cooldown active)"; return; }
  record_alert "$key"

  local ts; ts=$(date '+%Y-%m-%d %H:%M:%S')
  echo "[${ts}] ${subject}: ${body}" >> "${ALERT_LOG}"
  db_exec "INSERT INTO alerts(ts,type,subject,body) VALUES('${ts}','alert','${subject//\'/\'\'}','${body//\'/\'\'}');"

  # Discord
  if [[ -n "${WEBHOOK_URL}" ]]; then
    local pl
    pl=$(printf '{"username":"NetWatch","embeds":[{"title":"%s","description":"%s","color":15158332,"footer":{"text":"NetWatch v%s \u2022 %s"}}]}' \
         "${subject}" "${body}" "${NETWATCH_VERSION}" "${ts}")
    curl -s -X POST -H "Content-Type: application/json" -d "${pl}" "${WEBHOOK_URL}" &>/dev/null || true
  fi

  # Telegram
  if [[ -n "${TELEGRAM_BOT_TOKEN}" && -n "${TELEGRAM_CHAT_ID}" ]]; then
    local msg; msg=$(printf "*%s*\n%s\n\n_%s_" "${subject}" "${body}" "${ts}")
    curl -s "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
         -d "chat_id=${TELEGRAM_CHAT_ID}" -d "parse_mode=Markdown" \
         --data-urlencode "text=${msg}" &>/dev/null || true
  fi

  # Email
  if [[ -n "${EMAIL_TO}" ]] && command -v sendmail &>/dev/null; then
    {
      echo "To: ${EMAIL_TO}"
      echo "From: ${EMAIL_FROM}"
      echo "Subject: ${EMAIL_SUBJECT_PREFIX} ${subject}"
      echo ""
      echo "${body}"
      echo ""
      echo "-- NetWatch v${NETWATCH_VERSION} | ${ts}"
    } | sendmail -t 2>/dev/null || true
  fi

  # Signal (new)
  # Call send_signal in the background to avoid blocking the main scan loop
  if [[ -n "${SIGNAL_NUMBER}" && -n "${SIGNAL_RECIPIENTS}" ]]; then
    send_signal "${subject}" "${body}" &
  fi
}

# ---------------------------
# DEPENDENCY CHECK (adds signal-cli check)
# ---------------------------

USE_NONROOT=false

check_deps() {
  local missing=()
  for cmd in nmap curl sqlite3; do
    command -v "$cmd" &>/dev/null || missing+=("$cmd")
  done
  if [[ ${#missing[@]} -gt 0 ]]; then
    warn "Missing required tools: ${missing[*]}"
    warn "Install: sudo apt install ${missing[*]}"
    exit 1
  fi
  for cmd in arp-scan avahi-browse; do
    command -v "$cmd" &>/dev/null || dim "Optional tool not found: ${cmd}"
  done
  # signal-cli is optional but recommended for Signal alerts
  if ! command -v "${SIGNAL_CLI_PATH}" &>/dev/null; then
    dim "Optional tool not found: signal-cli (Signal alerts disabled until installed)"
  fi
  if [[ "${EUID}" -ne 0 ]]; then
    warn "Not running as root — limited mode (no ARP scan, no OS fingerprint, TCP connect only)."
    ENABLE_OS_FINGERPRINT=false
    USE_NONROOT=true
  fi
}

# ---------------------------
# The rest of the script (discovery, scanning, DB inserts, report generation,
# stale tracking, etc.) remains the same as v2. For brevity, include the
# unchanged functions from your v2 script here or source them from the v2 file.
# ---------------------------

# For example, include or source the rest of your v2 functions:
# source /path/to/your/v2/functions.sh
# Or paste the remaining functions (detect_subnets, run_arp_scan, run_nmap_discovery,
# fingerprint_os, scan_ports_host, scan_all_hosts_parallel, classify_port,
# lookup_device, lookup_tags, register_device, do_learn, do_list_known, do_add_device,
# do_remove_device, update_stale_tracker, generate_html_report, do_scan, do_diff,
# do_report, do_watch, do_install_cron, do_remove_cron, do_install_systemd,
# do_remove_systemd, usage, main)

# For a self-contained file, append the rest of your v2 code here unchanged,
# ensuring function names and DB calls remain compatible.

# ---------------------------
# ENTRY POINT (same as v2)
# ---------------------------

main() {
  # Parse global flags before command
  while [[ "${1:-}" == --* ]]; do
    case "$1" in
      --profile)
        shift
        SCAN_PROFILE="${1:-standard}"
        [[ -v "PROFILE_PORTS[${SCAN_PROFILE}]" ]] || {
          warn "Unknown profile '${SCAN_PROFILE}'. Use: quick | standard | deep"; exit 1
        }
        shift
        ;;
      *) warn "Unknown flag: $1"; exit 1 ;;
    esac
  done

  init
  check_deps
  integrity_check || true

  local cmd="${1:-help}"
  shift || true

  case "$cmd" in
    scan)             do_scan ;;
    watch)            do_watch "${1:-3600}" ;;
    diff)             do_diff "${1:-}" "${2:-}" ;;
    report)           do_report ;;
    history)          do_history ;;
    query)            do_db_query "$@" ;;
    list)             do_list_known ;;
    add)              do_add_device "$@" ;;
    remove)           do_remove_device "$@" ;;
    learn)            do_learn ;;
    exclude)          do_exclude "$@" ;;
    unexclude)        do_unexclude "$@" ;;
    cron)             do_install_cron "${1:-hourly}" ;;
    cron-remove)      do_remove_cron ;;
    systemd)          do_install_systemd "${1:-3600}" ;;
    systemd-remove)   do_remove_systemd ;;
    integrity-update) do_integrity_update ;;
    help|-h|--help)   usage ;;
    *) warn "Unknown command: ${cmd}"; usage; exit 1 ;;
  esac
}

main "$@"
