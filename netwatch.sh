#!/usr/bin/env bash
# =============================================================================
# netwatch.sh — Lightweight Home Network Monitor (v2.0)
# =============================================================================
# Full-featured home Wi-Fi monitor using nmap + arp-scan.
#
# Features:
#   • ARP + nmap host discovery (parallel)
#   • OS fingerprinting
#   • Service banner / version detection
#   • CVE lookup via nmap vulners script
#   • Reverse DNS + mDNS/Bonjour hostname resolution
#   • Full port enumeration with risk scoring
#   • Known-device allowlist with tags/groups
#   • Auto-registration (learn mode)
#   • Stale device tracking
#   • Alert deduplication / cooldown
#   • Discord + Telegram + Email alerts
#   • HTML report generation
#   • SQLite scan history backend
#   • Snapshot diffing
#   • Scan profiles (quick / standard / deep)
#   • Multi-subnet support
#   • Exclusion list
#   • Non-root graceful fallback
#   • Script integrity check
#   • Cron + systemd unit installer
#   • Watch mode
#
# Requirements (hard): nmap, curl, sqlite3
# Requirements (soft): arp-scan, avahi-browse, sendmail
# Run as root or with sudo for full ARP + SYN-scan capability.
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

# ─── VERSION & PATH ───────────────────────────────────────────────────────────

NETWATCH_VERSION="2.0.0"
SCRIPT_PATH="$(realpath "${BASH_SOURCE[0]}")"

# ─── CONFIGURATION ────────────────────────────────────────────────────────────

# Subnets to scan (space-separated). Leave empty to auto-detect.
SUBNETS=""                          # e.g. "192.168.1.0/24 10.0.0.0/24"

# Data directory
DATA_DIR="${HOME}/.netwatch"

# Files
KNOWN_DEVICES_FILE="${DATA_DIR}/known_devices.txt"  # MAC=Label[:tag1,tag2]
EXCLUSIONS_FILE="${DATA_DIR}/exclusions.txt"         # IPs or MACs to skip
ALERT_COOLDOWN_FILE="${DATA_DIR}/alert_cooldown.db"  # last-alerted timestamps
DB_FILE="${DATA_DIR}/netwatch.db"                    # SQLite history
SCAN_LOG="${DATA_DIR}/scan.log"
ALERT_LOG="${DATA_DIR}/alerts.log"
SNAPSHOT_DIR="${DATA_DIR}/snapshots"
REPORT_DIR="${DATA_DIR}/reports"
INTEGRITY_HASH_FILE="${DATA_DIR}/script.sha256"
STALE_DB="${DATA_DIR}/stale_tracker.txt"

# ── Scan Profiles ─────────────────────────────────────────────────────────────
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

# ── Feature Flags ─────────────────────────────────────────────────────────────
ENABLE_OS_FINGERPRINT=true        # nmap -O (requires root)
ENABLE_VULN_SCAN=false            # nmap --script vulners (install nmap-vulners first)
ENABLE_MDNS=true                  # avahi-browse mDNS discovery
ENABLE_PARALLEL=true              # parallel host port scans
PARALLEL_JOBS=8                   # max concurrent nmap jobs
ENABLE_INTEGRITY_CHECK=true       # warn if script checksum changes
ALERT_COOLDOWN_SECONDS=3600       # seconds before re-alerting same issue
STALE_DEVICE_SCANS=3              # flag device stale after N consecutive missed scans

# ── Alert Channels ────────────────────────────────────────────────────────────
WEBHOOK_URL=""                    # Discord webhook URL
TELEGRAM_BOT_TOKEN=""
TELEGRAM_CHAT_ID=""
EMAIL_TO=""                       # e.g. you@example.com
EMAIL_FROM="netwatch@localhost"
EMAIL_SUBJECT_PREFIX="[NetWatch]"

# ─── PORT RISK TABLES ─────────────────────────────────────────────────────────

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

# ─── COLOUR HELPERS ───────────────────────────────────────────────────────────

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

# ─── INITIALISATION ───────────────────────────────────────────────────────────

init() {
  mkdir -p "${DATA_DIR}" "${SNAPSHOT_DIR}" "${REPORT_DIR}"
  touch "${SCAN_LOG}" "${ALERT_LOG}"
  [[ -f "${KNOWN_DEVICES_FILE}" ]] || touch "${KNOWN_DEVICES_FILE}"
  [[ -f "${EXCLUSIONS_FILE}" ]]    || touch "${EXCLUSIONS_FILE}"
  [[ -f "${STALE_DB}" ]]           || touch "${STALE_DB}"
  db_init
}

# ─── SQLITE DATABASE ──────────────────────────────────────────────────────────

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

db_insert_scan() {
  local ts="$1" subnet="$2" hosts="$3" new="$4" risky="$5"
  command -v sqlite3 &>/dev/null || { echo "0"; return; }
  sqlite3 "${DB_FILE}" \
    "INSERT INTO scans(ts,subnet,host_count,new_count,risky_count)
     VALUES('${ts}','${subnet// /,}',${hosts},${new},${risky});
     SELECT last_insert_rowid();"
}

db_insert_host() {
  command -v sqlite3 &>/dev/null || { echo "0"; return; }
  local scan_id="$1" ip="$2" mac="$3" vendor="$4" hostname="$5" \
        os="$6" label="$7" tags="$8" score="$9" ts="${10}"
  vendor="${vendor//\'/\'\'}"; os="${os//\'/\'\'}"; label="${label//\'/\'\'}"
  sqlite3 "${DB_FILE}" \
    "INSERT INTO hosts(scan_id,ip,mac,vendor,hostname,os_guess,label,tags,risk_score,ts)
     VALUES(${scan_id},'${ip}','${mac}','${vendor}','${hostname}','${os}',
            '${label}','${tags}',${score},'${ts}');
     SELECT last_insert_rowid();"
}

db_insert_port() {
  command -v sqlite3 &>/dev/null || return
  local host_id="$1" port="$2" proto="$3" state="$4" \
        service="$5" version="$6" banner="$7" risk="$8" ts="$9"
  version="${version//\'/\'\'}"; banner="${banner//\'/\'\'}"
  db_exec "INSERT INTO ports(host_id,port,proto,state,service,version,banner,risk,ts)
           VALUES(${host_id},${port},'${proto}','${state}','${service}',
                  '${version}','${banner}','${risk}','${ts}');"
}

db_insert_alert() {
  command -v sqlite3 &>/dev/null || return
  local type="$1" subject="$2" body="${3//\'/\'\'}"
  local ts; ts=$(date '+%Y-%m-%d %H:%M:%S')
  db_exec "INSERT INTO alerts(ts,type,subject,body) VALUES('${ts}','${type}','${subject}','${body}');"
}

db_query() {
  command -v sqlite3 &>/dev/null || { warn "sqlite3 not installed."; return; }
  sqlite3 -column -header "${DB_FILE}" "$1"
}

do_history() {
  banner "Scan History (last 20)"
  db_query "SELECT id, ts, subnet, host_count, new_count, risky_count
            FROM scans ORDER BY id DESC LIMIT 20;"
}

do_db_query() {
  local sql="${1:-}"
  [[ -z "$sql" ]] && { warn "Usage: $0 query \"SELECT ...\""; exit 1; }
  db_query "$sql"
}

# ─── INTEGRITY CHECK ──────────────────────────────────────────────────────────

integrity_check() {
  [[ "${ENABLE_INTEGRITY_CHECK}" != "true" ]] && return
  local current_hash
  current_hash=$(sha256sum "${SCRIPT_PATH}" | awk '{print $1}')
  if [[ -f "${INTEGRITY_HASH_FILE}" ]]; then
    local stored_hash; stored_hash=$(cat "${INTEGRITY_HASH_FILE}")
    if [[ "$current_hash" != "$stored_hash" ]]; then
      warn "Script checksum mismatch — file may have been modified!"
      warn "  Stored : ${stored_hash}"
      warn "  Current: ${current_hash}"
      warn "  Run '$0 integrity-update' to accept the new version."
    fi
  else
    echo "${current_hash}" > "${INTEGRITY_HASH_FILE}"
    dim "Integrity baseline saved (${current_hash:0:16}…)"
  fi
}

do_integrity_update() {
  local h; h=$(sha256sum "${SCRIPT_PATH}" | awk '{print $1}')
  echo "$h" > "${INTEGRITY_HASH_FILE}"
  ok "Integrity hash updated: ${h}"
}

# ─── DEPENDENCY CHECK ─────────────────────────────────────────────────────────

# Set in check_deps; used throughout
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
  if [[ "${EUID}" -ne 0 ]]; then
    warn "Not running as root — limited mode (no ARP scan, no OS fingerprint, TCP connect only)."
    ENABLE_OS_FINGERPRINT=false
    USE_NONROOT=true
  fi
}

# ─── EXCLUSION LIST ───────────────────────────────────────────────────────────

is_excluded() {
  local target="${1^^}"
  [[ -f "${EXCLUSIONS_FILE}" ]] || return 1
  grep -qi "^${target}$" "${EXCLUSIONS_FILE}" 2>/dev/null
}

do_exclude() {
  [[ -z "${1:-}" ]] && { warn "Usage: $0 exclude <IP|MAC>"; exit 1; }
  echo "${1^^}" >> "${EXCLUSIONS_FILE}"
  ok "Excluded: $1"
}

do_unexclude() {
  local t="${1^^}"
  sed -i "/^${t}$/Id" "${EXCLUSIONS_FILE}" && ok "Removed exclusion: ${t}" || warn "Not found."
}

# ─── SUBNET DETECTION ─────────────────────────────────────────────────────────

detect_subnets() {
  if [[ -n "${SUBNETS}" ]]; then echo "${SUBNETS}"; return; fi
  local iface; iface=$(ip route 2>/dev/null | awk '/default/{print $5; exit}')
  local cidr; cidr=$(ip -o -f inet addr show "${iface}" 2>/dev/null | awk '{print $4}' | head -1)
  [[ -z "$cidr" ]] && { warn "Cannot auto-detect subnet. Set SUBNETS in config."; exit 1; }
  python3 -c "import ipaddress; print(ipaddress.ip_network('${cidr}',strict=False))" 2>/dev/null \
    || ipcalc -n "${cidr}" | awk -F= '/NETWORK/{print $2}'
}

# ─── HOSTNAME RESOLUTION ──────────────────────────────────────────────────────

resolve_hostname() {
  local ip="$1"
  host "${ip}" 2>/dev/null \
    | awk '/domain name pointer/{gsub(/\.$/,"",$NF); print $NF; exit}' || echo ""
}

run_mdns_discovery() {
  command -v avahi-browse &>/dev/null || return
  info "mDNS/Bonjour discovery …"
  avahi-browse -atrp 2>/dev/null | awk -F';' '/^=/{print $8, $7}' | grep -v '^$' || true
}

# ─── ARP + NMAP DISCOVERY ─────────────────────────────────────────────────────

run_arp_scan() {
  local subnet="$1"
  [[ "${USE_NONROOT}" == "true" ]] && return
  command -v arp-scan &>/dev/null || return
  info "ARP scanning ${subnet} …"
  arp-scan --localnet --retry=3 2>/dev/null \
    | awk '/^[0-9]/{print $1, $2, substr($0,index($0,$3))}' \
    || arp-scan "${subnet}" --retry=3 2>/dev/null \
       | awk '/^[0-9]/{print $1, $2, substr($0,index($0,$3))}' || true
}

run_nmap_discovery() {
  local subnet="$1"
  info "nmap ping sweep on ${subnet} …"
  local flags="-sn"
  [[ "${USE_NONROOT}" == "true" ]] && flags="-sn --unprivileged"
  nmap ${flags} "${subnet}" -oG - 2>/dev/null | awk '/Up$/{print $2}' || true
}

# ─── OS FINGERPRINTING ────────────────────────────────────────────────────────

fingerprint_os() {
  local ip="$1"
  [[ "${ENABLE_OS_FINGERPRINT}" != "true" ]] && return
  nmap -O --osscan-guess "${ip}" 2>/dev/null \
    | awk '/OS details:|Aggressive OS guesses:/{
        sub(/OS details: /,""); sub(/Aggressive OS guesses: /,"")
        gsub(/ \([0-9]+%\)/,""); print; exit
      }' || true
}

# ─── PORT SCAN ────────────────────────────────────────────────────────────────

scan_ports_host() {
  local ip="$1"
  local port_range="${PROFILE_PORTS[${SCAN_PROFILE}]}"
  local timing="${PROFILE_TIMING[${SCAN_PROFILE}]}"
  local flags="-p ${port_range} -${timing} --open --version-intensity 5 -sV --script banner"
  [[ "${USE_NONROOT}" == "true" ]] && flags="${flags} -sT"
  [[ "${ENABLE_VULN_SCAN}" == "true" ]] && flags="${flags} --script vulners"
  nmap ${flags} "${ip}" 2>/dev/null || true
}

# ─── PARALLEL SCANNER ─────────────────────────────────────────────────────────

scan_all_hosts_parallel() {
  # $1 = name of associative array [mac]=ip
  local -n _hosts=$1
  local tmp_dir; tmp_dir=$(mktemp -d)
  local pids=()

  for mac in "${!_hosts[@]}"; do
    local ip="${_hosts[$mac]}"
    is_excluded "$ip"  && continue
    is_excluded "$mac" && continue
    local out="${tmp_dir}/${mac//:/=}.nmap"
    ( scan_ports_host "$ip" > "$out" 2>/dev/null ) &
    pids+=($!)
    if [[ ${#pids[@]} -ge ${PARALLEL_JOBS} ]]; then
      wait "${pids[0]}" 2>/dev/null || true
      pids=("${pids[@]:1}")
    fi
  done
  for pid in "${pids[@]}"; do wait "$pid" 2>/dev/null || true; done
  echo "$tmp_dir"
}

# ─── PORT RISK CLASSIFIER ─────────────────────────────────────────────────────

classify_port() {
  local p="$1"
  if   [[ -v "RISKY_PORTS[$p]"  ]]; then echo "RISKY:${RISKY_PORTS[$p]}"
  elif [[ -v "NORMAL_PORTS[$p]" ]]; then echo "NORMAL:${NORMAL_PORTS[$p]}"
  else echo "UNKNOWN:"
  fi
}

# ─── KNOWN DEVICE REGISTRY ────────────────────────────────────────────────────
# Format per line: MAC=Label[:tag1,tag2]

lookup_device() {
  local mac="${1^^}"
  local line; line=$(grep -i "^${mac}=" "${KNOWN_DEVICES_FILE}" 2>/dev/null | head -1) || true
  [[ -z "$line" ]] && { echo "UNKNOWN"; return; }
  local val="${line#*=}"; echo "${val%%:*}"
}

lookup_tags() {
  local mac="${1^^}"
  local line; line=$(grep -i "^${mac}=" "${KNOWN_DEVICES_FILE}" 2>/dev/null | head -1) || true
  [[ -z "$line" ]] && { echo ""; return; }
  local val="${line#*=}"
  [[ "$val" == *:* ]] && echo "${val#*:}" || echo ""
}

register_device() {
  local mac="${1^^}" label="$2" tags="${3:-}"
  sed -i "/^${mac}=/Id" "${KNOWN_DEVICES_FILE}" 2>/dev/null || true
  [[ -n "$tags" ]] && echo "${mac}=${label}:${tags}" >> "${KNOWN_DEVICES_FILE}" \
                   || echo "${mac}=${label}"          >> "${KNOWN_DEVICES_FILE}"
  ok "Registered: ${mac} → ${label}${tags:+ [${tags}]}"
}

do_learn() {
  local subnet; subnet=$(detect_subnets | awk '{print $1}')
  banner "Learn Mode"
  warn "Auto-register all currently visible devices? [y/N]"
  read -r ans; [[ "${ans,,}" == "y" ]] || { info "Aborted."; exit 0; }

  while IFS=' ' read -r ip mac vendor; do
    [[ "$ip" =~ ^[0-9] ]] || continue
    mac="${mac^^}"
    [[ "$(lookup_device "$mac")" != "UNKNOWN" ]] && continue
    local hn; hn=$(resolve_hostname "$ip")
    local label="${hn:-${vendor%% *}}-${ip##*.}"
    register_device "$mac" "$label" "auto"
  done < <(
    run_arp_scan "$subnet"
    run_nmap_discovery "$subnet" | while read -r ip; do
      echo "$ip 00:00:00:00:00:00 nmap-discovered"
    done
  )
  ok "Learn complete. Review ${KNOWN_DEVICES_FILE}"
}

do_list_known() {
  banner "Known Devices"
  [[ -s "${KNOWN_DEVICES_FILE}" ]] || { warn "No known devices. Run: $0 add <MAC> <label>"; return; }
  printf "%-20s %-32s %s\n" "MAC" "LABEL" "TAGS"
  printf "%s\n" "─────────────────────────────────────────────────────────"
  while IFS='=' read -r mac rest; do
    local label="${rest%%:*}" tags="${rest#*:}"
    [[ "$tags" == "$label" ]] && tags=""
    printf "%-20s %-32s %s\n" "$mac" "$label" "$tags"
  done < "${KNOWN_DEVICES_FILE}"
}

do_add_device()    { register_device "${1:-}" "${2:-}" "${3:-}"; }
do_remove_device() {
  local mac="${1^^}"
  sed -i "/^${mac}=/Id" "${KNOWN_DEVICES_FILE}" && ok "Removed ${mac}" || warn "Not found."
}

# ─── STALE DEVICE TRACKING ────────────────────────────────────────────────────

update_stale_tracker() {
  local scan_id="$1"
  local -n _seen=$2   # array of MACs seen this scan

  # Mark seen MACs
  for mac in "${_seen[@]}"; do
    sed -i "/^${mac}=/Id" "${STALE_DB}" 2>/dev/null || true
    echo "${mac}=${scan_id}" >> "${STALE_DB}"
  done

  # Check known devices not seen
  while IFS='=' read -r mac _; do
    printf '%s\n' "${_seen[@]}" | grep -qi "^${mac}$" 2>/dev/null && continue
    local last_id; last_id=$(grep -i "^${mac}=" "${STALE_DB}" 2>/dev/null | cut -d= -f2 | head -1)
    [[ -z "${last_id:-}" ]] && continue
    local gap=$(( scan_id - last_id ))
    if [[ $gap -ge ${STALE_DEVICE_SCANS} ]]; then
      local label; label=$(lookup_device "$mac")
      warn "Stale: ${mac} (${label}) not seen for ${gap} scans"
      send_alert "Stale Device" "${mac} (${label}) missing for ${gap} consecutive scans"
    fi
  done < "${KNOWN_DEVICES_FILE}"
}

# ─── ALERT COOLDOWN ───────────────────────────────────────────────────────────

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

# ─── ALERT ENGINE ─────────────────────────────────────────────────────────────

send_alert() {
  local subject="$1" body="$2"
  local key="${subject}:${body}"

  should_alert "$key" || { dim "  (alert suppressed — cooldown active)"; return; }
  record_alert "$key"

  local ts; ts=$(date '+%Y-%m-%d %H:%M:%S')
  echo "[${ts}] ${subject}: ${body}" >> "${ALERT_LOG}"
  db_insert_alert "alert" "${subject}" "${body}"

  # Discord
  if [[ -n "${WEBHOOK_URL}" ]]; then
    local pl
    pl=$(printf '{"username":"NetWatch \ud83d\udee1","embeds":[{"title":"%s","description":"%s","color":15158332,"footer":{"text":"NetWatch v%s \u2022 %s"}}]}' \
         "${subject}" "${body}" "${NETWATCH_VERSION}" "${ts}")
    curl -s -X POST -H "Content-Type: application/json" -d "${pl}" "${WEBHOOK_URL}" &>/dev/null || true
  fi

  # Telegram
  if [[ -n "${TELEGRAM_BOT_TOKEN}" && -n "${TELEGRAM_CHAT_ID}" ]]; then
    local msg; msg=$(printf "\xf0\x9f\x9a\xa8 *%s*\n%s\n\n_%s_" "${subject}" "${body}" "${ts}")
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
}

# ─── HTML REPORT ──────────────────────────────────────────────────────────────

generate_html_report() {
  local out="$1" scan_ts="$2" subnet="$3"
  shift 3
  local rows=("$@")

  local total=0 unknown_count=0 risky_count=0
  for r in "${rows[@]}"; do
    (( total++ )) || true
    IFS='|' read -r _ _ _ _ _ label _ score _ <<< "$r"
    [[ "$label" == "UNKNOWN" ]] && (( unknown_count++ )) || true
    [[ "${score:-0}" -gt 0 ]]   && (( risky_count++   )) || true
  done

  cat > "$out" <<HTMLDOC
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetWatch Report — ${scan_ts}</title>
<style>
:root{--bg:#0f1117;--surf:#1a1d27;--bdr:#2d3148;--txt:#e2e8f0;
      --mut:#64748b;--grn:#22c55e;--yel:#eab308;--red:#ef4444;
      --cyn:#06b6d4;--blu:#3b82f6}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--txt);font:14px/1.6 'Segoe UI',system-ui,sans-serif;padding:2rem}
h1{font-size:1.8rem;color:var(--cyn);margin-bottom:.25rem}
.meta{color:var(--mut);font-size:.85rem;margin-bottom:2rem}
.summary{display:flex;gap:1rem;flex-wrap:wrap;margin-bottom:2rem}
.card{background:var(--surf);border:1px solid var(--bdr);border-radius:8px;
      padding:1rem 1.5rem;min-width:140px;text-align:center}
.card .num{font-size:2rem;font-weight:700;color:var(--cyn)}
.card .lbl{font-size:.75rem;color:var(--mut);text-transform:uppercase;letter-spacing:.05em}
table{width:100%;border-collapse:collapse;margin-bottom:2rem;font-size:.85rem}
th{background:var(--surf);color:var(--mut);text-align:left;padding:.6rem 1rem;
   border-bottom:2px solid var(--bdr);font-weight:600;text-transform:uppercase;
   letter-spacing:.05em}
td{padding:.55rem 1rem;border-bottom:1px solid var(--bdr);vertical-align:top}
tr:hover td{background:rgba(255,255,255,.03)}
.badge{display:inline-block;padding:.15rem .5rem;border-radius:4px;
       font-size:.75rem;font-weight:600;margin:.1rem}
.risky{background:rgba(239,68,68,.15);color:var(--red)}
.normal{background:rgba(34,197,94,.12);color:var(--grn)}
.unknown{background:rgba(100,116,139,.15);color:var(--mut)}
.tag{background:rgba(59,130,246,.15);color:var(--blu);
     display:inline-block;padding:.1rem .4rem;border-radius:3px;
     font-size:.72rem;margin:.1rem}
.hi{color:var(--red);font-weight:700}
.med{color:var(--yel);font-weight:700}
.lo{color:var(--grn)}
.hn{color:var(--cyn);font-size:.8rem}
.os{color:var(--mut);font-size:.78rem;font-style:italic}
footer{color:var(--mut);font-size:.75rem;text-align:center;
       padding-top:2rem;border-top:1px solid var(--bdr)}
</style>
</head>
<body>
<h1>🛡 NetWatch Scan Report</h1>
<p class="meta">Generated: ${scan_ts} &nbsp;|&nbsp; Subnet: ${subnet} &nbsp;|&nbsp; v${NETWATCH_VERSION}</p>
<div class="summary">
  <div class="card"><div class="num">${total}</div><div class="lbl">Devices</div></div>
  <div class="card"><div class="num" style="color:var(--red)">${unknown_count}</div><div class="lbl">Unknown</div></div>
  <div class="card"><div class="num" style="color:var(--yel)">${risky_count}</div><div class="lbl">Risky Hosts</div></div>
</div>
<table>
<thead>
<tr><th>IP</th><th>MAC / Vendor</th><th>Hostname / OS</th><th>Label / Tags</th><th>Score</th><th>Open Ports</th></tr>
</thead>
<tbody>
HTMLDOC

  for r in "${rows[@]}"; do
    IFS='|' read -r ip mac vendor hn os label tags score ports_html <<< "$r"
    local sc="${score:-0}"
    local sc_class="lo"
    [[ $sc -gt 5  ]] && sc_class="med"
    [[ $sc -gt 20 ]] && sc_class="hi"
    local lbl_html="$label"
    [[ "$label" == "UNKNOWN" ]] && lbl_html='<span class="badge risky">UNKNOWN</span>'
    local tags_html=""
    if [[ -n "$tags" ]]; then
      IFS=',' read -ra tarr <<< "$tags"
      for t in "${tarr[@]}"; do tags_html+="<span class='tag'>${t}</span>"; done
    fi
    cat >> "$out" <<ROW
<tr>
<td><strong>${ip}</strong></td>
<td>${mac}<br><span class="os">${vendor}</span></td>
<td><span class="hn">${hn}</span><br><span class="os">${os}</span></td>
<td>${lbl_html}<br>${tags_html}</td>
<td class="${sc_class}">${sc}</td>
<td>${ports_html}</td>
</tr>
ROW
  done

  cat >> "$out" <<HTMLDOC
</tbody></table>
<footer>NetWatch v${NETWATCH_VERSION} — For authorised home network monitoring only.</footer>
</body></html>
HTMLDOC
  ok "HTML report → ${out}"
}

# ─── MAIN SCAN ROUTINE ────────────────────────────────────────────────────────

do_scan() {
  local subnets_raw; subnets_raw=$(detect_subnets)
  local scan_ts; scan_ts=$(date '+%Y-%m-%d %H:%M:%S')
  local scan_ts_file; scan_ts_file=$(date '+%Y%m%d_%H%M%S')
  local snapshot_file="${SNAPSHOT_DIR}/scan_${scan_ts_file}.txt"
  local report_file="${REPORT_DIR}/report_${scan_ts_file}.html"

  banner "NetWatch v${NETWATCH_VERSION} — ${scan_ts}"
  info "Profile : ${SCAN_PROFILE}  (ports ${PROFILE_PORTS[${SCAN_PROFILE}]}, ${PROFILE_TIMING[${SCAN_PROFILE}]})"
  info "Subnets : ${subnets_raw}"
  info "Root    : $( [[ "${USE_NONROOT}" == "true" ]] && echo "No (limited mode)" || echo "Yes (full mode)" )"

  declare -A discovered   # [mac]=ip
  declare -A vendors      # [mac]=vendor
  declare -A hostnames    # [mac]=hostname
  declare -A os_guesses   # [mac]=os_string

  # ── Phase 1: Device Discovery ──────────────────────────────────────────────
  banner "Phase 1 — Device Discovery"

  # Collect mDNS names first (ip→hostname)
  declare -A mdns_map
  if [[ "${ENABLE_MDNS}" == "true" ]]; then
    while IFS=' ' read -r mip mname; do
      [[ -z "$mip" ]] && continue
      mdns_map["$mip"]="$mname"
    done < <(run_mdns_discovery)
  fi

  for subnet in ${subnets_raw}; do
    while IFS=' ' read -r ip mac vendor; do
      [[ "$ip" =~ ^[0-9] ]] || continue
      is_excluded "$ip"  && { dim "  Skip (excluded IP)  ${ip}";  continue; }
      is_excluded "$mac" && { dim "  Skip (excluded MAC) ${mac}"; continue; }
      mac="${mac^^}"
      discovered["$mac"]="$ip"
      vendors["$mac"]="${vendor}"
    done < <(run_arp_scan "$subnet")

    while IFS= read -r ip; do
      is_excluded "$ip" && continue
      local already=false
      for m in "${!discovered[@]}"; do
        [[ "${discovered[$m]}" == "$ip" ]] && { already=true; break; }
      done
      if [[ "$already" == "false" ]]; then
        local fmac="00:00:00:${ip##*.}.nmap"
        fmac="NMAP:${ip}"   # synthetic key
        discovered["$fmac"]="$ip"
        vendors["$fmac"]="(nmap-discovered)"
      fi
    done < <(run_nmap_discovery "$subnet")
  done

  # Resolve hostnames
  for mac in "${!discovered[@]}"; do
    local ip="${discovered[$mac]}"
    local hn="${mdns_map[$ip]:-}"
    [[ -z "$hn" ]] && hn=$(resolve_hostname "$ip")
    hostnames["$mac"]="${hn}"
  done

  # Print table
  printf "\n%-18s %-20s %-24s %-24s %s\n" "IP" "MAC" "VENDOR" "HOSTNAME" "LABEL"
  printf "%s\n" "──────────────────────────────────────────────────────────────────────────────────────────"
  local seen_macs=()
  for mac in "${!discovered[@]}"; do
    local ip="${discovered[$mac]}" vendor="${vendors[$mac]}" hn="${hostnames[$mac]:-}"
    local label; label=$(lookup_device "$mac")
    printf "%-18s %-20s %-24s %-24s %s\n" "$ip" "$mac" "${vendor:0:23}" "${hn:0:23}" "$label"
    echo "${ip} ${mac} ${vendor} ${hn} ${label}" >> "${snapshot_file}"
    seen_macs+=("$mac")
  done

  # ── Phase 2: OS Fingerprinting ────────────────────────────────────────────
  if [[ "${ENABLE_OS_FINGERPRINT}" == "true" ]]; then
    banner "Phase 2 — OS Fingerprinting"
    for mac in "${!discovered[@]}"; do
      local ip="${discovered[$mac]}"
      info "  OS probe → ${ip}"
      local os; os=$(fingerprint_os "$ip")
      os_guesses["$mac"]="${os:-Unknown}"
      printf "  %-18s %s\n" "$ip" "${os_guesses[$mac]}"
    done
  fi

  # ── Phase 3: Port Enumeration ──────────────────────────────────────────────
  banner "Phase 3 — Port Enumeration (${SCAN_PROFILE})"

  local tmp_dir
  if [[ "${ENABLE_PARALLEL}" == "true" ]]; then
    info "Parallel scan (${PARALLEL_JOBS} jobs) …"
    tmp_dir=$(scan_all_hosts_parallel discovered)
  else
    tmp_dir=$(mktemp -d)
    for mac in "${!discovered[@]}"; do
      local ip="${discovered[$mac]}"
      is_excluded "$ip" || is_excluded "$mac" && continue
      scan_ports_host "$ip" > "${tmp_dir}/${mac//:/=}.nmap" 2>/dev/null || true
    done
  fi

  local html_rows=()
  local new_devices=()
  local risky_findings=()
  local total_risk=0

  local scan_id
  scan_id=$(db_insert_scan "${scan_ts}" "${subnets_raw}" "${#discovered[@]}" 0 0)

  for mac in "${!discovered[@]}"; do
    local ip="${discovered[$mac]}"
    local vendor="${vendors[$mac]}"
    local hn="${hostnames[$mac]:-}"
    local os="${os_guesses[$mac]:-}"
    local label; label=$(lookup_device "$mac")
    local tags; tags=$(lookup_tags "$mac")
    local nmap_file="${tmp_dir}/${mac//:/=}.nmap"

    echo -e "\n${BOLD}▶ ${ip}${RESET}  ${DIM}${mac}  ${hn}${RESET}  ${CYAN}${label}${RESET}"
    [[ -n "$os" && "$os" != "Unknown" ]] && echo -e "  ${DIM}OS: ${os}${RESET}"

    local host_risk=0
    local ports_html=""

    local host_id
    host_id=$(db_insert_host "${scan_id}" "${ip}" "${mac}" "${vendor}" \
              "${hn}" "${os}" "${label}" "${tags}" "0" "${scan_ts}")

    if [[ -f "$nmap_file" ]]; then
      # CVE / vulners output
      local vulns
      vulns=$(grep -E "CVE-[0-9]{4}-[0-9]+" "$nmap_file" 2>/dev/null | head -5 || true)
      if [[ -n "$vulns" ]]; then
        echo -e "  ${YELLOW}CVE hints:${RESET}"
        while IFS= read -r vline; do echo -e "    ${DIM}${vline}${RESET}"; done <<< "$vulns"
        echo "VULNS ${ip}: ${vulns}" >> "${snapshot_file}"
      fi

      while IFS= read -r line; do
        # Match lines like: 22/tcp   open  ssh     OpenSSH 8.2p1 ...
        if [[ "$line" =~ ^([0-9]+)/([a-z]+)[[:space:]]+open[[:space:]]+([a-zA-Z_-]+)[[:space:]]*(.*) ]]; then
          local pnum="${BASH_REMATCH[1]}"
          local proto="${BASH_REMATCH[2]}"
          local svc="${BASH_REMATCH[3]}"
          local ver="${BASH_REMATCH[4]}"

          local cls; cls=$(classify_port "${pnum}")
          local risk="${cls%%:*}" desc="${cls##*:}"

          local banner=""
          # Pull banner line if present (next line after port in nmap output)
          banner=$(awk "/^${pnum}\/${proto}/{found=1; next} found && /banner/{print; exit} found && /^[0-9]/{exit}" \
                   "$nmap_file" 2>/dev/null | sed 's/.*banner: //' | head -1 || true)

          local score_delta=1
          [[ "$risk" == "RISKY"  ]] && score_delta=10
          [[ "$risk" == "NORMAL" ]] && score_delta=0
          host_risk=$(( host_risk + score_delta ))

          db_insert_port "${host_id}" "${pnum}" "${proto}" "open" \
                         "${svc}" "${ver}" "${banner}" "${risk}" "${scan_ts}"

          case "$risk" in
            RISKY)
              alert "  ${pnum}/${proto}  ⚠  RISKY   — ${desc}"
              [[ -n "$ver"    ]] && echo -e "    ${DIM}Version: ${ver}${RESET}"
              [[ -n "$banner" ]] && echo -e "    ${DIM}Banner : ${banner}${RESET}"
              risky_findings+=("${ip}:${pnum}/${proto} — ${desc}")
              ports_html+="<span class='badge risky'>${pnum}/${proto}</span> "
              echo "RISKY_PORT ${ip} ${pnum} ${proto} ${desc}" >> "${snapshot_file}"
              ;;
            NORMAL)
              ok "  ${pnum}/${proto}  ✓  Normal  — ${desc}${ver:+  (${ver})}"
              ports_html+="<span class='badge normal'>${pnum}/${proto}</span> "
              ;;
            *)
              info "  ${pnum}/${proto}  ○  Uncategorised — ${svc}${ver:+ ${ver}}"
              ports_html+="<span class='badge unknown'>${pnum}/${proto}</span> "
              ;;
          esac
        fi
      done < "$nmap_file"
    fi

    [[ $host_risk -gt 0 ]] && echo -e "  $( [[ $host_risk -gt 20 ]] && echo "${RED}" || echo "${YELLOW}" )Risk score: ${host_risk}${RESET}"

    # Update host risk score in DB
    db_exec "UPDATE hosts SET risk_score=${host_risk} WHERE id=${host_id};"
    total_risk=$(( total_risk + host_risk ))

    [[ "$label" == "UNKNOWN" ]] && new_devices+=("${ip} [${mac}] ${vendor}")

    html_rows+=("${ip}|${mac}|${vendor}|${hn}|${os}|${label}|${tags}|${host_risk}|${ports_html}")
  done

  rm -rf "${tmp_dir}" 2>/dev/null || true

  # ── Phase 4: Stale Device Check ───────────────────────────────────────────
  banner "Phase 4 — Stale Device Check"
  update_stale_tracker "${scan_id}" seen_macs

  # ── Phase 5: Alerts ───────────────────────────────────────────────────────
  banner "Phase 5 — Alerts"

  if [[ ${#new_devices[@]} -gt 0 ]]; then
    alert "Unknown devices on network!"
    for d in "${new_devices[@]}"; do
      alert "  • ${d}"
      send_alert "Unknown Device" "${d}"
    done
  else
    ok "All devices are in the approved list."
  fi

  if [[ ${#risky_findings[@]} -gt 0 ]]; then
    alert "Risky open ports found!"
    for f in "${risky_findings[@]}"; do
      alert "  • ${f}"
      send_alert "Risky Port Exposed" "${f}"
    done
  else
    ok "No risky open ports detected."
  fi

  echo -e "\n${BOLD}Overall network risk score: $( [[ $total_risk -gt 30 ]] && echo "${RED}" || ( [[ $total_risk -gt 10 ]] && echo "${YELLOW}" || echo "${GREEN}" ) )${total_risk}${RESET}"

  # ── Phase 6: Reports & DB update ─────────────────────────────────────────
  banner "Phase 6 — Reports"
  generate_html_report "${report_file}" "${scan_ts}" "${subnets_raw}" "${html_rows[@]:-}"

  db_exec "UPDATE scans SET new_count=${#new_devices[@]}, risky_count=${#risky_findings[@]} WHERE id=${scan_id};"

  {
    echo "=== SCAN ${scan_ts} ==="
    echo "Subnets  : ${subnets_raw}"
    echo "Profile  : ${SCAN_PROFILE}"
    echo "Devices  : ${#discovered[@]}"
    echo "Unknown  : ${#new_devices[@]}"
    echo "Risky    : ${#risky_findings[@]}"
    echo "RiskScore: ${total_risk}"
    echo ""
  } >> "${SCAN_LOG}"

  ok "Snapshot  → ${snapshot_file}"
  ok "HTML      → ${report_file}"
  ok "DB        → ${DB_FILE}"
  ok "Logs      → ${SCAN_LOG} | ${ALERT_LOG}"
}

# ─── DIFF ─────────────────────────────────────────────────────────────────────

do_diff() {
  local s1="${1:-}" s2="${2:-}"
  if [[ -z "$s1" || -z "$s2" ]]; then
    mapfile -t snaps < <(ls -t "${SNAPSHOT_DIR}"/*.txt 2>/dev/null)
    [[ ${#snaps[@]} -lt 2 ]] && { warn "Need 2+ snapshots. Run a scan first."; exit 1; }
    s2="${snaps[0]}"; s1="${snaps[1]}"
  fi
  banner "Snapshot Diff"
  info "Old: $(basename "$s1")"
  info "New: $(basename "$s2")"
  echo ""
  diff --color=always "$s1" "$s2" || true
}

# ─── REPORT ───────────────────────────────────────────────────────────────────

do_report() {
  banner "Recent Alerts (last 50)"
  tail -50 "${ALERT_LOG}" 2>/dev/null || warn "No alerts yet."
  echo ""
  if command -v sqlite3 &>/dev/null; then
    info "Alert DB (last 20):"
    db_query "SELECT ts, subject, body FROM alerts ORDER BY id DESC LIMIT 20;"
  fi
}

# ─── WATCH ────────────────────────────────────────────────────────────────────

do_watch() {
  local interval="${1:-3600}"
  info "Watch mode — every ${interval}s. Ctrl-C to stop."
  while true; do
    do_scan
    info "Next scan in ${interval}s …"; sleep "${interval}"
  done
}

# ─── CRON ─────────────────────────────────────────────────────────────────────

do_install_cron() {
  local interval="${1:-hourly}" cron_entry
  case "$interval" in
    hourly) cron_entry="0 * * * * sudo ${SCRIPT_PATH} scan" ;;
    daily)  cron_entry="0 6 * * * sudo ${SCRIPT_PATH} scan" ;;
    boot)   cron_entry="@reboot sudo ${SCRIPT_PATH} scan" ;;
    *)      cron_entry="*/${interval} * * * * sudo ${SCRIPT_PATH} scan" ;;
  esac
  ( crontab -l 2>/dev/null | grep -v "${SCRIPT_PATH}"; echo "${cron_entry}" ) | crontab -
  ok "Cron installed: ${cron_entry}"
}

do_remove_cron() {
  crontab -l 2>/dev/null | grep -v "${SCRIPT_PATH}" | crontab -
  ok "Cron job removed."
}

# ─── SYSTEMD ──────────────────────────────────────────────────────────────────

do_install_systemd() {
  local interval="${1:-3600}"
  [[ "${EUID}" -ne 0 ]] && { warn "systemd install requires root."; exit 1; }

  cat > /etc/systemd/system/netwatch.service <<EOF
[Unit]
Description=NetWatch Network Monitor
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${SCRIPT_PATH} scan
User=root

[Install]
WantedBy=multi-user.target
EOF

  cat > /etc/systemd/system/netwatch.timer <<EOF
[Unit]
Description=NetWatch scan timer

[Timer]
OnBootSec=60
OnUnitActiveSec=${interval}s
Persistent=true

[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload
  systemctl enable --now netwatch.timer
  ok "systemd timer enabled (every ${interval}s). Check: systemctl status netwatch.timer"
}

do_remove_systemd() {
  [[ "${EUID}" -ne 0 ]] && { warn "Requires root."; exit 1; }
  systemctl disable --now netwatch.timer 2>/dev/null || true
  rm -f /etc/systemd/system/netwatch.{service,timer}
  systemctl daemon-reload
  ok "systemd units removed."
}

# ─── HELP ─────────────────────────────────────────────────────────────────────

usage() {
  cat <<EOF
${BOLD}NetWatch v${NETWATCH_VERSION} — Home Network Monitor${RESET}

${BOLD}USAGE${RESET}
  $(basename "$0") [--profile quick|standard|deep] <command> [options]

${BOLD}SCAN${RESET}
  scan                         Full scan (discover + ports + OS + reports + alerts)
  watch [seconds]              Continuous scan loop (default: 3600s)

${BOLD}DEVICES${RESET}
  list                         List approved devices
  add <MAC> <label> [tags]     Register device (tags: comma-separated)
  remove <MAC>                 Remove from approved list
  learn                        Auto-register all currently visible devices
  exclude <IP|MAC>             Never scan this target
  unexclude <IP|MAC>           Remove from exclusion list

${BOLD}ANALYSIS${RESET}
  diff [snap1 snap2]           Diff two snapshots (default: last two)
  report                       Show recent alerts
  history                      Show scan history from SQLite
  query "<SQL>"                Raw SQL against netwatch.db

${BOLD}AUTOMATION${RESET}
  cron [hourly|daily|boot|N]   Install cron job
  cron-remove                  Remove cron job
  systemd [seconds]            Install systemd timer (root required)
  systemd-remove               Remove systemd timer

${BOLD}MAINTENANCE${RESET}
  integrity-update             Accept current script checksum as baseline
  help                         Show this message

${BOLD}PROFILES${RESET}
  --profile quick              Ports 1-1024, T4
  --profile standard           Ports 1-10000, T4  (default)
  --profile deep               Ports 1-65535, T3

${BOLD}DATA DIR${RESET}  ${DATA_DIR}/
  known_devices.txt   exclusions.txt   netwatch.db
  scan.log   alerts.log   snapshots/   reports/

${BOLD}EXAMPLES${RESET}
  sudo $(basename "$0") scan
  sudo $(basename "$0") --profile deep scan
  sudo $(basename "$0") add AA:BB:CC:DD:EE:FF "NAS" storage,trusted
  sudo $(basename "$0") learn
  sudo $(basename "$0") exclude 192.168.1.1
  sudo $(basename "$0") watch 1800
  sudo $(basename "$0") cron hourly
  sudo $(basename "$0") systemd 3600
  sudo $(basename "$0") history
  sudo $(basename "$0") query "SELECT ip, risk_score FROM hosts ORDER BY risk_score DESC LIMIT 10"
EOF
}

# ─── ENTRY POINT ──────────────────────────────────────────────────────────────

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
  integrity_check

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
