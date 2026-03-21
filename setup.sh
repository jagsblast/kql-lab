#!/usr/bin/env bash
set -euo pipefail

# ──────────────────────────────────────────────────────────────────────────────
# setup.sh — Idempotent setup for Windows Event Log → Kustainer pipeline
#
# What it does:
#   1. Migrates a standalone 'adx' container to docker-compose management
#   2. Starts ADX + Logstash via docker compose
#   3. Waits for Kustainer to be healthy
#   4. Creates database, table, JSON mapping, and streaming ingest policy
#   5. Sends a test event to verify end-to-end ingest works
#
# Re-run safely at any time — all schema commands are idempotent.
# ──────────────────────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ADX_URL="http://localhost:8080"
DB="NetDefaultDB"
MAX_WAIT=180

# ── Storage config (override via .env or environment) ─────────────────────────
# Load .env if present
[[ -f "$SCRIPT_DIR/.env" ]] && set -o allexport && source "$SCRIPT_DIR/.env" && set +o allexport
DATA_RETENTION_DAYS="${DATA_RETENTION_DAYS:-7}"    # keep N days of events
DATA_MAX_GB="${DATA_MAX_GB:-5}"                    # cap ./data/ at this many GB
DATA_WARN_GB="${DATA_WARN_GB:-2}"                  # warn if free space < N GB
DATA_MIN_FREE_GB="${DATA_MIN_FREE_GB:-1}"           # abort if free space < N GB

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${GREEN}[setup]${NC} $*"; }
warn() { echo -e "${YELLOW}[ warn]${NC} $*"; }
info() { echo -e "${CYAN}[ info]${NC} $*"; }
fail() { echo -e "${RED}[error]${NC} $*" >&2; exit 1; }

echo ""
echo -e "${CYAN}══════════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  Windows Event Logs → Kustainer — Setup${NC}"
echo -e "${CYAN}══════════════════════════════════════════════════════════════════${NC}"
echo ""

# ── 0. Pre-flight ─────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    fail "This script must be run as root.\n  Re-run with: sudo ./setup.sh"
fi

if ! command -v docker >/dev/null 2>&1; then
    fail "docker not found. Install it: https://docs.docker.com/engine/install/"
fi

# Check Docker daemon connectivity — catches 'not in docker group' early
if ! docker info >/dev/null 2>&1; then
    if [[ -S /var/run/docker.sock ]]; then
        fail "Permission denied connecting to Docker.\n" \
             "  Your user is not in the 'docker' group. Fix with:\n" \
             "    sudo usermod -aG docker \$USER && newgrp docker\n" \
             "  Or re-run this script with sudo."
    else
        fail "Cannot connect to the Docker daemon. Is Docker running?\n" \
             "  Try: sudo systemctl start docker"
    fi
fi

if ! docker compose version >/dev/null 2>&1; then
    fail "'docker compose' plugin not found (requires Docker 20.10+ with Compose V2).\n" \
         "  Install: sudo apt-get install docker-compose-plugin  # Debian/Ubuntu\n" \
         "          or see https://docs.docker.com/compose/install/"
fi

command -v python3 >/dev/null 2>&1 || fail "python3 not found. Install: sudo apt-get install python3"
command -v curl    >/dev/null 2>&1 || fail "curl not found. Install: sudo apt-get install curl"

# AVX2 check — libKusto.NativeInfra.so is compiled with AVX2 instructions.
# Without AVX2 the process is killed instantly (SIGILL/exit 137) regardless of
# RAM or Docker config. This is a VM CPU feature passthrough issue.
if ! grep -qw 'avx2' /proc/cpuinfo; then
    fail "AVX2 CPU instruction set not available — Kustainer requires AVX2.\n" \
         "  Your VM is not exposing host CPU features. Fix in your hypervisor:\n" \
         "    VMware   : VM Settings → Processors → 'Expose hardware-assisted virtualisation'\n" \
         "    VirtualBox: System → Processor → Paravirtualisation: KVM + enable Nested VT-x\n" \
         "    KVM/QEMU : Set CPU model to 'host' (-cpu host)\n" \
         "    Proxmox  : VM → Hardware → Processor → CPU type: host\n" \
         "  Then verify with: grep avx2 /proc/cpuinfo | head -1"
fi
info "AVX2: present — OK."

# RAM check — Kustainer (ADX) is memory-hungry; OOM kill = exit 137 crash loop
TOTAL_RAM_KB=$(awk '/^MemTotal:/{print $2}' /proc/meminfo)
TOTAL_RAM_GB=$(awk "BEGIN{printf \"%.1f\", $TOTAL_RAM_KB/1048576}")
if awk "BEGIN{exit !($TOTAL_RAM_GB < 4)}"; then
    fail "Only ${TOTAL_RAM_GB} GB RAM detected — Kustainer requires at least 4 GB.\n" \
         "  The container will OOM-crash (exit 137) on this host.\n" \
         "  Use a machine with 4 GB+ RAM (6 GB+ recommended)."
elif awk "BEGIN{exit !($TOTAL_RAM_GB < 6)}"; then
    warn "RAM: ${TOTAL_RAM_GB} GB — Kustainer may be slow or unstable below 6 GB."
else
    info "RAM: ${TOTAL_RAM_GB} GB — OK."
fi

# vm.max_map_count — Kustainer uses mmap-heavy storage (same as Elasticsearch).
# Without this the kernel SIGKILL's the process at startup (exit 137), regardless
# of available RAM. Minimum is 262144; we set 524288 for headroom.
MIN_MAP_COUNT=262144
CUR_MAP_COUNT=$(cat /proc/sys/vm/max_map_count 2>/dev/null || echo 0)
if (( CUR_MAP_COUNT < MIN_MAP_COUNT )); then
    warn "vm.max_map_count is ${CUR_MAP_COUNT} (need >=${MIN_MAP_COUNT}) — fixing now ..."
    sysctl -w vm.max_map_count=524288 >/dev/null
    # Make it survive reboots
    grep -qxF 'vm.max_map_count=524288' /etc/sysctl.conf 2>/dev/null || \
        echo 'vm.max_map_count=524288' >> /etc/sysctl.conf
    info "vm.max_map_count set to 524288 (persisted in /etc/sysctl.conf)."
else
    info "vm.max_map_count: ${CUR_MAP_COUNT} — OK."
fi

# Disk space check — Kustainer writes aggressively; a full disk bricks the host
FREE_KB=$(df -k "$SCRIPT_DIR" | awk 'NR==2{print $4}')
FREE_GB=$(awk "BEGIN{printf \"%.1f\", $FREE_KB/1048576}")
if awk "BEGIN{exit !($FREE_GB < $DATA_MIN_FREE_GB)}"; then
    fail "Only ${FREE_GB} GB free — need at least ${DATA_MIN_FREE_GB} GB. Free space or reduce DATA_RETENTION_DAYS in .env."
elif awk "BEGIN{exit !($FREE_GB < $DATA_WARN_GB)}"; then
    warn "Low disk space: ${FREE_GB} GB free (threshold: ${DATA_WARN_GB} GB). Monitor closely."
else
    info "Disk space OK: ${FREE_GB} GB free."
fi

# Data directory size check — warn if ./data/ already exceeds DATA_MAX_GB
if [[ -d "$SCRIPT_DIR/data" ]]; then
    DATA_KB=$(du -sk "$SCRIPT_DIR/data" | awk '{print $1}')
    DATA_GB=$(awk "BEGIN{printf \"%.1f\", $DATA_KB/1048576}")
    if awk "BEGIN{exit !($DATA_GB > $DATA_MAX_GB)}"; then
        warn "./data/ is ${DATA_GB} GB — over the ${DATA_MAX_GB} GB cap."
        warn "Run ./trim.sh to reduce retention and reclaim space."
    else
        info "Data directory: ${DATA_GB} GB / ${DATA_MAX_GB} GB cap."
    fi
fi
info "Retention policy: ${DATA_RETENTION_DAYS} days (set DATA_RETENTION_DAYS in .env to change)."

cd "$SCRIPT_DIR"

# ── 1. Migrate standalone adx container to docker-compose ────────────────────
COMPOSE_LABEL=$(docker inspect adx --format '{{index .Config.Labels "com.docker.compose.project"}}' 2>/dev/null || true)
RUNNING=$(docker ps -q --filter name=^/adx$ 2>/dev/null || true)

if [[ -n "$RUNNING" && -z "$COMPOSE_LABEL" ]]; then
    warn "Found standalone 'adx' container — migrating to docker-compose management."
    warn "Your data in ./data/ is preserved."
    docker stop adx >/dev/null
    docker rm   adx >/dev/null
    log "Standalone container removed."
fi

# ── 2. Ensure required directories exist ─────────────────────────────────────
log "Ensuring directory layout ..."
mkdir -p data logstash/pipeline logstash/config winlogbeat schemas

# ── 3. Start the stack ────────────────────────────────────────────────────────
log "Starting ADX + Logstash via docker compose ..."
docker compose up -d
echo ""

# ── 4. Wait for Kustainer ────────────────────────────────────────────────────
log "Waiting for Kustainer to become healthy (max ${MAX_WAIT}s) ..."
ELAPSED=0
until curl -sf -X POST "${ADX_URL}/v1/rest/mgmt" \
        -H "Content-Type: application/json" \
        -d '{"db":"NetDefaultDB","csl":".show version"}' \
        -o /dev/null 2>/dev/null; do
    if (( ELAPSED >= MAX_WAIT )); then
        fail "Kustainer did not become ready within ${MAX_WAIT}s. Check: docker logs adx"
    fi
    sleep 5
    ELAPSED=$(( ELAPSED + 5 ))
    echo -n "."
done
echo ""
log "Kustainer is ready."
echo ""

# ── 5. Initialise schema (idempotent Python block) ────────────────────────────
log "Initialising schema in Kustainer ..."

python3 - <<'PYEOF'
import sys, json

try:
    import urllib.request, urllib.error
except ImportError:
    print("ERROR: urllib not available", file=sys.stderr)
    sys.exit(1)

BASE = "http://localhost:8080"
DB   = "NetDefaultDB"

def mgmt(db, csl, label=""):
    body = json.dumps({"db": db, "csl": csl}).encode()
    req  = urllib.request.Request(
        f"{BASE}/v1/rest/mgmt",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            result = json.loads(resp.read())
            if label:
                print(f"  ✓  {label}")
            return result
    except urllib.error.HTTPError as e:
        msg = e.read().decode(errors="replace")
        if any(x in msg.lower() for x in ["already exists", "entityalreadyexists", "alreadyexists"]):
            if label:
                print(f"  ✓  {label} (already exists)")
            return {}
        print(f"  ✗  {label}: HTTP {e.code} — {msg[:300]}", file=sys.stderr)
        raise

# 1. Table (create-merge = idempotent; adds columns if schema changes)
mgmt(DB,
     ".create-merge table WindowsEvents "
     "( TimeCreated:datetime, Computer:string, EventId:int, Level:string,"
     "  Channel:string, Provider:string, Message:string,"
     "  EventData:dynamic, RawEvent:dynamic )",
     "table     WindowsEvents")

# 2. JSON ingestion mapping (WinLogBeat 8.x field paths)
# NOTE: $["@timestamp"] uses double-quote bracket notation because Kustainer
# strips the quotes from single-quote bracket notation, e.g. $['x'] → $[x].
# json.dumps encodes " as \" in the JSON text; the KQL verbatim string
# @'...' passes backslashes through as literals, so JSON stays valid.
mapping = json.dumps([
    {"column": "TimeCreated", "path": '$["@timestamp"]',     "datatype": "datetime"},
    {"column": "Computer",    "path": "$.winlog.computer_name","datatype": "string"  },
    {"column": "EventId",     "path": "$.winlog.event_id",     "datatype": "int"     },
    {"column": "Level",       "path": "$.log.level",           "datatype": "string"  },
    {"column": "Channel",     "path": "$.winlog.channel",      "datatype": "string"  },
    {"column": "Provider",    "path": "$.winlog.provider_name","datatype": "string"  },
    {"column": "Message",     "path": "$.message",             "datatype": "string"  },
    {"column": "EventData",   "path": "$.winlog.event_data",   "datatype": "dynamic" },
    {"column": "RawEvent",    "path": "$",                     "datatype": "dynamic" },
])
# KQL verbatim @'...' string: only '' escapes single quote; \ passes as-is
kql_mapping = mapping.replace("'", "''")
csl = (
    f'.create-or-alter table WindowsEvents '
    f'ingestion json mapping "winlogbeat_mapping" @\'{kql_mapping}\''
)
mgmt(DB, csl, "mapping   winlogbeat_mapping")

# 3. Streaming ingestion policy (required for /v1/rest/ingest endpoint)
mgmt(DB,
     ".alter table WindowsEvents policy streamingingestion enable",
     "policy    streaming ingestion → WindowsEvents")

import os
retention_days = int(os.environ.get("DATA_RETENTION_DAYS", "7"))
cache_days     = min(retention_days, 3)   # hot cache <= retention, cap at 3d

# 4. Retention policy — ADX automatically drops extents older than this.
#    Recoverability disabled: no soft-delete tombstones wasting extra space.
mgmt(DB,
     f'.alter table WindowsEvents policy retention @\'{{"SoftDeletePeriod":"{retention_days}.00:00:00","Recoverability":"Disabled"}}\'',
     f"policy    retention → {retention_days} days")

# 5. Caching policy — limits how much data ADX keeps in hot (disk) cache.
#    Data older than this is still queryable but read from cold storage.
mgmt(DB,
     f".alter table WindowsEvents policy caching hot = {cache_days}d",
     f"policy    hot cache → {cache_days} days")

print("")
print("  Schema initialisation complete.")
PYEOF

echo ""

# ── 6. Test ingest via relay ─────────────────────────────────────────────────
log "Testing ingest via relay container ..."
# Give relay a moment to start and connect to ADX
sleep 3
TEST_EVENT='{"@timestamp":"2026-03-20T00:00:00.000Z","winlog":{"computer_name":"setup-test","event_id":1,"channel":"SetupTest","provider_name":"KQL-Lab-Setup","event_data":{"note":"setup verification"}},"log":{"level":"information"},"message":"Setup verification event — safe to delete"}'

HTTP_CODE=$(curl -s -o /tmp/relay_test.json -w "%{http_code}" \
    -X POST "http://localhost:9001/ingest" \
    -H "Content-Type: application/json" \
    --data-binary "$TEST_EVENT")

if [[ "$HTTP_CODE" == "200" || "$HTTP_CODE" == "204" ]]; then
    log "Relay ingest test PASSED (HTTP ${HTTP_CODE})."
else
    warn "Relay returned HTTP ${HTTP_CODE}. Response: $(cat /tmp/relay_test.json 2>/dev/null || echo '(empty)')"
    warn "Check: docker logs relay"
fi

echo ""

# ── 7. Package winlogbeat folder for copy to DC ─────────────────────────────
log "Packaging winlogbeat-dc.zip ..."
cd "$SCRIPT_DIR"
zip -q -r winlogbeat-dc.zip winlogbeat/
log "winlogbeat-dc.zip ready — copy this to your Windows DC."
echo ""

# ── 8. Provision DC via Ansible (optional — skipped if not configured) ───────
INVENTORY="$SCRIPT_DIR/ansible/inventory.ini"
PLAYBOOK="$SCRIPT_DIR/ansible/setup-dc.yml"

_ansible_ready=false
if command -v ansible-playbook >/dev/null 2>&1 && \
   command -v python3 >/dev/null 2>&1 && \
   python3 -c "import winrm" >/dev/null 2>&1; then
    _ansible_ready=true
fi

if [[ "$_ansible_ready" == "true" ]] && grep -qE '^\s*[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$INVENTORY" 2>/dev/null; then
    echo -e "${CYAN}──────────────────────────────────────────────────────────────────${NC}"
    info "Ansible + WinRM found and ansible/inventory.ini has a DC IP configured."
    info "This will: promote the DC, create lab users/SPNs, and install WinLogBeat."
    echo ""
    read -r -p "  Run Ansible DC provisioning now? [y/N] " _ans
    echo ""
    if [[ "${_ans,,}" == "y" ]]; then
        log "Running: ansible-playbook -i ansible/inventory.ini ansible/setup-dc.yml"
        echo ""
        ansible-playbook -i "$INVENTORY" "$PLAYBOOK" || \
            warn "Ansible run finished with errors — check output above."
    else
        info "Skipped. Run manually later:"
        info "  ansible-playbook -i ansible/inventory.ini ansible/setup-dc.yml"
    fi
    echo ""
else
    if [[ "$_ansible_ready" == "false" ]]; then
        info "Ansible/pywinrm not installed — skipping DC provisioning."
        info "To provision later:  pip3 install ansible pywinrm"
        info "                     ansible-galaxy collection install -r ansible/requirements.yml"
        info "                     ansible-playbook -i ansible/inventory.ini ansible/setup-dc.yml"
    else
        info "No DC IP set in ansible/inventory.ini — skipping DC provisioning."
        info "Edit ansible/inventory.ini with your Windows Server IP and re-run, or run:"
        info "  ansible-playbook -i ansible/inventory.ini ansible/setup-dc.yml"
    fi
    echo ""
fi

# ── 9. Summary ────────────────────────────────────────────────────────────────
HOST_IP=$(hostname -I | awk '{print $2}')   # prefer the LAN IP (second entry)
[[ -z "$HOST_IP" ]] && HOST_IP=$(hostname -I | awk '{print $1}')

echo -e "${GREEN}╔══════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║              Setup Complete                                      ║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║${NC}  Kustainer REST API   http://localhost:8080                      ${GREEN}║${NC}"
echo -e "${GREEN}║${NC}  Logstash Beats port  ${HOST_IP}:5044  (WinLogBeat target)        ${GREEN}║${NC}"
echo -e "${GREEN}║${NC}  Database             NetDefaultDB                               ${GREEN}║${NC}"
echo -e "${GREEN}║${NC}  Table                WindowsEvents                             ${GREEN}║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║${NC}  Windows DC steps (run as Administrator):                        ${GREEN}║${NC}"
echo -e "${GREEN}║${NC}   1.  Copy winlogbeat-dc.zip to the DC and extract it            ${GREEN}║${NC}"
echo -e "${GREEN}║${NC}   2.  Run:  .\\install-winlogbeat.ps1 -LogstashHost ${HOST_IP}   ${GREEN}║${NC}"
echo -e "${GREEN}║${NC}   3.  Wait ~30 s, then in Kustainer:                            ${GREEN}║${NC}"
echo -e "${GREEN}║${NC}         WindowsEvents | take 10                                 ${GREEN}║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║${NC}  Useful commands:                                               ${GREEN}║${NC}"
echo -e "${GREEN}║${NC}   docker logs -f logstash   — watch Logstash output             ${GREEN}║${NC}"
echo -e "${GREEN}║${NC}   docker logs -f adx        — watch Kustainer output            ${GREEN}║${NC}"
echo -e "${GREEN}║${NC}   ./teardown.sh             — stop the stack                    ${GREEN}║${NC}"
echo -e "${GREEN}║${NC}   ./teardown.sh --purge     — stop + wipe all ingested data     ${GREEN}║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════╝${NC}"
echo ""
