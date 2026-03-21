#!/usr/bin/env bash
set -euo pipefail

# ──────────────────────────────────────────────────────────────────────────────
# trim.sh — Enforce DATA_MAX_GB cap on ./data/
#
# Checks the current size of ./data/ against DATA_MAX_GB. If over the cap,
# calculates a reduced retention window proportionally and applies it to
# Kustainer. ADX then purges old extents in the background (typically < 5 min).
#
# Usage:
#   ./trim.sh              — check and trim if needed
#   ./trim.sh --check      — report size only, make no changes
#   ./trim.sh --force N    — force retention to N days regardless of size
#
# Cron example (check every hour):
#   0 * * * * /path/to/kql-lab/trim.sh >> /var/log/kql-lab-trim.log 2>&1
# ──────────────────────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ADX_URL="http://localhost:8080"
DB="NetDefaultDB"

# Load .env if present
[[ -f "$SCRIPT_DIR/.env" ]] && set -o allexport && source "$SCRIPT_DIR/.env" && set +o allexport
DATA_RETENTION_DAYS="${DATA_RETENTION_DAYS:-7}"
DATA_MAX_GB="${DATA_MAX_GB:-5}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${GREEN}[ trim]${NC} $*"; }
warn() { echo -e "${YELLOW}[ trim]${NC} $*"; }
info() { echo -e "${CYAN}[ trim]${NC} $*"; }
fail() { echo -e "${RED}[ trim]${NC} $*" >&2; exit 1; }

CHECK_ONLY=false
FORCE_DAYS=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --check) CHECK_ONLY=true ;;
        --force) FORCE_DAYS="$2"; shift ;;
        *) fail "Unknown argument: $1" ;;
    esac
    shift
done

# ── Measure ./data/ ──────────────────────────────────────────────────────────
DATA_DIR="$SCRIPT_DIR/data"
[[ -d "$DATA_DIR" ]] || { info "No data/ directory found — nothing to trim."; exit 0; }

DATA_KB=$(du -sk "$DATA_DIR" | awk '{print $1}')
DATA_GB=$(echo "scale=2; $DATA_KB / 1048576" | bc)

info "Current ./data/ size : ${DATA_GB} GB"
info "Cap (DATA_MAX_GB)     : ${DATA_MAX_GB} GB"
info "Retention (current)   : ${DATA_RETENTION_DAYS} days"

# ── Check-only mode ──────────────────────────────────────────────────────────
if $CHECK_ONLY; then
    if awk "BEGIN{exit !($DATA_GB > $DATA_MAX_GB)}"; then
        warn "OVER CAP by $(echo "scale=2; $DATA_GB - $DATA_MAX_GB" | bc) GB — run ./trim.sh to fix."
        exit 1
    else
        log "Under cap — no action needed."
        exit 0
    fi
fi

# ── Force mode ───────────────────────────────────────────────────────────────
if [[ -n "$FORCE_DAYS" ]]; then
    NEW_DAYS="$FORCE_DAYS"
    warn "Forcing retention to ${NEW_DAYS} days (--force)."
else
    # ── Auto-trim: calculate proportional new retention ───────────────────────
    if ! awk "BEGIN{exit !($DATA_GB > $DATA_MAX_GB)}"; then
        log "Under cap (${DATA_GB} GB / ${DATA_MAX_GB} GB) — no trim needed."
        exit 0
    fi

    # Scale retention proportionally: new = floor(current * max / current_size)
    # Floor to int, minimum 1 day.
    NEW_DAYS=$(python3 -c "
import math
current = float('$DATA_GB')
maximum = float('$DATA_MAX_GB')
days    = int('$DATA_RETENTION_DAYS')
new     = max(1, math.floor(days * (maximum / current)))
print(new)
")
    warn "Over cap: ${DATA_GB} GB > ${DATA_MAX_GB} GB."
    warn "Reducing retention: ${DATA_RETENTION_DAYS} days → ${NEW_DAYS} days."
fi

# ── Apply new retention policy to Kustainer ──────────────────────────────────
command -v curl >/dev/null 2>&1 || fail "curl not found"

# Verify ADX is reachable
curl -sf -X POST "${ADX_URL}/v1/rest/mgmt" \
    -H "Content-Type: application/json" \
    -d '{"db":"NetDefaultDB","csl":".show version"}' \
    -o /dev/null 2>/dev/null \
    || fail "Kustainer not reachable at ${ADX_URL} — is the stack running?"

CACHE_DAYS=$(python3 -c "print(min(int('$NEW_DAYS'), 3))")

python3 - <<PYEOF
import json, urllib.request

BASE = "$ADX_URL"
DB   = "$DB"

def mgmt(csl, label):
    body = json.dumps({"db": DB, "csl": csl}).encode()
    req  = urllib.request.Request(
        f"{BASE}/v1/rest/mgmt",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30):
        pass
    print(f"  ✓  {label}")

mgmt(
    '.alter table WindowsEvents policy retention @\'{"SoftDeletePeriod":"$NEW_DAYS.00:00:00","Recoverability":"Disabled"}\'',
    f"retention policy → $NEW_DAYS days"
)
mgmt(
    ".alter table WindowsEvents policy caching hot = ${CACHE_DAYS}d",
    f"hot cache policy → $CACHE_DAYS days"
)
PYEOF

log "Policies updated. ADX will purge extents older than ${NEW_DAYS} days in the background."
log "Re-run ./trim.sh --check in ~5 minutes to confirm ./data/ is shrinking."

# ── Persist new retention to .env ────────────────────────────────────────────
ENV_FILE="$SCRIPT_DIR/.env"
if [[ -f "$ENV_FILE" ]]; then
    if grep -q "^DATA_RETENTION_DAYS=" "$ENV_FILE"; then
        sed -i "s/^DATA_RETENTION_DAYS=.*/DATA_RETENTION_DAYS=$NEW_DAYS/" "$ENV_FILE"
        log ".env updated: DATA_RETENTION_DAYS=$NEW_DAYS"
    else
        echo "DATA_RETENTION_DAYS=$NEW_DAYS" >> "$ENV_FILE"
        log ".env updated: DATA_RETENTION_DAYS=$NEW_DAYS (appended)"
    fi
else
    warn "No .env file found — new retention ($NEW_DAYS days) was applied to Kustainer"
    warn "but not persisted. Copy .env.example to .env to persist it."
fi
