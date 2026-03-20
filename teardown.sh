#!/usr/bin/env bash
set -euo pipefail

# ──────────────────────────────────────────────────────────────────────────────
# teardown.sh — Stop the Windows Event Log → Kustainer pipeline
#
#   ./teardown.sh           stop containers, keep all data
#   ./teardown.sh --purge   stop containers AND delete ./data/ (irreversible)
# ──────────────────────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

PURGE=false
for arg in "$@"; do
    [[ "$arg" == "--purge" ]] && PURGE=true
done

echo "Stopping docker compose services ..."
docker compose down

if $PURGE; then
    echo ""
    echo "WARNING: --purge will permanently delete all Kustainer data in ./data/"
    read -rp "Are you sure? [y/N] " confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        echo "Purging ./data/ ..."
        rm -rf ./data/*
        echo "Data purged."
    else
        echo "Purge cancelled — data is intact."
    fi
fi

echo "Teardown complete."
