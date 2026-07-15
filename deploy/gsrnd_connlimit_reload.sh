#!/usr/bin/env bash
# Reloads the live iptables ruleset unchanged (iptables-save | iptables-restore)
# to reset nf_conncount's -m connlimit tracking state before it grows into an
# unbounded memory leak (nf_conncount's own GC frees at most 8 nodes per tree
# traversal - CONNCOUNT_GC_MAX_NODES - which falls behind under this server's
# connection-attempt volume). Reloading does not change which traffic is
# allowed or blocked.
#
# Checks periodically instead of reloading on a blind timer. The normal
# trigger is vmap_area slab usage crossing VMAP_THRESHOLD_BYTES - nothing
# else forces a reload. MAX_AGE is only a rarely-hit backstop (e.g. in case
# vmap_area growth stalls somewhere below the threshold for an unrelated
# reason) - it is not meant to fire in routine operation. A quiet box with
# spare memory should go well past MAX_AGE between reloads on the threshold
# trigger alone; fewer reloads also means fewer connlimit reset windows for
# a patient attacker to time bursts around.

CHECK_INTERVAL=300                             # how often to check (5 min)
MAX_AGE=$((48 * 60 * 60))                      # rarely-hit backstop only (2 days)
VMAP_THRESHOLD_BYTES=$((1024 * 1024 * 1024))   # normal trigger: reload once vmap_area exceeds this (1GB)
SNAPSHOT=/run/gsrnd-connlimit-reload.rules

last_reload=$(date +%s)

reload() {
    local reason=$1
    if iptables-save > "${SNAPSHOT}.tmp" 2>/dev/null && grep -q '^COMMIT' "${SNAPSHOT}.tmp"; then
        mv "${SNAPSHOT}.tmp" "$SNAPSHOT"
        if iptables-restore < "$SNAPSHOT"; then
            logger -t gsrnd-connlimit-reload "reloaded ruleset ($(wc -l < "$SNAPSHOT") lines) - ${reason}"
            last_reload=$(date +%s)
        else
            logger -t gsrnd-connlimit-reload "ERROR: iptables-restore failed, ruleset left as-is"
        fi
    else
        logger -t gsrnd-connlimit-reload "ERROR: iptables-save produced invalid output, skipping this cycle"
    fi
}

while true; do
    sleep "$CHECK_INTERVAL"

    vmap_bytes=$(awk '$1=="vmap_area"{printf "%.0f", $3*$4}' /proc/slabinfo)
    age=$(( $(date +%s) - last_reload ))

    if [[ -n "$vmap_bytes" && "$vmap_bytes" -ge "$VMAP_THRESHOLD_BYTES" ]]; then
        reload "vmap_area at ${vmap_bytes} bytes >= ${VMAP_THRESHOLD_BYTES}"
    elif [[ "$age" -ge "$MAX_AGE" ]]; then
        reload "max age ${age}s reached"
    fi
done
