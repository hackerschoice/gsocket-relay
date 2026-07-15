#!/usr/bin/env bash
# Continuously sizes net.ipv4.tcp_mem to whatever memory is currently spare,
# so TCP buffers expand when gsrnd is idle and get squeezed toward the
# tcp_rmem/tcp_wmem forced minimums as gsrnd's (intentionally unrestricted)
# heap grows. gsrnd's own memory is never capped; this only bounds TCP.
#
# tcp_rmem/tcp_wmem's per-socket ceiling (3rd field) is sized off of how much
# TCP memory is *actually* in use (sockstat's "mem", same page units as
# tcp_mem) relative to the HIGH pressure threshold above - not connection
# count. Most connections are idle and never grow anywhere near the ceiling
# regardless of how high it's set, so gating on connection count needlessly
# punishes idle-heavy boxes. Gating on real usage means: usage near zero ->
# ceiling near the max, so the few actively-transferring connections get full
# speed; usage climbing toward the pressure threshold -> ceiling shrinks
# toward the floor, throttling further growth only for whoever's still
# growing at that point.

OS_RESERVE_KB=$((512 * 1024))     # protects the OS, never given to TCP or gsrnd
BUF_FLOOR_KB=32                   # per-socket rmem/wmem ceiling, min (near pressure)
BUF_CEIL_KB=512                   # per-socket rmem/wmem ceiling, max (usage ~0)
INTERVAL=3

while true; do
    MEM_AVAIL_KB=$(awk '/MemAvailable/{print $2}' /proc/meminfo)
    BUDGET_KB=$((MEM_AVAIL_KB - OS_RESERVE_KB))
    [[ $BUDGET_KB -lt 0 ]] && BUDGET_KB=0   # sysctl can't take negative values

    LOW=$((BUDGET_KB * 90 / 100 / 4))
    MID=$((BUDGET_KB * 95 / 100 / 4))
    HIGH=$((BUDGET_KB * 100 / 100 / 4))
    echo "${LOW} ${MID} ${HIGH}" > /proc/sys/net/ipv4/tcp_mem

    MEM_USED_PAGES=$(awk '/^TCP:/{for(i=1;i<=NF;i++) if ($i=="mem"){print $(i+1); exit}}' /proc/net/sockstat)
    [[ -z $MEM_USED_PAGES ]] && MEM_USED_PAGES=0
    [[ $HIGH -lt 1 ]] && HIGH=1   # avoid div-by-zero if budget is exhausted

    # usage_ratio scaled 0-1000 for integer-arithmetic precision, then applied
    # to the floor..ceiling range.
    USAGE_RATIO_1000=$((MEM_USED_PAGES * 1000 / HIGH))
    [[ $USAGE_RATIO_1000 -gt 1000 ]] && USAGE_RATIO_1000=1000

    BUF_MAX_KB=$((BUF_CEIL_KB - (BUF_CEIL_KB - BUF_FLOOR_KB) * USAGE_RATIO_1000 / 1000))
    [[ $BUF_MAX_KB -lt $BUF_FLOOR_KB ]] && BUF_MAX_KB=$BUF_FLOOR_KB
    [[ $BUF_MAX_KB -gt $BUF_CEIL_KB ]] && BUF_MAX_KB=$BUF_CEIL_KB
    BUF_MAX_B=$((BUF_MAX_KB * 1024))

    echo "4096 16384 ${BUF_MAX_B}" > /proc/sys/net/ipv4/tcp_rmem
    echo "4096 65536 ${BUF_MAX_B}" > /proc/sys/net/ipv4/tcp_wmem

    sleep "$INTERVAL"
done
