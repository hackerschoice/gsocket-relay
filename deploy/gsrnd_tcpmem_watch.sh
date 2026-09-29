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

OS_RESERVE_KB=$((512 * 1024))     # budgeting margin, not a reserved allocation
TCP_BUDGET_FLOOR_KB=$((16 * 1024)) # keep TCP usable when available memory is low
BUF_FLOOR_KB=32                   # per-socket rmem/wmem ceiling, min (near pressure)
BUF_CEIL_KB=512                   # per-socket rmem/wmem ceiling, max (usage ~0)
INTERVAL=3

calculate_limits() {
    local mem_avail_kb=$1 mem_used_pages=$2 page_size=$3
    local budget_kb usage_ratio_1000 buf_max_kb

    [[ $mem_avail_kb =~ ^[0-9]+$ && $mem_used_pages =~ ^[0-9]+$ &&
       $page_size =~ ^[0-9]+$ ]] || return 1
    (( page_size >= 1024 && page_size <= 65536 )) || return 1

    budget_kb=$((mem_avail_kb - OS_RESERVE_KB))
    (( budget_kb >= TCP_BUDGET_FLOOR_KB )) || budget_kb=$TCP_BUDGET_FLOOR_KB
    LOW=$((budget_kb * 1024 * 90 / 100 / page_size))
    MID=$((budget_kb * 1024 * 95 / 100 / page_size))
    HIGH=$((budget_kb * 1024 / page_size))

    # usage_ratio scaled 0-1000 for integer-arithmetic precision, then applied
    # to the floor..ceiling range.
    usage_ratio_1000=$((mem_used_pages * 1000 / HIGH))
    (( usage_ratio_1000 <= 1000 )) || usage_ratio_1000=1000

    buf_max_kb=$((BUF_CEIL_KB - (BUF_CEIL_KB - BUF_FLOOR_KB) * usage_ratio_1000 / 1000))
    BUF_MAX_B=$((buf_max_kb * 1024))
    RMEM_DEFAULT_B=16384
    WMEM_DEFAULT_B=65536
    (( WMEM_DEFAULT_B <= BUF_MAX_B )) || WMEM_DEFAULT_B=$BUF_MAX_B
    return 0
}

main() {
    local page_size mem_avail_kb mem_used_pages
    page_size=$(getconf PAGESIZE) || return 1
    while true; do
        mem_avail_kb=$(awk '/^MemAvailable:/{print $2}' /proc/meminfo)
        mem_used_pages=$(awk '/^TCP:/{for(i=1;i<=NF;i++) if ($i=="mem"){print $(i+1); exit}}' /proc/net/sockstat)
        if calculate_limits "$mem_avail_kb" "$mem_used_pages" "$page_size"; then
            echo "${LOW} ${MID} ${HIGH}" > /proc/sys/net/ipv4/tcp_mem
            echo "4096 ${RMEM_DEFAULT_B} ${BUF_MAX_B}" > /proc/sys/net/ipv4/tcp_rmem
            echo "4096 ${WMEM_DEFAULT_B} ${BUF_MAX_B}" > /proc/sys/net/ipv4/tcp_wmem
        else
            echo "Cannot calculate TCP memory limits from current memory counters" >&2
        fi

        sleep "$INTERVAL"
    done
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    main
fi
