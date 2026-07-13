#!/usr/bin/env bash
# Continuously sizes net.ipv4.tcp_mem to whatever memory is currently spare,
# so TCP buffers expand when gsrnd is idle and get squeezed toward the
# tcp_rmem/tcp_wmem forced minimums as gsrnd's (intentionally unrestricted)
# heap grows. gsrnd's own memory is never capped; this only bounds TCP.

OS_RESERVE_KB=$((512 * 1024))     # protects the OS, never given to TCP or gsrnd
INTERVAL=3

while true; do
    MEM_AVAIL_KB=$(awk '/MemAvailable/{print $2}' /proc/meminfo)
    BUDGET_KB=$((MEM_AVAIL_KB - OS_RESERVE_KB))
    [[ $BUDGET_KB -lt 0 ]] && BUDGET_KB=0   # sysctl can't take negative values

    LOW=$((BUDGET_KB * 90 / 100 / 4))
    MID=$((BUDGET_KB * 95 / 100 / 4))
    HIGH=$((BUDGET_KB * 100 / 100 / 4))
    echo "${LOW} ${MID} ${HIGH}" > /proc/sys/net/ipv4/tcp_mem

    sleep "$INTERVAL"
done
