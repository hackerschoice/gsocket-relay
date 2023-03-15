
#! /bin/bash

MEM_KB=$(grep MemTotal /proc/meminfo  | awk '{print $2;}')
MEM_P80=$((MEM_KB * 80 / 100 / 4 ))

grep . /proc/sys/net/ipv4/tcp*mem

sysctl net.ipv4.tcp_syncookies=0
echo 1048576 >/proc/sys/net/core/somaxconn
echo 1048576 >/proc/sys/net/ipv4/tcp_max_syn_backlog

echo 5 >/proc/sys/net/ipv4/tcp_fin_timeout
echo 2 >/proc/sys/net/ipv4/tcp_tw_reuse
echo 1 >/proc/sys/net/ipv4/tcp_no_metrics_save

# Decrease orphans - Ophaned TCP connections should be killed fast.
echo 1024 >/proc/sys/net/ipv4/tcp_max_orphans

# Set this to 80% of physical memory
echo "${MEM_P80} ${MEM_P80} 262144" >/proc/sys/net/ipv4/tcp_mem

# 4k per socket min.
echo 4096  32768 131072 >/proc/sys/net/ipv4/tcp_rmem
echo 4096  32768 131072 >/proc/sys/net/ipv4/tcp_wmem


