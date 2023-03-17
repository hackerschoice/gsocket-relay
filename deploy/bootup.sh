
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
# Each can eat up to 64kB
echo 128 >/proc/sys/net/ipv4/tcp_max_orphans

# Set this to 80% of physical memory
# low, pressure, high (man 7 tcp)
echo "${MEM_P80} ${MEM_P80} 262144" >/proc/sys/net/ipv4/tcp_mem

# 4k per socket min.
# min, default, max
echo 4096  4096   131072 >/proc/sys/net/ipv4/tcp_rmem
# wmem defines throughput. On a 200ms link between A and B the max speed thus is:
# 1000 / (200 * 2) * wmem_default
echo 4096  16384  131072 >/proc/sys/net/ipv4/tcp_wmem

### Check journal file
ps -A --sort -rss -o comm,pmem,rss | head -n 5
sed 's/#SystemMaxFileSize.*/SystemMaxFileSize=50M/' -i /etc/systemd/journald.conf
sed 's/#SystemMaxUse.*/SystemMaxUse=10M/' -i /etc/systemd/journald.conf
systemctl restart systemd-journald
