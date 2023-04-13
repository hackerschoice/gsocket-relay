
#! /bin/bash

tc_set()
{
	local dev
	local rate
	dev="$1"
	rate="$2"


	# Installs a class based queue
	tc qdisc add dev "${dev}" root handle 1: cbq avpkt 1000 bandwidth 1Gbit 

	# Create a shaped class
	tc class add dev "${dev}" parent 1: classid 1:1 cbq rate "${rate:-1Gbit}" \
		  allot 1500 prio 5 bounded isolated

	# Send all traffic through the shaped class
	tc filter add dev "${dev}" parent 1: matchall flowid 1:1
}

# TC
DEV_GW=$(ip route show | grep default | head -n1 | awk '{print $5;}')

if [[ -n $DEV_GW ]]; then
	tc qdisc del dev "${DEV_GW}" root 2>/dev/null
	tc_set "${DEV_GW}" 100Mbit
fi

MEM_KB=$(grep MemTotal /proc/meminfo  | awk '{print $2;}')
MEM_P80=$((MEM_KB * 80 / 100 / 4 ))

grep . /proc/sys/net/ipv4/tcp*mem

echo 1048576 >/proc/sys/net/core/somaxconn
echo 1048576 >/proc/sys/net/ipv4/tcp_max_syn_backlog

# Disabled by default. We dont use conntracking on gsocket-relay servers.
modprobe nf_conntrack
echo 1048576 >/proc/sys/net/netfilter/nf_conntrack_max
iptables -A INPUT -p tcp --dport 64222 --syn -m connlimit --connlimit-above 8 -j REJECT --reject-with tcp-reset
iptables -A INPUT -p tcp --syn -m connlimit --connlimit-above 2048 -j DROP

echo 5 >/proc/sys/net/ipv4/tcp_fin_timeout
echo 2 >/proc/sys/net/ipv4/tcp_tw_reuse
echo 1 >/proc/sys/net/ipv4/tcp_no_metrics_save

echo 10 >/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_time_wait
echo 10 >/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_syn_recv
echo 10 >/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_close_wait
echo 10 >/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_fin_wait
echo 5 >/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_last_ack
echo 1 >/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_close

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

# exec "$(dirname "$0")/gsrnd" -p22 -p53 -p67 -p443 -p7350

