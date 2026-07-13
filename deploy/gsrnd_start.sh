
#! /usr/bin/env bash

BASEDIR="$(cd "$(dirname "${0}")" || exit; pwd)"
# source "${BASEDIR}/funcs" || exit
[[ -f "${BASEDIR}/.env" ]] && source "${BASEDIR}/.env" || echo >&2 ".env not found. TG notify disabled."

[[ -z $MYNAME ]] && {
	MYNAME=$(hostname)
	MYNAME=${MYNAME%%.*}
}

tg_msg()
{
	local str
	[[ -z "$TG_TOKEN" ]] && return

	str=$(curl -fLSs --retry 3 --max-time 15 --data-urlencode "text=\[$(date '+%F %T' -u)]\[${MYNAME:-GS}] $*" "https://api.telegram.org/bot${TG_TOKEN}/sendMessage?chat_id=${TG_CHATID}&parse_mode=Markdown" | jq '.ok')
	[[ $str != "true" ]] && return 255 #ERREXIT 249 "Telegram API failed...."
	return 0
}

# Once
ipt() {
	local first=$1

	shift 1
	iptables -C "$@" 2>/dev/null && return
	iptables "$first" "$@"
}

tg_msg "GSRND started."

DEV_GW=$(ip route show | grep default | head -n1 | awk '{print $5;}')
TC_ARGS=()
[[ -n $GS_LIMIT ]] && TC_ARGS+=(bandwidth "$GS_LIMIT")

tc qdisc del dev "$DEV_GW" root 2>/dev/null
tc qdisc add dev "$DEV_GW" root cake "${TC_ARGS[@]}" "dsthost"
unset TC_ARGS
# tc qdisc add dev "$DEV_GW"root handle 11: sfq
# tc filter add dev "$DEV_GW" parent 11: handle 11 flow hash keys dst divisor 2048

echo $((16 * 1024)) >/proc/sys/net/core/somaxconn
echo $((128 * 1024)) >/proc/sys/net/ipv4/tcp_max_syn_backlog

sysctl -w net.ipv4.tcp_syncookies=1

# Disabled by default. We dont use conntracking on gsocket-relay servers.
modprobe nf_conntrack
# 262,144 × 350 bytes ≈ 92MB
echo 1048576 >/proc/sys/net/netfilter/nf_conntrack_max
P="$(grep -m1 ^Port /etc/ssh/sshd_config | sed -e 's|Port \(.\)|\1|g')"
P="${P:-64222}"
ipt -A INPUT -p tcp --syn -m multiport ! --dports "22,25,53,67,80,443,7350,${P}" -j DROP
ipt -A INPUT -p tcp --dport "${P}" --syn -m connlimit --connlimit-above 8 -j REJECT --reject-with tcp-reset
# Some bad deployments (early version) start hundrets of gsnc -l. The gsrnd puts those into
# BAD-AUTH queue to stop them from flooding the server with SYN. On IPT -j DROP
# the client will wait 130 seconds before giving up.
# ipt -A INPUT -p tcp --syn -m connlimit --connlimit-above 2048 -j DROP
ipt -A INPUT -p tcp --syn -m connlimit --connlimit-above 1024 -j DROP
# Prevent SYN floods
ipt -A INPUT -p tcp --syn -m hashlimit --hashlimit-name synflood --hashlimit-above 50/sec --hashlimit-burst 100 --hashlimit-mode srcip --hashlimit-srcmask 32 -j DROP
#ipt -A INPUT -p tcp --syn -m hashlimit --hashlimit-name synflood-global --hashlimit-above 2000/sec --hashlimit-burst 40000 --hashlimit-mode dstip -j DROP

# See https://www.frozentux.net/ipsysctl-tutorial/chunkyhtml/tcpvariables.html
echo 60 >/proc/sys/net/ipv4/tcp_keepalive_time
echo 10 >/proc/sys/net/ipv4/tcp_keepalive_intvl
echo 4  >/proc/sys/net/ipv4/tcp_keepalive_probes

# Reduce to 2. The CLIENT will re-transmit SYN anyway.
echo 2 >/proc/sys/net/ipv4/tcp_synack_retries
# 7=25.4sec, 8=51sec, 9=102.2sec, 10=204.6sec, 11=324.6sec, 12=444.6sec
echo 8 >/proc/sys/net/ipv4/tcp_retries2

echo 5 >/proc/sys/net/ipv4/tcp_fin_timeout
echo 2 >/proc/sys/net/ipv4/tcp_tw_reuse
echo 1 >/proc/sys/net/ipv4/tcp_no_metrics_save

echo 10 >/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_time_wait
echo 10 >/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_syn_recv
echo 10 >/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_close_wait
echo 10 >/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_fin_wait
echo 5 >/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_last_ack
echo 1 >/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_close

# Decrease orphans - Orphaned TCP connections should be killed fast.
# Each can eat up to 64kB
echo 1024 >/proc/sys/net/ipv4/tcp_max_orphans
echo 2 >/proc/sys/net/ipv4/tcp_orphan_retries
# echo 65535 >/proc/sys/net/ipv4/tcp_max_orphans

# net.ipv4.tcp_mem is now managed continuously by gsrnd-tcpmem.service
# (see gsrnd_tcpmem_watch.sh) - it yields TCP buffer memory to gsrnd on
# demand instead of a static split computed once at start.

# 4k per socket min.
# min, default, max
#echo 4096  4096   131072 >/proc/sys/net/ipv4/tcp_rmem
# Note: Normally the packets are read immediately and thus no rmem is needed.
# Start with larger buffer. Will be redued when pressure increases.
echo "4096  16384   32768" >/proc/sys/net/ipv4/tcp_rmem
# wmem defines throughput. On a 200ms link between A and B the max speed thus is:
# 1000 / (200 * 2) * wmem_default
#
# with 131072 buffer and 200ms the user can get 327KBps
# 131072 / (0.2 * 2) / 1024 == 320
# On a 4GB server with 80% for TCP and all buffers 
# 4 * 1024 * 1024 * 1024 * 0.8 /  131072 == 26,214 connections
#echo 4096  1048576  1048576 >/proc/sys/net/ipv4/tcp_wmem
echo "4096    65536  1048576" >/proc/sys/net/ipv4/tcp_wmem

grep . /proc/sys/net/ipv4/tcp*mem

# NOTE: It's started from systemd via:
# ExecStartPre=/bin/bash /home/gsnet/usr/bin/gsrnd_start.sh
# ExecStart=/home/gsnet/usr/bin/gsrnd -p...

