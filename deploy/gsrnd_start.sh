
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
[ -n "$GS_LIMIT" ] && TC_ARGS+=(bandwidth "$GS_LIMIT")

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
# CLI (gsrn_cli) only ever connects via loopback (127.0.0.1). Exempt lo before
# the DDoS/SYN-filter rules below so the port allow-list doesn't need to know
# about CLI_DEFAULT_PORT/CLI_DEFAULT_PORT_SSL.
ipt -I INPUT -i lo -j ACCEPT
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

# Connections dropped by the connlimit rules above (source already over its
# cap) never get a reply and otherwise sit in SYN_SENT for the 120s kernel
# default - shrink that backlog fast, we never work this traffic anyway.
echo 5 >/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_syn_sent
# Kernel default is 432000 (5 days). gsrnd clients keep-alive every 30s at
# the application layer, so anything idle past a few minutes is already
# dead (crashed client, network partition) - don't hold its state for days.
echo 360 >/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_established

# Decrease orphans - Orphaned TCP connections should be killed fast.
# Each can eat up to 64kB
echo 1024 >/proc/sys/net/ipv4/tcp_max_orphans
echo 2 >/proc/sys/net/ipv4/tcp_orphan_retries
# echo 65535 >/proc/sys/net/ipv4/tcp_max_orphans

# net.ipv4.tcp_mem AND tcp_rmem/tcp_wmem's per-socket ceiling (3rd field) are
# now managed continuously by gsrnd-tcpmem.service (see gsrnd_tcpmem_watch.sh)
# - it scales the ceiling between 32KB and 512KB based on how much TCP memory
# is actually in use vs. the tcp_mem pressure threshold, instead of a static
# value picked once here. These starting values just cover the few seconds
# before its first iteration.
# min, default, max
echo "4096  16384   32768" >/proc/sys/net/ipv4/tcp_rmem
echo "4096  65536   32768" >/proc/sys/net/ipv4/tcp_wmem

grep . /proc/sys/net/ipv4/tcp*mem

# NOTE: It's started from systemd via:
# ExecStartPre=/bin/bash /home/gsnet/usr/bin/gsrnd_start.sh
# ExecStart=/home/gsnet/usr/bin/gsrnd -p...

