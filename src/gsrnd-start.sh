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
DEV_GW=$(ip route show | grep default | awk '{print $5;}')

if [[ -n $DEV_GW ]]; then
	tc qdisc del dev "${DEV_GW}" root 2>/dev/null
	tc_set "${DEV_GW}" 100Mbit
fi

exec "$(dirname "$0")/gsrnd" "$@"
