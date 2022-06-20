#! /bin/bash

# Test if all servers are alive and functional
INTERVAL=60 # Check all servers every n seconds

BASEDIR="$(cd "$(dirname "${0}")" || exit; pwd)"

# Load the list of GSRN hosts if no arg is specified. File looks like this:
# DOMAIN=thc.org
# HOSTS+=("gs1.${DOMAIN}")
# HOSTS+=("gs2.${DOMAIN}")
# HOSTS+=("gs3.${DOMAIN}")
# HOSTS+=("gs4.${DOMAIN}")
# HOSTS+=("gs5.${DOMAIN}")
[[ ${#@} -eq 0 ]] && source "${BASEDIR}/.gsrn_hosts" 

# Otherwise use hosts from command line arguments.
[[ -z $HOSTS ]] && HOSTS=(${@})
[[ -z $HOSTS ]] && { echo -e "heartbeat.sh [gsrn-hostname] ..."; exit 255; }

ERREXIT()
{
	local code
	code="$1"

	[[ $? -ne 0 ]] && code="$?"
	[[ -z $code ]] && code=99

	shift 1
	[[ -n $1 ]] && echo -e >&2 "ERROR: $*"

	exit "$code"
}

XMD5() { md5sum "${1}" 2>/dev/null | cut -f1 -d' '; }

command -v gs-netcat >/dev/null || ERREXIT 254 "Not found: gs-netcat"
command -v md5sum >/dev/null || ERREXIT 254 "Not found: md5sum"

waitkp()
{
	local x
	local rounds
	# How many seconds the test should take
	local sleep_wd
	sleep_wd=5

	x=0
	rounds=$((sleep_wd * 10))

	while :; do
		kill -0 $1 &>/dev/null || return
		sleep 0.1
		x=$((x+1))
		[[ $x -gt $rounds ]] && break
	done
}

heartbeat()
{
	# Start a server
	local server
	server=$1
	sn="${server//./_}"

	rm -f /tmp/gsrn_heartbeat_server_err.txt /tmp/gsrn_heartbeat_server_out.txt /tmp/gsrn_heartbeat_client_err.txt /tmp/gsrn_heartbeat_client_out.txt

	# Start 2 background processes
	GSPID1="$(sh -c 'GSOCKET_HOST="'$1'" gs-netcat -s "'$SECRET'" -l </tmp/gsrn_heartbeat_in.txt 2>/tmp/gsrn_heartbeat_server_err.txt >/tmp/gsrn_heartbeat_server_out.txt & echo ${!}')"
	GSPID2="$(sh -c 'GSOCKET_HOST="'$1'" gs-netcat -s "'$SECRET'" -w </tmp/gsrn_heartbeat_in.txt 2>/tmp/gsrn_heartbeat_client_err.txt >/tmp/gsrn_heartbeat_client_out.txt & echo ${!}')"

	# Wait max sleep_wd seconds for them to complete.
	waitkp $GSPID1
	waitkp $GSPID2

	# Compare results
	if [[ "$md5_in" = "$(XMD5 /tmp/gsrn_heartbeat_server_out.txt)" ]]; then
		OK_COUNT=$((OK_COUNT+=1))
		eval unset test_failed_\"${sn}\"
		return
	fi

	# Return if we already reported this error
	eval [[ -n \$"test_failed_${sn}" ]] && return

	# Report error ONCE until test is OK again
	eval "test_failed_${sn}"=1
	ERR_MSG+="FAILED: Server '$server':\n"
	ERR_MSG+="=====Server=====\n$(cat /tmp/gsrn_heartbeat_server_err.txt)\n"
	ERR_MSG+="=====Client=====\n$(cat /tmp/gsrn_heartbeat_client_err.txt)\n"
}

init_vars()
{
	echo "$(date) Hello World" >/tmp/gsrn_heartbeat_in.txt
	md5_in="$(XMD5 /tmp/gsrn_heartbeat_in.txt)"
	SECRET="$(gs-netcat -g)"
}



ts_last="$(date +%s)"
while :; do
	init_vars

	OK_COUNT=0
	ts_date="$(date)"
	unset ERR_MSG
	for h in "${HOSTS[@]}"; do
		heartbeat "$h"
	done
	[[ -n $ERR_MSG ]] && echo -en "$ERR_MSG"

	[[ "$OK_COUNT" -eq "${#HOSTS[@]}" ]] && echo "[OK] OK_COUNT=$OK_COUNT ${ts_date}"
	# ERREXIT 0 "DEBUG TESTING"
	ts_now="$(date +%s)"

	sleep $((INTERVAL - (ts_now - ts_last)))
	ts_last=$((ts_last + INTERVAL))
done





