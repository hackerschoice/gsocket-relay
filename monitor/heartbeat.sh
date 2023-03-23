#! /bin/bash

[[ $BASH_VERSION == "3."* ]] && { echo >&2 "BASH to old (${BASH_VERSION}). Try /usr/local/bin/bash ${0}."; exit 255; }
# Test if all servers are alive and functional
INTERVAL=60 # Check all servers every n seconds

BASEDIR="$(cd "$(dirname "${0}")" || exit; pwd)"
source "${BASEDIR}/funcs"
[[ -f "${BASEDIR}/.env" ]] && source "${BASEDIR}/.env"

command -v gs-netcat >/dev/null || ERREXIT 254 "Not found: gs-netcat"
command -v md5sum >/dev/null || ERREXIT 254 "Not found: md5sum"
command -v jq >/dev/null || ERREXIT 253 "Not found: jq"
command -v gdate >/dev/null && date(){ gdate "$@"; }
# Set these in .env
[[ -z $TG_TOKEN ]] && ERREXIT 252 "TG_TOKEN not set."
[[ -z $TG_CHATID ]] && ERREXIT 251 "TG_CHATID not set."

[[ -z $MYNAME ]] && {
	MYNAME=$(hostname)
	MYNAME=${MYNAME%%.*}
}


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
	kill $1
}


tg_msg()
{
	local str

	str=$(curl -fLSs --data-urlencode "text=\[$(date '+%F %T' -u)]\[${MYNAME}] $*" "https://api.telegram.org/bot${TG_TOKEN}/sendMessage?chat_id=${TG_CHATID}&parse_mode=Markdown" | jq '.ok')
	[[ $str != "true" ]] && ERREXIT 249 "Telegram API failed...."
	return 0
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
	waitkp "$GSPID1"
	waitkp "$GSPID2"

	# Compare results
	if [[ "$md5_in" == "$(XMD5 /tmp/gsrn_heartbeat_server_out.txt)" ]] && [[ "$md5_in" == "$(XMD5 /tmp/gsrn_heartbeat_client_out.txt)" ]]; then
		OK_COUNT=$((OK_COUNT+=1))
		[[ -n ${failed["${sn}"]} ]] && {
			tg_msg "✅ OK: Server: '$server'"
		}
		unset failed["${sn}"]
		return
	fi

	# Return if we already reported this error
	[[ -n ${failed["${sn}"]} ]] && return

	# Report error ONCE until test is OK again
	failed["${sn}"]=1
	tg_msg '🔥 FAILED: Server '"${server}"':
_=====Server=====_
```
'"$(grep -v ^= /tmp/gsrn_heartbeat_server_err.txt)"'
```_=====Client=====_
```
'"$(grep -v ^= /tmp/gsrn_heartbeat_client_err.txt)"'
```'

}

init_vars()
{
	echo "$(date) Hello World" >/tmp/gsrn_heartbeat_in.txt
	md5_in="$(XMD5 /tmp/gsrn_heartbeat_in.txt)"
	SECRET="$(gs-netcat -g)"
}

tg_msg '🏁 Starting *monitor* for '"${HOSTS[*]}"

declare -A failed
ts_last="$(date +%s)"
while :; do
	init_vars

	OK_COUNT=0
	unset ERR_MSG
	for h in "${HOSTS[@]}"; do
		heartbeat "$h"
	done
	# [[ -n $ERR_MSG ]] && {
	# 	tg_msg "$ERR_MSG"
	# }

	[[ "$OK_COUNT" -eq "${#HOSTS[@]}" ]] && echo "OK_COUNT=$OK_COUNT"
	# ERREXIT 0 "DEBUG TESTING"
	ts_now="$(date +%s)"

	sleep $((INTERVAL - (ts_now - ts_last)))
	ts_last=$((ts_last + INTERVAL))
done





