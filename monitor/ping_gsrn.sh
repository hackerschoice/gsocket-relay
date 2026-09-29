#! /usr/bin/env bash

BASEDIR="$(cd "$(dirname "${0}")" || exit; pwd)"
source "${BASEDIR}/funcs"
command -v gs-netcat >/dev/null || ERREXIT 255 "command not found: gs-netcat"

date_bin="date"
command -v gdate >/dev/null && date_bin="gdate"
unset GSOCKET_IP

[[ "$($date_bin +%s%N)" == *N ]] && {
	echo >&2 "No GNU-date found. $date_bin +%s%N is bad. Try brew install coreutils"
	exit 255
}

gsrn_ping()
{
	local n=0
	SECRET=$(gs-netcat -g)

	export GSOCKET_HOST=$(dig +short "$1")
	export SECRET
	VARBACK=$(mktemp)

	GSPID="$(gs-netcat -s "$SECRET" -l -e cat 2>/dev/null >/dev/null </dev/null & echo "${!}")"
	M=31337000000

	echo -n "${1%%.*} [$GSOCKET_HOST] "

	(sleep 1; for x in {1..3}; do $date_bin +%s%N; sleep 0.5; done) | timeout 5 gs-netcat -s "$SECRET" -w -q| while read -r x 2>/dev/null; do
		! [[ $x =~ ^17 ]] && continue
		D=$(($($date_bin +%s%N) - x))
		printf "%.3fms " "$(echo "$D"/1000000 | bc -l)"
		[ "$D" -gt "$M" ] && continue
		M="$D"
		echo "$M" >"$VARBACK"
	done
	D=$(<"$VARBACK")
	rm -f "${VARBACK:?}"
	[ -n "$D" ] && printf "\t\tMIN %.3fms\n" "$(echo "$D"/1000000 | bc -l)"
	[ -z "$D" ] && printf "\t\tBADBADBAD\n"

	kill "$GSPID"
}

for h in "${HOSTS[@]}"; do
	gsrn_ping "$h"
done

