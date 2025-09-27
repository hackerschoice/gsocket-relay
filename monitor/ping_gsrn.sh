#! /usr/bin/env bash

BASEDIR="$(cd "$(dirname "${0}")" || exit; pwd)"
source "${BASEDIR}/funcs"

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

	export GSOCKET_HOST="$1"
	export SECRET
	VARBACK=$(mktemp)

	GSPID="$(gs-netcat -s "$SECRET" -l -e cat 2>/dev/null >/dev/null </dev/null & echo "${!}")"
	M=31337000000

	echo -n "${1%%.*} "

	(sleep 1; for x in {1..3}; do $date_bin +%s%N; sleep 0.5; done) | gs-netcat -s "$SECRET" -w -q| while read -r x 2>/dev/null; do
		! [[ $x =~ ^17 ]] && continue
		D=$(($($date_bin +%s%N) - x))
		printf "%.3fms " "$(echo "$D"/1000000 | bc -l)"
		[ "$D" -gt "$M" ] && continue
		M="$D"
		echo "$M" >"$VARBACK"
	done
	D=$(<"$VARBACK")
	rm -f "${VARBACK:?}"
	printf "\t\tMIN %.3fms\n" "$(echo "$D"/1000000 | bc -l)"

	kill "$GSPID"
}

for h in "${HOSTS[@]}"; do
	gsrn_ping "$h"
done




