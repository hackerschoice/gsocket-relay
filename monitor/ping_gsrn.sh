#! /usr/bin/env bash

BASEDIR="$(cd "$(dirname "${0}")" || exit; pwd)"
source "${BASEDIR}/funcs"

date_bin="date"
command -v gdate >/dev/null && date_bin="gdate"
unset GSOCKET_IP

gsrn_ping()
{
	SECRET=$(gs-netcat -g)

	export GSOCKET_HOST=$1
	export SECRET
	VARBACK=$(mktemp)

	GSPID="$(sh -c 'gs-netcat -s "$SECRET" -l -e cat &>/dev/null & echo ${!}')"
	M=31337000000

	(sleep 1; for x in $(seq 1 3); do $date_bin +%s%N; sleep 0.5; done) | gs-netcat -s "$SECRET" -w -q| while read -r x; do
		! [[ $x =~ ^17 ]] && continue

		D=$(($($date_bin +%s%N) - x))
		M=$(MIN $M $D)

		echo "$M" >"$VARBACK"
	done
	D=$(cat "$VARBACK")
	rm -f "${VARBACK:?}"
	printf "MIN %s %.3fms\n" "$1" "$(echo "$D"/1000000 | bc -l)"

	kill "$GSPID"
}

for h in "${HOSTS[@]}"; do
	gsrn_ping "$h"
done




