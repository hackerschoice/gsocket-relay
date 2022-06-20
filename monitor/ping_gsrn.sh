#! /bin/bash

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
[[ -z $HOSTS ]] && { echo -e "$(basename "${0}") [gsrn-hostname] ..."; exit 255; }

date_bin="date"
command -v gdate >/dev/null && date_bin="gdate"
unset GSOCKET_IP

MIN()
{
	echo $(($1>$2 ? $2 : $1))
}

gsrn_ping()
{
	SECRET=$(gs-netcat -g)

	export GSOCKET_HOST=$1
	export SECRET
	VARBACK=$(mktemp)

	GSPID="$(sh -c 'gs-netcat -s "$SECRET" -l -e cat &>/dev/null & echo ${!}')"
	M=31337000000

	(sleep 1; for x in $(seq 1 3); do $date_bin +%s%N; sleep 0.5; done) | gs-netcat -s "$SECRET" -w -q| while read -r x; do
		! [[ $x =~ ^16 ]] && continue

		D=$(($($date_bin +%s%N) - x))
		M=$(MIN $M $D)
		echo "$M" >"$VARBACK"
	done
	D=$(cat "$VARBACK")
	rm -f "$VARBACK"
	printf "MIN %s %.3fms\n" "$1" "$(echo "$D"/1000000 | bc -l)"

	kill "$GSPID"
}

for h in "${HOSTS[@]}"; do
	gsrn_ping "$h"
done




