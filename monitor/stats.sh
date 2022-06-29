#! /bin/bash

BASEDIR="$(cd "$(dirname "${0}")" || exit; pwd)"
source "${BASEDIR}/funcs"

date_bin="date"
command -v gdate >/dev/null && date_bin="gdate"
unset GSOCKET_IP

for h in "${HOSTS[@]}"; do
	echo "=====${h}====="
	ssh -p 64222 gsnet@"${h}" '(echo -e "stats\nlist cli"; sleep 1) | usr/bin/gsrn_cli'
done




