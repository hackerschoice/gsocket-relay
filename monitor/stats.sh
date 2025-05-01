#! /bin/bash

BASEDIR="$(cd "$(dirname "${0}")" || exit; pwd)"
source "${BASEDIR}/funcs"

date_bin="date"
command -v gdate >/dev/null && date_bin="gdate"
unset GSOCKET_IP

[ -z "$VERBOSE" ] && echo >&2 "Use VERBOSE=[12] for verbose output"
cmd=""
[ "${VERBOSE:-0}" -eq 1 ] && cmd='(echo -e "stats\nlist server"; sleep 1) | gsrn_cli;'
[ "${VERBOSE:-0}" -gt 1 ] && cmd="(echo -e 'stats\nlist cli'; sleep 1) | gsrn_cli;"
cmd+='echo -e "netstat EST: \e[0;33m$(netstat -ant | grep EST | wc -l)\e[0m";'

for h in "${HOSTS[@]}"; do
	echo "=====${h}====="
	ssh "${SSH_ARGS[@]}" "${h}" "$cmd"
done




