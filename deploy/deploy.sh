#! /bin/bash

VER_RELAY="$(grep AC_INIT ../configure.ac | cut -f3 -d"[" | cut -f1 -d']')"
VER_GS="$(grep AC_INIT ../../gsocket/configure.ac | cut -f3 -d"[" | cut -f1 -d']')"

deploy_host()
{
	local port
	port=$1
	host=$2
	[[ -z $host ]] && { echo >&2 "Bad parameters"; exit 2; } 
	echo "Deploying to ${host}:${port}...."
	ssh -p $port "gsnet@${host}" "{ [[ \"v${VER_GS}\" = \$(gsocket/tools/gs-netcat -h 2>&1 | grep ^OpenSSL |cut -f9 -d' '|tr -d ')') ]] || exit 255; } && exit 0" || { 
		echo "Updating gsocket-${VER_GS}..."
		scp -P $port ../../gsocket/gsocket-${VER_GS}.tar.gz "gsnet@${host}:" 
		ssh -p $port "gsnet@${host}" "tar xfz gsocket-${VER_GS}.tar.gz && \
			ln -sf gsocket-${VER_GS} gsocket && \
			(cd gsocket && ./configure --prefix=\$HOME/usr && make all install)"
	}

	ssh -p $port "gsnet@${host}" "[[ \"${VER_RELAY}\" = \$(usr/bin/gsrnd -h 2>&1 | grep ^Vers | cut -f2 -d' ') ]] && exit 0" && { echo "gsocket-relay-${VER_RELAY} already installed. Skipping."; return; }
	scp -P $port ../gsocket-relay-${VER_RELAY}.tar.gz "gsnet@${host}:"
	ssh -p $port "gsnet@${host}" "tar xfz gsocket-relay-${VER_RELAY}.tar.gz && \
		{ [[ -d \$HOME/usr ]] || mkdir \$HOME/usr; } && \
		(cd gsocket && ./configure --prefix=\$HOME/usr && make all install) && \
		[[ -f usr/bin/gsrnd ]] && { cp usr/bin/gsrnd usr/bin/gsrnd-\$(usr/bin/gsrnd -h 2>&1 | grep ^Vers | cut -f2 -d' ')_\$(date '+%s'); } && \
		(cd gsocket-relay-${VER_RELAY} && ./configure --prefix=\$HOME/usr && make all install) && \
		{ [[ \"${VER_RELAY}\" = \$(usr/bin/gsrnd -h 2>&1 | grep ^Vers | cut -f2 -d' ') ]] || { echo \"${host}: Cant execute gsrnd\"; exit 255; } } && \
		exit 0
	"
}

# deploy_host()
# {
# 	local port
# 	port=$1
# 	host=$2
# 	[[ -z $host ]] && { echo >&2 "Bad parameters"; exit 2; } 
# 	echo "Deploying to ${host}:${port}...."
# 	ssh -p $port "gsnet@${host}" "[[ \"${VER_RELAY}\" = \$(usr/bin/gsrnd -h 2>&1 | grep ^Vers | cut -f2 -d' ') ]] && exit 0" && { echo "gsocket-relay-${VER_RELAY} already installed. Skipping."; return; }
# 	scp -P $port ../../gsocket/gsocket-${VER_GS}.tar.gz ../gsocket-relay-${VER_RELAY}.tar.gz "gsnet@${host}:"
# 	ssh -p $port "gsnet@${host}" "tar xfz gsocket-${VER_GS}.tar.gz && \
# 	tar xfz gsocket-relay-${VER_RELAY}.tar.gz && \
# 	ln -sf gsocket-${VER_GS} gsocket && \
# 	{ [[ -d \$HOME/usr ]] || mkdir \$HOME/usr; } && \
# 	(cd gsocket && ./configure --prefix=\$HOME/usr && make all install) && \
# 	[[ -f usr/bin/gsrnd ]] && { cp usr/bin/gsrnd usr/bin/gsrnd-\$(usr/bin/gsrnd -h 2>&1 | grep ^Vers | cut -f2 -d' ')_\$(date '+%s'); } && \
# 	(cd gsocket-relay-${VER_RELAY} && ./configure --prefix=\$HOME/usr && make all install) && \
# 	{ [[ \"${VER_RELAY}\" = \$(usr/bin/gsrnd -h 2>&1 | grep ^Vers | cut -f2 -d' ') ]] || { echo \"${host}: Cant execute gsrnd\"; exit 255; } } && \
# 	exit 0
# 	"
# }

restart_host()
{
	local port
	port=$1
	host=$2
	[[ -z $host ]] && { echo >&2 "Bad parameters"; exit 2; } 
	ssh -p $port "root@${host}" "systemctl restart gsrnd && sleep 1 && systemctl status gsrnd"
}

# wget https://www.openssl.org/source/openssl-1.1.1k.tar.gz
# tar xfvz openssl-1.1.1k.tar.gz
# (cd openssl-1.1.1k && ./Configure linux-$(uname -m) --prefix=$HOME/usr && make all install_sw)
# sudo yum -y update
# sudo yum -y install gcc libevent-devel
#
# sudo apt -y install libevent-dev
echo "Relay  : ${VER_RELAY}"
echo "GSocket: ${VER_GS}"

hosts="gs1 gs2 gs3 gs4 gs5"
[[ -n "$1" ]] && hosts="$@"


for h in $hosts; do
	port=6422
	[[ "$h" =~ 'g16' ]] && port=22

	deploy_host "$port" "$h" || exit 254
done

echo "Press Enter to restart gsrnd or Ctrl-C to quit."
read
for h in $hosts; do
	port=6422
	[[ "$h" =~ 'g16' ]] && port=22
	restart_host "$port" "$h" || exit 254
done




