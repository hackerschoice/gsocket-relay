#! /bin/bash

# Bootstrapping a bare-linux until we are ready

ln -sf /dev/null ~/.bash_history
apt update
apt install -y tmux jq build-essential curl iptables ripgrep fd-find bc htop conntrack libevent-dev libssl-dev net-tools
ln -s /usr/bin/fdfind /usr/bin/fd
echo nf_conntrack >>/etc/modules
echo "net.ipv4.tcp_syncookies=0" >>/etc/sysctl.conf

### Check journal file
ps -A --sort -rss -o comm,pmem,rss | head -n 5
sed 's/#SystemMaxFileSize.*/SystemMaxFileSize=50M/' -i /etc/systemd/journald.conf
sed 's/#SystemMaxUse.*/SystemMaxUse=10M/' -i /etc/systemd/journald.conf
systemctl restart systemd-journald

sed 's/.*Port 22$/Port 64222/' -i /etc/ssh/sshd_config
systemctl restart sshd

useradd gsnet
mkdir -p /home/gsnet/usr/bin /home/gsnet/src
# chown gsnet:gsnet /home/gsnet

[[ -L /etc/resolv.conf ]] && {
    systemctl stop systemd-resolved
    systemctl disable systemd-resolved
    rm /etc/resolv.conf
    echo -e "nameserver 1.1.1.1\nnameserver 8.8.8.8" >/etc/resolv.conf
}

# For gsrn-hb also add all servers to /etc/hosts

exit 0
cd /sec/src
VER="1.4.42dev2"
tar xfvz "gsocket-${VER}.tar.gz"
ln -s "gsocket-${VER}" gsocket
cd gsocket-relay-1.0.12
ln -s ../gsocket gsocket
(cd gsocket && ./configure && make)
./configure --prefix=/sec/usr && make install
cp deploy/gsrnd.service /etc/systemd/system
systemctl enable gsrnd
systemctl start gsrnd && systemctl status gsrnd
journalctl -u gsrnd -f --no-hostname
