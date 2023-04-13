#! /bin/bash

# Bootstrapping a bare-linux until we are ready

apt update
apt install tmux jq build-essential ripgrep fd-find bc htop conntrack libevent-dev libssl-dev
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

mkdir -p /home/gsnet/usr/bin
# ./configure --prefix=/home/gsnet/usr
# cp deploy/gsrnd.service /etc/systemd/system
# systemctl enable gsrnd
# systemctl start gsrnd
# journalctl -u gsrnd -f --no-hostname
