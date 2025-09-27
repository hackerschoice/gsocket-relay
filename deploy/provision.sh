#! /bin/bash

# Bootstrapping a bare-linux until we are ready

ln -sf /dev/null ~/.bash_history
apt update
apt install -y tmux jq build-essential curl iptables ripgrep fd-find bc htop conntrack libevent-dev libssl-dev net-tools gsocket
ln -s /usr/bin/fdfind /usr/bin/fd
echo nf_conntrack >>/etc/modules
echo "net.ipv4.tcp_syncookies=0" >>/etc/sysctl.conf

### Check journal file
ps -A --sort -rss -o comm,pmem,rss | head -n 5
sed 's/#SystemMaxFileSize.*/SystemMaxFileSize=50M/' -i /etc/systemd/journald.conf
sed 's/#SystemMaxUse.*/SystemMaxUse=10M/' -i /etc/systemd/journald.conf
systemctl restart systemd-journald

sed 's/.*Port 22$/Port 64222/' -i /etc/ssh/sshd_config
systemctl restart ssh

useradd gsnet
cp -a /etc/skel /home/gsnet
mkdir /home/gsnet/.ssh
touch /home/gsnet/.ssh/authorized_keys
chown -R gsnet:gsnet /home/gsnet

[[ -L /etc/resolv.conf ]] && {
    systemctl stop systemd-resolved
    systemctl disable systemd-resolved
    rm /etc/resolv.conf
    echo -e "nameserver 1.1.1.1\nnameserver 8.8.8.8" >/etc/resolv.conf
}

