# Global Socket Relay

Chances are that you are wrong here. Click here if you want to learn about gsocket: [https://www.github.com/hackerschoice/gsocket](https://www.github.com/hackerschoice.com/gsocket). You do **NOT** need this to use gsocket.

*You have been warned...*

**Installation from static binary**
```shell
DIR="/opt/gsrnd"
[ ! -d "${DIR:?}" ] && mkdir -p "${DIR}"
curl -SsfL "https://github.com/hackerschoice/gsocket-relay/releases/latest/download/gsrnd-linux-$(uname -m)" -o "${DIR:?}/gsrnd" \
&& curl -SsfL "https://github.com/hackerschoice/gsocket-relay/releases/latest/download/gsrn_cli-linux-$(uname -m)" -o "${DIR}/gsrn_cli" \
&& curl -SsfL "https://github.com/hackerschoice/gsocket-relay/raw/refs/heads/main/deploy/gsrnd_start.sh" -o "${DIR}/gsrnd_start.sh" \
&& chmod 755 /usr/bin/gsrnd /usr/bin/gsrn_cli /usr/bin/gsrnd_start.sh \
&& curl -SsfL 'https://github.com/hackerschoice/gsocket-relay/raw/refs/heads/main/deploy/gsrnd.service' | sed "s|/usr/bin/|${DIR:?}/|" > \
&& systemctl enable gsrnd \
&& systemctl start gsrnd && systemctl status gsrnd \
&& journalctl -u gsrnd -f --no-hostname 
```

---

### OLD STUFF

**Installation from source**
```
$ sudo apt install make automake autoconf gcc libevent-dev libssl-dev
$ git clone --depth 1 https://github.com/hackerschoice/gsocket-relay.git
$ cd gsocket-relay
$ git clone --depth 1 https://github.com/hackerschoice/gsocket
$ (cd gsocket; ./bootstrap && ./configure && make)
$ ./bootstrap && ./configure && make
```

**Running the relay**
```
$ src/gsrnd
```

**Testing**
```
$ cd gsocket/tests
$ GSOCKET_IP=127.0.0.1 ./run_gs_tests.sh
```
