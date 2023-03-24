# Global Socket Relay

Chances are that you are wrong here. Click here if you want to learn about gsocket: [https://www.github.com/hackerschoice/gsocket](https://www.github.com/hackerschoice.com/gsocket). You do not need this unless you want to review code.

You have been warned...

TODO:
- document (try the wiki)

**Installation**
```
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
