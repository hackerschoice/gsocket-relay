# Global Socket Server

Chances are that you are wrong here. Click here if you want to learn about gsocket: [https://www.github.com/hackerschoice/gsocket](https://www.github.com/hackerschoice.com/gsocket).

**Installation**
```
$ git clone --depth 1 https://github.com/hackerschoice/gsocket-server.git
$ cd gsocket-server
$ git clone --depth 1 https://github.com/hackerschoice/gsocket
$ (cd gsocket; ./bootstrap && ./configure && make)
$ ./bootstrap && ./configure && make
```

**Running the server**
```
$ src/gsrnd
```

**Testing**
```
$ cd gsocket/tests
$ GSOCKET_IP=127.0.0.1 ./run_gs_tests.sh
```
