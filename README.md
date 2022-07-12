# SOCKS5 server
tested on macos and ubuntu20.04
only support socks version 5

PREREQUISITE:
```
install libev
```

BUILD:
```
mkdir build && cd build
cmake ..
```

RUN SOCKS5 SERVER:
```
// server listen to port 6788
./Socks5Server 

```

RUN SOCKS5 CLIENT:
```
curl -v -L --socks5 127.0.0.1:6788 https://www.baidu.com
```

TODO:
1. ipv6
2. udp
3. up/down speed monitor