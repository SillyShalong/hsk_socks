# SOCKS5 server 
tested on macos and ubuntu20.04

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
1. dns cache
2. support ipv6
3. custom log
4. support udp