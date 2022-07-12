# Event driven Socks5Server base on libev

Introduction:
1. Implementation of socks5 protocol server side
2. Based on libev
3. Only support socks version 5
4. Well commented and include a diagram to clarify program logic

PREREQUISITE:
```
install libev
```

BUILD:
```
// tested on macos and ubuntu20.04
 
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
curl -v -L --socks5 127.0.0.1:6788 http://127.0.0.1:8080
curl -v -L --socks5-hostname 127.0.0.1:6788 https://www.google.com
```

PROBLEMS TO ISSUE:
1. The only blocking call in the program is DNS resolve, since the program is single thread, it might slow due to blocking to dns resolver, the solution is to use async dns resolver. or change to an appropriate dns server

TODO:
1. ipv6
2. udp
3. up/down speed monitor
4. track connections
5. tcp fast open
6. tcp no delay
7. use async dns resolver, otherwise resolving dns is slow sometimes