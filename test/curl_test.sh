#!/bin/bash
curl -v -L --socks5-hostname 127.0.0.1:6788 https://www.baidu.com
curl -v -L --socks5-hostname 127.0.0.1:6788 https://www.google.com
curl -v -L --socks5-hostname 127.0.0.1:6788 https://www.facebook.com
curl -v -L --socks5-hostname 127.0.0.1:6788 https://www.bing.cn
curl -v -L --socks5-hostname 127.0.0.1:6788 https://www.bilibili.com
curl -v -L --socks5-hostname 127.0.0.1:6788 https://speed.hetzner.de/100MB.bin -o /dev/null