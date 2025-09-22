# services/proxy/Dockerfile
FROM debian:12-slim

ARG VER=0.9.5
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential wget ca-certificates util-linux \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /tmp
RUN wget -O 3proxy.tgz "https://github.com/3proxy/3proxy/archive/refs/tags/${VER}.tar.gz" \
 && tar xzf 3proxy.tgz \
 && cd 3proxy-${VER} \
 && make -f Makefile.Linux \
 && mkdir -p /usr/local/3proxy/sbin /usr/local/3proxy/conf /run/3proxy \
 && cp bin/3proxy /usr/local/3proxy/sbin/ \
 && rm -rf /tmp/3proxy*

COPY services/proxy/bin/nsenter-net.sh /usr/local/bin/nsenter-net.sh
RUN chmod +x /usr/local/bin/nsenter-net.sh

WORKDIR /usr/local/3proxy
