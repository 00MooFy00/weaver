FROM debian:12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash build-essential ca-certificates curl git gosu iproute2 nftables util-linux \
    python3 python3-yaml \
 && rm -rf /var/lib/apt/lists/*

# 3proxy 0.9.5
RUN set -eux; \
    mkdir -p /opt && cd /opt; \
    curl -fsSL -o 3proxy.tar.gz https://github.com/z3APA3A/3proxy/archive/refs/tags/0.9.5.tar.gz; \
    tar xf 3proxy.tar.gz; \
    cd 3proxy-0.9.5; \
    make -f Makefile.Linux; \
    install -s src/3proxy /usr/bin/3proxy

RUN groupadd -g 1337 weaver && useradd -m -u 1337 -g 1337 weaver

WORKDIR /app
COPY services/proxy/bin/entrypoint.sh /usr/local/sbin/proxy-entry.sh
RUN chmod +x /usr/local/sbin/proxy-entry.sh

RUN mkdir -p /run/3proxy && chown -R 1337:1337 /run/3proxy
ENTRYPOINT ["/usr/local/sbin/proxy-entry.sh"]

