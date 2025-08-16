FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential ca-certificates wget \
    libssl-dev libcrypt-dev \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /tmp

RUN wget -qO 3proxy.tar.gz https://github.com/3proxy/3proxy/archive/refs/tags/0.9.4.tar.gz \
 && tar xzf 3proxy.tar.gz \
 && cd 3proxy-0.9.4 \
 && make -f Makefile.Linux \
 # Устойчиво на разных вариантах сборки
 && sh -lc 'set -e; OUT=src/3proxy; [ -f "$OUT" ] || OUT=bin/3proxy; install -m 0755 "$OUT" /usr/bin/3proxy' \
 && cd /tmp && rm -rf 3proxy-0.9.4 3proxy.tar.gz

WORKDIR /app
RUN mkdir -p /app/config

COPY services/proxy/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
