FROM debian:12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates wget build-essential make gcc \
    nftables python3 python3-yaml gosu \
 && rm -rf /var/lib/apt/lists/*

# ===== Build 3proxy (фиксированная версия) =====
ENV PROXY_VERSION=0.9.5
RUN wget -O /tmp/3proxy.tar.gz "https://github.com/3proxy/3proxy/archive/refs/tags/${PROXY_VERSION}.tar.gz" \
 && cd /tmp && tar xzf 3proxy.tar.gz && cd "3proxy-${PROXY_VERSION}" \
 && make -f Makefile.Linux \
 && if [ -x bin/3proxy ]; then install -Dm755 bin/3proxy /usr/local/bin/3proxy; \
    elif [ -x src/3proxy ]; then install -Dm755 src/3proxy /usr/local/bin/3proxy; \
    else echo "FATAL: 3proxy binary not found"; exit 1; fi \
 && rm -rf /tmp/3proxy*

# Пользователь для 3proxy (UID/GID 1337)
RUN groupadd -g 1337 weaver && useradd -r -u 1337 -g 1337 -M -s /usr/sbin/nologin weaver

# Портгард и энтрипоинт
COPY services/proxy/portguard.py /usr/local/bin/portguard.py
COPY services/proxy/entrypoint.sh /entrypoint.sh
RUN chmod +x /usr/local/bin/portguard.py /entrypoint.sh \
 && sed -i 's/\r$//' /entrypoint.sh

WORKDIR /app
ENTRYPOINT ["/entrypoint.sh"]

