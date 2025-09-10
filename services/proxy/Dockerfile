LABEL authors="MooFy"
# -------- builder --------
FROM debian:bookworm-slim AS builder
ARG DEBIAN_FRONTEND=noninteractive
ARG VERSION=0.9.5
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates wget build-essential make gcc libc6-dev libssl-dev tar \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /tmp
# исходники 3proxy 0.9.5 (security fix)
RUN wget -qO 3proxy.tar.gz https://github.com/3proxy/3proxy/archive/refs/tags/${VERSION}.tar.gz \
 && tar -xzf 3proxy.tar.gz \
 && cd 3proxy-${VERSION} \
 && make -f Makefile.Linux \
 && make -f Makefile.Linux install

# -------- runtime --------
FROM debian:bookworm-slim
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends tzdata ca-certificates \
 && rm -rf /var/lib/apt/lists/*
# создаём системного пользователя с фиксированным UID=1337 (совпадает в host ns)
RUN useradd -u 1337 -U -M -r -s /usr/sbin/nologin 3proxy
# копируем установленный 3proxy из билда
COPY --from=builder /usr/local/3proxy /usr/local/3proxy
# minimal symlink для удобного запуска
RUN ln -s /usr/local/3proxy/bin/3proxy /usr/bin/3proxy \
 && mkdir -p /etc/3proxy
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
USER 1337:1337
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
