FROM debian:12-slim
RUN apt-get update && apt-get install -y --no-install-recommends nftables iproute2 procps \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY services/setup/bin/setup.sh /app/setup.sh
RUN chmod +x /app/setup.sh
ENTRYPOINT ["/app/setup.sh"]

