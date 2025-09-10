LABEL authors="MooFy"

FROM python:3.9-slim-bookworm
ARG DEBIAN_FRONTEND=noninteractive
# nftables & nsenter для работы в host netns через libnftables и util-linux
RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 nftables util-linux python3-nftables \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements/manager.txt /tmp/req.txt
RUN pip install --no-cache-dir -r /tmp/req.txt
COPY services/manager/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
COPY services/manager/manager /app/manager
ENTRYPOINT ["/entrypoint.sh"]
