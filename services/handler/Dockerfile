LABEL authors="MooFy"

FROM python:3.11-slim-bookworm
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential python3-dev libnetfilter-queue-dev libmnl-dev \
    iproute2 util-linux nftables \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements/handler.txt /tmp/req.txt
RUN pip install --no-cache-dir -r /tmp/req.txt
COPY services/handler/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
COPY services/handler/handler /app/handler
ENTRYPOINT ["/entrypoint.sh"]
