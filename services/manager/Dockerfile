FROM python:3.11-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 nftables ca-certificates curl jq \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements/manager.txt /tmp/req.txt
RUN pip install --no-cache-dir -r /tmp/req.txt

COPY services/manager/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

COPY services/manager/weaver_manager /app/weaver_manager
ENV PYTHONUNBUFFERED=1

