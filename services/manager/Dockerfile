FROM python:3.11-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 nftables util-linux ca-certificates curl jq \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# контекст сборки — корень, поэтому так
COPY requirements/manager.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY services/manager/ /app/
RUN chmod +x /app/bin/nsenter-net.sh

ENV PYTHONUNBUFFERED=1
