FROM python:3.11-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libnfnetlink-dev libnetfilter-queue-dev util-linux ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements/handler.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY services/handler/ /app/
RUN chmod +x /app/bin/nsenter-net.sh

ENV PYTHONUNBUFFERED=1
