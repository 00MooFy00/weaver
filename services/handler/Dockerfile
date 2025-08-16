FROM python:3.11-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    libnetfilter-queue1 libnetfilter-queue-dev \
    libnfnetlink0 libnfnetlink-dev \
    nftables iproute2 tcpdump \
    build-essential ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements/handler.txt /tmp/req.txt
RUN pip install --no-cache-dir -r /tmp/req.txt

COPY services/handler/entrypoint.sh /app/entrypoint.sh
COPY services/handler/weaver_handler /app/weaver_handler
RUN chmod +x /app/entrypoint.sh

CMD ["/app/entrypoint.sh"]

ENV PYTHONUNBUFFERED=1
