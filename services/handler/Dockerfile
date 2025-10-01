FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 libnfnetlink0 libnetfilter-queue1 \
    build-essential python3-dev \
    libnfnetlink-dev libnetfilter-queue-dev libmnl-dev \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements/handler.txt /app/requirements.txt
RUN pip install --no-cache-dir --upgrade pip setuptools wheel \
 && pip install --no-cache-dir -r /app/requirements.txt

COPY services/handler/ /app/weaver_handler/
COPY services/handler/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]

