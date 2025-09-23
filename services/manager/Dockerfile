FROM python:3.9-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 nftables ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY services/manager/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY services/manager/weaver_manager/ /app/weaver_manager/
COPY services/manager/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh && sed -i 's/\r$//' /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]

