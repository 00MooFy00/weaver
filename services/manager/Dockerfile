FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 nftables gosu curl ca-certificates iputils-ping \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements/manager.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY services/manager/weaver_manager/ /app/weaver_manager/
COPY services/manager/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh && sed -i 's/\r$//' /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]

