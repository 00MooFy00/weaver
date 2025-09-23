FROM python:3.9-slim-bookworm

# Нужны тулзы и dev-зависимости для сборки NetfilterQueue C-расширения
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential gcc pkg-config \
    libnfnetlink-dev libnetfilter-queue-dev \
    nftables iproute2 ca-certificates \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY services/handler/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY services/handler/weaver_handler/ /app/weaver_handler/
COPY services/handler/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh && sed -i 's/\r$//' /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]

