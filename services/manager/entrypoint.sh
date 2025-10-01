#!/usr/bin/env bash
set -euo pipefail

ARGS=(--config /app/config/config.yaml --nft-mode auto --addr-mode manage)

# Никаких проверок и подкоманд — просто запускаем корневую CLI
exec python -m weaver_manager "${ARGS[@]}"

