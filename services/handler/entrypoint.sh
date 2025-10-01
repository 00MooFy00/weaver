#!/usr/bin/env bash
set -euo pipefail
export PYTHONUNBUFFERED=1
export PYTHONPATH=/app

CFG="${WEAVER_CONFIG:-/app/config/config.yaml}"

# запускаем как пакет, чтобы относительные импорты работали
exec python -m weaver_handler.weaver_handler.main --config "$CFG"

