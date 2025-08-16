#!/usr/bin/env sh
set -eu pipefail
export PYTHONUNBUFFERED=1

exec python -m weaver_manager.cli apply --config /app/config/config.yaml --iface auto
