#!/usr/bin/env sh
set -eu

exec python -m weaver_manager --config /app/config/config.yaml apply

