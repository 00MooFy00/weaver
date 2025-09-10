#!/usr/bin/env bash
set -euo pipefail
# Все сетевые операции выполняем в host netns (через PID 1)
# чтобы управлять интерфейсами и nftables хоста, не ломая изоляцию сети контейнера.
if [[ "${1:-}" == "apply" || "${1:-}" == "reload" || "${1:-}" == "flush" ]]; then
  exec nsenter --net=/proc/1/ns/net -- python -m manager.cli "$@"
else
  exec "$@"
fi
