#!/usr/bin/env bash
set -euo pipefail

CFG="/etc/3proxy/3proxy.cfg"
if [[ ! -s "$CFG" ]]; then
  echo "FATAL: $CFG not found or empty" >&2
  exit 1
fi

# Запуск 3proxy (man 3proxy: SIGUSR1 — reload config)
exec /usr/local/3proxy/bin/3proxy "$CFG"
