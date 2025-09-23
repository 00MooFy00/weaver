#!/usr/bin/env sh
set -eu

# Страховка от CRLF в самом себе
sed -i 's/\r$//' "$0" || true

CFG="${WEAVER_CONFIG:-/app/config.yaml}"

# Если смонтировали директорию, пробуем найти файл внутри
if [ -d "$CFG" ]; then
  if [ -f "$CFG/config.yaml" ]; then
    CFG="$CFG/config.yaml"
  else
    echo "FATAL: WEAVER_CONFIG points to directory ($CFG), but no config.yaml inside" >&2
    ls -la "$CFG" || true
    exit 64
  fi
fi

if [ ! -f "$CFG" ]; then
  echo "FATAL: config file not found at $CFG" >&2
  exit 64
fi

exec python -m weaver_handler.main --config "$CFG"

