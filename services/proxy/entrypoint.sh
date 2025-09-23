#!/usr/bin/env sh
set -eu
sed -i 's/\r$//' "$0" || true

CFG="${WEAVER_CONFIG:-/app/config.yaml}"
PCFG="${PROXY_CFG:-/app/config/3proxy.cfg}"

if [ -d "$CFG" ]; then
  if [ -f "$CFG/config.yaml" ]; then
    CFG="$CFG/config.yaml"
  else
    echo "FATAL: WEAVER_CONFIG points to directory ($CFG), but no config.yaml inside" >&2
    ls -la "$CFG" || true
    exit 64
  fi
fi

if [ -d "$PCFG" ]; then
  if [ -f "$PCFG/3proxy.cfg" ]; then
    PCFG="$PCFG/3proxy.cfg"
  else
    echo "FATAL: PROXY_CFG points to directory ($PCFG), but no 3proxy.cfg inside" >&2
    ls -la "$PCFG" || true
    exit 64
  fi
fi

[ -f "$CFG" ] || { echo "FATAL: config file not found at $CFG" >&2; exit 64; }
[ -f "$PCFG" ] || { echo "FATAL: 3proxy config not found at $PCFG" >&2; exit 64; }

cleanup() {
  echo "cleanup: closing nftables allow rules..."
  python3 -u /usr/local/bin/portguard.py close --config "$CFG" || true
}
trap cleanup INT TERM EXIT

# Открываем правила (input + output)
python3 -u /usr/local/bin/portguard.py open --config "$CFG"

# Запускаем 3proxy под uid/gid 1337 (weaver), чтобы egress-фильтр по skuid сработал
gosu weaver:weaver /usr/local/bin/3proxy "$PCFG" &
child="$!"
wait "$child"

