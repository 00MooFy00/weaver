cat > services/proxy/entrypoint.sh <<'SH'
#!/bin/sh
set -e

CFG="${CFG:-/app/config/config.yaml}"
PCFG="${PCFG:-/app/config/3proxy.cfg}"

# Если передали директорию с конфигом - возьмём 3proxy.cfg из неё
if [ -d "$PCFG" ]; then
  if [ -f "$PCFG/3proxy.cfg" ]; then
    PCFG="$PCFG/3proxy.cfg"
  else
    echo "FATAL: PROXY_CFG points to directory ($PCFG), but no 3proxy.cfg inside" >&2
    ls -la "$PCFG" || true
    exit 64
  fi
fi

[ -f "$CFG" ]  || { echo "FATAL: config file not found at $CFG" >&2; exit 64; }
[ -f "$PCFG" ] || { echo "FATAL: 3proxy config not found at $PCFG" >&2; exit 64; }

cleanup() {
  echo "cleanup: closing nftables allow rules..."
  python3 -u /usr/local/bin/portguard.py close --config "$CFG" >/dev/null 2>&1 || true
}

# Тихо чистим нашу таблицу (если была)
nft list table inet weaver_proxy >/dev/null 2>&1 && nft delete table inet weaver_proxy >/dev/null 2>&1 || true

# Открываем правила
python3 -u /usr/local/bin/portguard.py open --config "$CFG"

# Чистим при выходе
trap cleanup EXIT INT TERM

# 3proxy должен работать в Foreground: в конфиге НЕ должно быть "daemon"
exec gosu weaver:weaver /usr/local/bin/3proxy "$PCFG"
SH
chmod +x services/proxy/entrypoint.sh

