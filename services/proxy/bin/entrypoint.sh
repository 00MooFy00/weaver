#!/usr/bin/env bash
set -euo pipefail

RUN_DIR=/run/3proxy
CFG="$RUN_DIR/3proxy.cfg"
VER="$RUN_DIR/3proxy.ver"
PID="$RUN_DIR/3proxy.pid"

PORT_START="${PROXY_PORT_START:-30000}"
PORT_COUNT="${PROXY_PORT_COUNT:-64}"
LISTEN_IP="${PROXY_LISTEN_IP:-::}"

install -d -m 0775 -o 1337 -g 1337 "$RUN_DIR"
rm -f "$PID"

cat >"$CFG" <<'CFGEOF'
setgid 1337
setuid 1337
pidfile /run/3proxy/3proxy.pid
log /run/3proxy/3proxy.log D
rotate 10
monitor "/run/3proxy/3proxy.ver"
flush
nserver 1.1.1.1
nserver 8.8.8.8
timeouts 1 5 5 60 180 1800 10 60

auth none
allow *
CFGEOF

i=0
while [ "$i" -lt "$PORT_COUNT" ]; do
  p=$((PORT_START + i))
  echo "proxy -6 -p${p} -i${LISTEN_IP} -n -a" >>"$CFG"
  i=$((i+1))
done

chown 1337:1337 "$CFG"
echo $(( $(cat "$VER" 2>/dev/null || echo 0) + 1 )) >"$VER"

echo "[proxy] starting 3proxy; ports ${PORT_START}..$((PORT_START+PORT_COUNT-1))"
exec /usr/bin/3proxy "$CFG"

