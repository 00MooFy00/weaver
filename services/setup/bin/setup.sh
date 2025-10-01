#!/usr/bin/env bash
set -euo pipefail

iface="${IPV6_INTERFACE:-eno1}"
subnet="${IPV6_SUBNET:-2a01:4f8:c0c:1234::/64}"
nfq="${NFQUEUE_NUM:-0}"
uid="${PROXY_UID:-1337}"

log(){ echo "[setup] $*"; }

apply_sysctl() {
  log "sysctl ..."
  sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null
  sysctl -w net.ipv6.conf.default.accept_ra=2 >/dev/null || true
  sysctl -w net.ipv6.conf.all.accept_ra=2 >/dev/null || true
  sysctl -w net.ipv6.conf."${iface}".proxy_ndp=1 >/dev/null || true
  sysctl -w net.ipv6.ip_nonlocal_bind=1 >/dev/null
}

apply_nat66() {
  log "NAT66 for ${subnet} via ${iface}"
  nft list table ip6 nat >/dev/null 2>&1 || nft add table ip6 nat
  nft list chain ip6 nat postrouting >/dev/null 2>&1 || \
    nft add chain ip6 nat postrouting { type nat hook postrouting priority srcnat\; }
  if ! nft list chain ip6 nat postrouting | grep -q "oifname \"${iface}\" .* ${subnet} .* masquerade"; then
    nft add rule ip6 nat postrouting oifname "${iface}" ip6 saddr ${subnet} masquerade
  fi
}

apply_nfqueue() {
  log "NFQUEUE: ip6/raw OUTPUT -> queue ${nfq} for skuid=${uid} SYN"
  nft list table ip6 raw >/dev/null 2>&1 || nft add table ip6 raw
  nft list chain ip6 raw output >/dev/null 2>&1 || \
    nft add chain ip6 raw output { type filter hook output priority -300\; }
  # удалить прежнее похожее правило (если было)
  local handle
  while handle=$(nft -a list chain ip6 raw output | awk '/queue/ && /skuid/ && /tcp/ && /syn/ {print $NF; exit}'); do
    nft delete rule ip6 raw output handle "${handle}" || break
  done
  nft add rule ip6 raw output meta skuid ${uid} tcp flags & syn == syn queue num ${nfq} bypass
}

apply_sysctl
apply_nat66
apply_nfqueue

touch /tmp/setup_done
log "Host prepared. Staying alive."
sleep infinity

