# Proxy Weaver (safe / observe mode)

Контейнерный каркас для управления пулом прокси (3proxy) и наблюдения за исходящими SYN через nftables/NFQUEUE.  
**Без** подмены TCP-опций/TTL и прочих «маскировок»: только инфраструктура — адреса, конфиг, health, hot-reload.

---

## Архитектура

- **proxy** — контейнер с 3proxy, запускается **в host netns** через `nsenter -t 1 -n`, слушает диапазон портов, hot-reload конфига через `monitor "/run/3proxy/3proxy.ver"`.
- **manager** — одноразовая команда (идемпотентная): читает `config.yaml`, детерминированно генерит `/128` из заданного `/64`, навешивает недостающие адреса и снимает лишние, создаёт/обновляет nft-правила наблюдения, генерит `3proxy.cfg`, «тычёт» `monitor`.
- **handler** (опционально) — слушает очереди NFQUEUE **только observe**, ничего не переписывает, отдаёт `/health`.

> В dev на Docker Desktop/WSL: используем `nsenter` в **сетевой неймспейс хоста Docker (LinuxKit)**. Проверки делаем **через nsenter**, а не в своём WSL.

---

## Требования

- **Prod:** чистый Debian 12 с Docker Engine и **реальной** делегированной подсетью IPv6 (/64 или /48) + маршрутизация от провайдера.
- **Dev (Docker Desktop/WSL):** `nsenter` требует `CAP_SYS_ADMIN` и часто душится seccomp/apparmor → включены `privileged: true`, `seccomp=unconfined`, `apparmor=unconfined` в compose для удобства.  
  IPv6 из коробки **не маршрутизируется** (нет NAT66, нет делегированного префикса) — см. раздел «IPv4 vs IPv6».

---

## Установка и сборка

```bash
docker compose build

# поднять долгоживущие (handler опционален)
docker compose up -d proxy handler

# применить конфиг (идемпотентно), сгенерить /128, 3proxy.cfg и nft-правила
docker compose run --rm manager
```

## Конфигурация (config/config.yaml)
```Docker
global:
  state_file_path: /app/state/state.json
  proxy_config_path: /usr/local/3proxy/conf/3proxy.cfg
  ipv6_interface: eth0                 # интерфейс, куда навешиваем /128
  inbound_ipv4_address: "0.0.0.0"      # на что слушать IPv4-листенеры 3proxy
  log_level: INFO
  egress_bind: "auto"                  # "auto" | "off" — привязывать исходящий к /128 (флаг -e)
  pinned_ipv6: []                      # список /128, которые нельзя удалять при reconcile

observability:
  health_bind: "127.0.0.1:9090"
  health_interval_sec: 60

proxy_groups:
  - name: pool1
    ipv6_subnet: "2a01:4f8:c0c:1234::/64"
    count: 100                         # сколько прокси создать
    proxy_type: "http"                 # http | socks5
    port_range: { start: 30000, end: 30099 }
    nfqueue_num: 0                     # null/нет — не ставим queue-правило
    persona: null                      # совместимость; в safe-режиме не используется
```

## Проверка
```
# слушатели 3proxy
docker compose run --rm manager /app/bin/nsenter-net.sh ss -ltnp | grep 3proxy | head

# проверка навешанных /128
docker compose run --rm manager /app/bin/nsenter-net.sh ip -6 addr show dev eth0 | grep /128 | head

# проксирование (IPv4)
docker compose run --rm manager /app/bin/nsenter-net.sh \
  curl -x http://127.0.0.1:30000 https://api64.ipify.org -s

# nft-правило (если включен nfqueue_num)
docker compose run --rm manager /app/bin/nsenter-net.sh nft list table inet weaver

# лог 3proxy
docker compose run --rm manager sh -lc 'tail -n 120 /run/3proxy/3proxy.log'
```