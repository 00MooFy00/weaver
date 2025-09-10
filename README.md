# Proxy Weaver(каркас)

**Назначение:** контейнеризированный комплекс на Python для автоматического развёртывания пула прокси (3proxy), управления IPv6‑адресами и правил netfilter/nftables, плюс наблюдаемость (NFQUEUE + /health).  
**Важно:** эта реализация **не** изменяет TCP/IP‑заголовки и **не** осуществляет «эмуляцию отпечатков ОС».

## Почему так
- Debian 12 использует nftables по умолчанию【Debian wiki: nftables】.  
- NFQUEUE — per‑namespace; чтобы видеть пакеты хоста, handler/manager запускаются в **host netns** через `nsenter` (при этом **без** `network_mode: host`)【PyPI NetfilterQueue docs】.
- 3proxy: сборка из исходников, фиксированная версия **0.9.5** (security fix)【3proxy releases】; перезагрузка конфига через **SIGUSR1**【3proxy man: SIGNALS】.
- Матчинг исходящих SYN от 3proxy делается по `meta skuid 1337` (UID процесса), `meta l4proto tcp`, `tcp flags` и отправкой в `queue num MIN-MAX fanout bypass`【nftables meta skuid / queue fanout】.
