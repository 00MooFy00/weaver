from __future__ import annotations
import subprocess
import tempfile
import errno
import os
from typing import Sequence, List
from ipaddress import IPv6Address, IPv6Network


def _run(args: Sequence[str]) -> None:
    subprocess.run(list(args), check=True)

def _run_ok(args: Sequence[str]) -> bool:
    return subprocess.run(list(args),
                          stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL).returncode == 0

def _cap(args: Sequence[str]) -> str:
    p = subprocess.run(list(args), check=False, capture_output=True, text=True)
    return (p.stdout or "") + (p.stderr or "")


# -------- iface detect --------

def detect_default_iface() -> str:
    for cmd in (
        ["ip", "-6", "route", "show", "default"],
        ["ip", "route", "show", "default"],
    ):
        text = _cap(cmd).strip()
        for line in text.splitlines():
            parts = line.split()
            if "dev" in parts:
                try:
                    idx = parts.index("dev")
                    return parts[idx + 1]
                except Exception:
                    continue
    raise RuntimeError("No default route iface detected")


# -------- IPv6 helpers --------

def ensure_ipv6_addresses(interface: str, addrs: List[IPv6Address]) -> None:
    have_text = _cap(["ip", "-6", "addr", "show", "dev", interface])
    have = set()
    for line in have_text.splitlines():
        line = line.strip()
        if line.startswith("inet6 "):
            try:
                addr = line.split()[1].split("/")[0]
                have.add(addr.lower())
            except Exception:
                pass
    for ip6 in addrs:
        s = str(ip6).lower()
        if s not in have:
            _run(["ip", "-6", "addr", "add", f"{s}/128", "dev", interface, "nodad"])


def generate_ipv6_hosts(subnet: IPv6Network, count: int) -> List[IPv6Address]:
    hosts: List[IPv6Address] = []
    base = int(subnet.network_address)
    for i in range(1, count + 1):
        ip_int = base + i
        ip = IPv6Address(ip_int)
        if ip not in subnet:
            break
        hosts.append(ip)
    return hosts

# -------- nftables --------

def purge_table(table: str) -> None:
    # тихо: нет - так нет
    if _run_ok(["nft", "list", "table", "inet", table]):
        subprocess.run(["nft", "flush", "table", "inet", table],
                       check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["nft", "delete", "table", "inet", table],
                       check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def ensure_table_chain(table: str, chain_out: str, policy_accept: bool) -> None:
    if not _run_ok(["nft", "list", "table", "inet", table]):
        _run(["nft", "add", "table", "inet", table])

    have_chain = _run_ok(["nft", "list", "chain", "inet", table, chain_out])
    if not have_chain:
        pol = "accept" if policy_accept else "drop"
        _run([
            "nft","add","chain","inet",table,chain_out,
            "{","type","filter","hook","output","priority","filter",";","policy",pol,";","}"
        ])
    else:
        # при необходимости можно поправить policy
        text = subprocess.run(["nft","list","chain","inet",table,chain_out],
                              check=False, capture_output=True, text=True).stdout or ""
        need = "policy accept" if policy_accept else "policy drop"
        if need not in text:
            pol = "accept" if policy_accept else "drop"
            _run(["nft","flush","chain","inet",table,chain_out])
            _run([
                "nft","add","chain","inet",table,chain_out,
                "{","type","filter","hook","output","priority","filter",";","policy",pol,";","}"
            ])

def ensure_v6_set(table: str, set_name: str) -> None:
    if not _run_ok(["nft","list","set","inet",table,set_name]):
        _run(["nft","add","set","inet",table,set_name,"{","type","ipv6_addr",";","}"])

def _delete_rules_ref_set(table: str, chain: str, set_name: str) -> None:
    """
    Удалить все правила в цепочке, которые ссылаются на @set_name.
    Используем вывод с handle'ами: `nft -a list chain inet <table> <chain>`.
    """
    try:
        cp = subprocess.run(
            ["nft", "-a", "list", "chain", "inet", table, chain],
            capture_output=True, text=True, check=True
        )
    except subprocess.CalledProcessError:
        return

    for line in cp.stdout.splitlines():
        if f"@{set_name}" in line:
            m = re.search(r"handle\s+(\d+)", line)
            if m:
                handle = m.group(1)
                _run(["nft", "delete", "rule", "inet", table, chain, "handle", handle])


def ensure_v6_interval_set(table: str, set_name: str, chain_for_cleanup: Optional[str] = None) -> None:
    """
    Гарантировать существование сета типа ipv6_addr с `flags interval`.
    Если сет уже есть, но без interval — удалим правила, удалим сет и создадим заново.
    """
    # Есть ли сет?
    exists = _run_ok(["nft", "list", "set", "inet", table, set_name])
    if exists:
        # Проверяем, не уже ли он interval
        cp = subprocess.run(
            ["nft", "list", "set", "inet", table, set_name],
            capture_output=True, text=True
        )
        if "flags interval" in cp.stdout:
            return
        # Приведём к interval: сперва уберём правила, которые на него ссылаются
        if chain_for_cleanup:
            _delete_rules_ref_set(table, chain_for_cleanup, set_name)
        # Затем удалим и пересоздадим сет
        _run(["nft", "delete", "set", "inet", table, set_name])

    # Создаём interval‑сет (idempotent: если уже есть — _run_ok просто вернёт False/True)
    _run_ok([
        "nft", "add", "set", "inet", table, set_name,
        "{", "type", "ipv6_addr", ";", "flags", "interval", ";", "}"
    ])


def replace_v6_set_from_subnets(
    table: str,
    set_name: str,
    subnets: List[str],
    chain_for_cleanup: str,
    nfqueue_num: int
) -> None:
    """
    Полностью заменить содержимое сета диапазонами (префиксами).
    Обеспечивает `flags interval`, очищает сет и заливает элементы чанками.
    В конце гарантирует наличие queue‑правила.
    """
    from weaver_manager.nft import ensure_queue_rule  # локальный импорт, чтобы избежать циклов

    ensure_v6_interval_set(table, set_name, chain_for_cleanup)

    # Чистим сет
    _run(["nft", "flush", "set", "inet", table, set_name])

    if not subnets:
        ensure_queue_rule(table, chain_for_cleanup, set_name, nfqueue_num)
        return

    # Размер чанка (как и в адресном варианте)
    try:
        chunk_sz = int(os.environ.get("WEAVER_NFT_CHUNK", "256"))
    except Exception:
        chunk_sz = 256
    chunk_sz = max(16, min(2048, chunk_sz))

    print(f"[manager] nft add prefixes in chunks: size={chunk_sz}, total={len(subnets)}")

    # Заливаем чанками; при E2BIG — через временный файл
    for i in range(0, len(subnets), chunk_sz):
        chunk = subnets[i:i + chunk_sz]
        cmd = ["nft", "add", "element", "inet", table, set_name, "{", ",".join(chunk), "}"]
        try:
            _run(cmd)
        except OSError as e:
            if e.errno != errno.E2BIG:
                raise
            payload = f"add element inet {table} {set_name} {{ {','.join(chunk)} }}\n"
            with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as tf:
                tf.write(payload)
                tf.flush()
                tmp = tf.name
            try:
                _run(["nft", "-f", tmp])
            finally:
                try:
                    os.unlink(tmp)
                except FileNotFoundError:
                    pass

    # Убедимся, что стоит правильное queue‑правило
    ensure_queue_rule(table, chain_for_cleanup, set_name, nfqueue_num)

def ensure_queue_rule(table: str, chain_out: str, set_name: str, nfqueue_num: int) -> None:
    text = _cap(["nft", "list", "chain", "inet", table, chain_out])
    signature = f"ip6 saddr @{set_name} tcp flags syn queue flags bypass to {nfqueue_num}"
    if signature in text:
        return
    _run([
        "nft","add","rule","inet",table,chain_out,
        "ip6","saddr",f"@{set_name}",
        "tcp","flags","syn",
        "queue","flags","bypass","to",str(nfqueue_num)
    ])

# back-compat wrapper если где-то ждут одним вызовом
def ensure_nfqueue_rule_set(
    table: str,
    chain_out: str,
    set_name: str,
    elems: List[str],
    nfqueue_num: int,
    policy_accept: bool = True,
) -> None:
    ensure_table_chain(table, chain_out, policy_accept=policy_accept)
    replace_v6_set_elems(table, set_name, elems)
    ensure_queue_rule(table, chain_out, set_name, nfqueue_num)
