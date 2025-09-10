import nftables  # libnftables Python bindings (из apt python3-nftables)
from typing import List

TABLE = "pw"
FAMILY = "inet"
CHAIN_OUT = "pw_out"

def _nft() -> nftables.Nftables:
    n = nftables.Nftables()
    n.set_json_output(True)
    return n

def apply_rules(skuid: int, queue_numbers: List[int]) -> None:
    """
    Создаёт таблицу/цепочку и правило: отправляет исходящие SYN от процесса с uid=skuid в диапазон NFQUEUE с fanout.
    Правило аккуратно матчится:
      - meta skuid <uid>
      - meta l4proto tcp (корректно для IPv6 с ext headers)
      - tcp flags & (syn|ack) == syn
      - queue num <min>-<max> fanout bypass  (bypass = пропускать пакеты, если handler недоступен)
    """
    n = _nft()
    # 1) ensure table & chain
    n.json_cmd({"nftables": [{"flush": {"table": {"family": FAMILY, "name": TABLE}}}]})
    n.json_cmd({"nftables": [{"delete": {"table": {"family": FAMILY, "name": TABLE}}}]})
    n.json_cmd({"nftables": [{"add": {"table": {"family": FAMILY, "name": TABLE}}}]})
    n.json_cmd({
        "nftables": [{
            "add": {
                "chain": {
                    "family": FAMILY,
                    "table": TABLE,
                    "name": CHAIN_OUT,
                    "hook": "output",
                    "prio": 0,
                    "type": "filter",
                    "policy": "accept"
                }
            }
        }]
    })
    if not queue_numbers:
        return
    qmin, qmax = min(queue_numbers), max(queue_numbers)
    # 2) add rule
    rule = {
        "nftables": [{
            "add": {
                "rule": {
                    "family": FAMILY,
                    "table": TABLE,
                    "chain": CHAIN_OUT,
                    "expr": [
                        {"match": {"left": {"meta": {"key": "skuid"}}, "op": "==", "right": skuid}},
                        {"match": {"left": {"meta": {"key": "l4proto"}}, "op": "==", "right": "tcp"}},
                        {"match": {"left": {"bitwise": {
                            "sreg": {"payload": {"protocol": "tcp", "field": "flags"}},
                            "op": "&",
                            "data": 0x12  # SYN(0x02)|ACK(0x10)
                        }}, "op": "==", "right": 0x02}},
                        {"queue": {"num": qmin, "to": qmax, "flags": ["fanout", "bypass"]}}
                    ]
                }
            }
        }]
    }
    rc, out, err = n.json_cmd(rule)
    if rc != 0:
        raise RuntimeError(f"nft rule apply failed: {err}")
