from __future__ import annotations
import json, os, threading, time, logging, sys
from types import SimpleNamespace
from typing import Dict, List, Optional
import yaml

from .health import start_health_server
from .randomizer import run_nfqueue_randomizer

# ------------------------ Глобали/состояние ------------------------

CONFIG_PATH = "/app/config/config.yaml"

# параметры handler
ON_ERROR = "accept"
HEALTH_HOST = os.environ.get("WEAVER_HANDLER_HEALTH_HOST", "0.0.0.0")
HEALTH_PORT = int(os.environ.get("WEAVER_HANDLER_HEALTH_PORT", "8081"))
HEALTH_WINDOW_SEC = int(os.environ.get("WEAVER_HANDLER_HEALTH_WINDOW_SEC", "60"))

# реестры персон
persona_by_name: Dict[str, SimpleNamespace] = {}
PERSONA_POOL: List[SimpleNamespace] = []
PERSONA_WEIGHTS: Dict[str, float] = {}

# метрики
_last_activity: Dict[int, float] = {}
_persona_hits: Dict[str, int] = {}

# служебное
_start_ts = time.time()


# ------------------------ Логирование ------------------------

class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "asctime": time.strftime("%Y-%m-%d %H:%M:%S"),
            "levelname": record.levelname,
            "name": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)

def setup_logging():
    h = logging.StreamHandler(sys.stdout)
    h.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [h]
    root.setLevel(logging.INFO)


# ------------------------ Загрузка конфига ------------------------

def load_config(path: Optional[str] = None) -> dict:
    """
    Читает YAML и заполняет:
      - ON_ERROR, HEALTH_WINDOW_SEC
      - persona_by_name
      - PERSONA_POOL, PERSONA_WEIGHTS
    """
    global ON_ERROR, HEALTH_WINDOW_SEC
    global persona_by_name, PERSONA_POOL, PERSONA_WEIGHTS
    global CONFIG_PATH

    if path is None:
        path = os.environ.get("WEAVER_CONFIG") or CONFIG_PATH

    with open(path, "r") as f:
        data = yaml.safe_load(f) or {}

    g = data.get("global", {}) or {}
    h = g.get("handler", {}) or {}

    ON_ERROR = str(h.get("on_error", "accept")).lower()
    try:
        HEALTH_WINDOW_SEC = int(h.get("health_window_sec", 60))
    except Exception:
        HEALTH_WINDOW_SEC = 60

    # personas -> persona_by_name
    persona_by_name.clear()
    raw_personas = data.get("personas", {}) or {}
    for name, spec in raw_personas.items():
        try:
            ttl = int(spec.get("ttl", 64))
        except Exception:
            ttl = 64
        try:
            window_size = int(spec.get("window_size", 65535))
        except Exception:
            window_size = 65535

        layout = []
        for it in (spec.get("tcp_options_layout", []) or []):
            opt_name = str(it.get("name"))
            val = it.get("value", None)
            if val is not None:
                val = str(val)
            layout.append(SimpleNamespace(name=opt_name, value=val))

        persona_by_name[name] = SimpleNamespace(
            name=name, ttl=ttl, window_size=window_size, tcp_options_layout=layout
        )

    # Пул рандомизации персон наших:
    ref_names = [
        gspec.get("persona")
        for gspec in (data.get("proxy_groups", []) or [])
        if gspec.get("persona") in persona_by_name
    ]
    default_pool = list(dict.fromkeys(ref_names)) or list(persona_by_name.keys())
    pool_names = h.get("persona_pool") or default_pool

    PERSONA_POOL.clear()
    PERSONA_POOL.extend([persona_by_name[n] for n in pool_names if n in persona_by_name])

    raw_weights = h.get("persona_weights", {}) or {}
    PERSONA_WEIGHTS.clear()
    for n in pool_names:
        if n in persona_by_name:
            try:
                PERSONA_WEIGHTS[n] = float(raw_weights.get(n, 1.0))
            except Exception:
                PERSONA_WEIGHTS[n] = 1.0

    logging.getLogger("handler").info("Random persona pool: %s", [p.name for p in PERSONA_POOL])
    return data


# ------------------------ Health‑метрики ------------------------

def _on_activity(queue_num: int, persona_name: Optional[str]) -> None:
    _last_activity[queue_num] = time.time()
    if persona_name:
        _persona_hits[persona_name] = _persona_hits.get(persona_name, 0) + 1

def _health_state() -> dict:
    now = time.time()
    queues = sorted({0})
    status = {
        "uptime_sec": int(now - _start_ts),
        "on_error": ON_ERROR,
        "health_window_sec": HEALTH_WINDOW_SEC,
        "queues": {str(q): {
            "last_activity_ts": int(_last_activity.get(q, 0)),
            "alive": (_last_activity.get(q, 0) > 0) and ((now - _last_activity[q]) <= HEALTH_WINDOW_SEC),
        } for q in queues},
        "persona_pool": [p.name for p in PERSONA_POOL],
        "persona_weights": PERSONA_WEIGHTS,
        "persona_hits": dict(sorted(_persona_hits.items())),
    }
    return status


# ------------------------ Выбор персоны ------------------------

def _choose_persona():
    if not PERSONA_POOL:
        return None
    if PERSONA_WEIGHTS:
        names = [p.name for p in PERSONA_POOL]
        weights = [float(PERSONA_WEIGHTS.get(n, 1.0)) for n in names]
        return __import__("random").choices(PERSONA_POOL, weights=weights, k=1)[0]
    return __import__("random").choice(PERSONA_POOL)


# ------------------------ Точка входа ------------------------

def main():
    setup_logging()
    log = logging.getLogger("handler")

    load_config()
    log.info("handler starting...")

    # health‑сервер в отдельном потоке
    th = threading.Thread(target=start_health_server, args=(_health_state, "0.0.0.0", HEALTH_PORT), daemon=True)
    th.start()

    # Запуск рандомизатора (только очередь 0 — как в nft)
    log.info("Random persona pool: %s", [p.name for p in PERSONA_POOL])
    try:
        run_nfqueue_randomizer(queues=[0],
                               choose_persona=_choose_persona,
                               on_activity=_on_activity,
                               logger=log)
    except KeyboardInterrupt:
        pass
