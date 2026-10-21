"""Registro de auditoría: una línea JSON por evento, encadenadas por hash.

Cada línea guarda el hash SHA-256 de la anterior. Si alguien borra o edita una
línea, la cadena se rompe y `verify_chain()` lo detecta (inmutabilidad del log).
Eventos típicos: CONNECT, HANDSHAKE_FAILED, LOGIN_OK, LOGIN_FAILED, LOGOUT,
DISCONNECT, UNAUTHORIZED, REGISTER...  (RS4)
"""
import hashlib
import json
import threading
import time
from pathlib import Path

from src import config

GENESIS = "0" * 64


def _digest(prev: str, body: dict) -> str:
    return hashlib.sha256((prev + json.dumps(body, sort_keys=True, ensure_ascii=False)).encode()).hexdigest()


class AuditLog:
    def __init__(self, path=None, echo=False):
        self.path = Path(path or config.AUDIT_LOG)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.echo = echo
        self._lock = threading.Lock()
        self._prev = self._last_hash()

    def _last_hash(self) -> str:
        if not self.path.exists() or self.path.stat().st_size == 0:
            return GENESIS
        last = self.path.read_text(encoding="utf-8").strip().splitlines()[-1]
        return json.loads(last)["hash"]

    def event(self, event: str, **fields) -> None:
        with self._lock:
            body = {"ts": round(time.time(), 3), "event": event, **fields}
            h = _digest(self._prev, body)
            line = json.dumps({**body, "prev": self._prev, "hash": h}, ensure_ascii=False)
            with self.path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
            self._prev = h
            if self.echo:
                print(f"[AUDIT] {event} {fields}")


def verify_chain(path=None) -> tuple[bool, int]:
    """Recorre el log y comprueba la cadena. Devuelve (íntegra?, nº de líneas leídas)."""
    path = Path(path or config.AUDIT_LOG)
    prev, n = GENESIS, 0
    for line in path.read_text(encoding="utf-8").splitlines():
        rec = json.loads(line)
        h, p = rec.pop("hash"), rec.pop("prev")
        if p != prev or _digest(prev, rec) != h:
            return False, n
        prev, n = h, n + 1
    return True, n
