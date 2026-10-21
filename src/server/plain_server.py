"""Servidor SIN cifrar, solo para el benchmark comparativo (RS3).

Usa exactamente la misma lógica de sesión y la misma concurrencia que el gateway.
Lo único que cambia es que no hay TLS: así la diferencia medida es el coste del cifrado.
NO es para producción: las contraseñas viajan en claro (y eso se enseña en el pcap).
"""
import os

from src import config
from src.server.audit import AuditLog
from src.server.net import ThreadedServer
from src.server.session import make_session_handler
from src.server.store import Store


def create_plain_server(host=config.HOST, port=config.PLAIN_PORT, store=None, audit=None):
    store = store or Store()
    audit = audit or AuditLog(os.environ.get("USECURE_AUDIT_LOG") or config.LOGS_DIR / "audit_plain.jsonl")
    return ThreadedServer(host, port, make_session_handler(store, audit),
                          context_factory=None, audit=audit, name="plain")


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Servidor SIN cifrar (solo benchmark)")
    ap.add_argument("--host", default=config.HOST)
    ap.add_argument("--port", type=int, default=config.PLAIN_PORT)
    a = ap.parse_args()
    srv = create_plain_server(a.host, a.port)
    print(f"[PLAIN] Servidor SIN CIFRAR (solo benchmark) en {a.host}:{a.port}")
    srv.serve_forever()
