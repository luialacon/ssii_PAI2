"""Gateway VPN de U-Secure: TLS 1.3 + mTLS obligatorio (RS1, RS2, RF2, RF4).

Se arranca con `python -m src.server.gateway` (o la opción 2 del menú).
"""
import ssl
import threading

from src import config
from src.pki import ca
from src.server.audit import AuditLog
from src.server.net import ThreadedServer
from src.server.session import make_session_handler
from src.server.store import Store


def build_server_context() -> ssl.SSLContext:
    """Contexto TLS del gateway. Cada línea es un requisito del enunciado."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3   # RS2: SSLv3/TLS1.0/1.1/1.2 fuera
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(config.SERVER_CERT, config.SERVER_KEY)
    ctx.load_verify_locations(cafile=str(config.TRUST_BUNDLE))  # CA + CRL
    ctx.verify_mode = ssl.CERT_REQUIRED            # RS1: el cliente DEBE presentar certificado (mTLS)
    ctx.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF  # y no puede estar en la lista de revocados
    ctx.num_tickets = 0                            # sin tickets de reanudación: nada que sobreviva al cierre
    # Este Python usa OpenSSL 1.1.1: no expone set_ciphersuites() para TLS 1.3. Por eso (a) el
    # servidor impone SU preferencia (AES-256-GCM primero) y (b) net.py rechaza tras el handshake
    # cualquier suite fuera de config.ALLOWED_CIPHERS (CIPHER_REJECTED).
    ctx.options |= ssl.OP_CIPHER_SERVER_PREFERENCE
    return ctx


class ReloadingContext:
    """Recarga el contexto si la CRL cambia (así revocar un certificado surte efecto sin reiniciar)."""

    def __init__(self, builder=build_server_context):
        self._builder = builder
        self._lock = threading.Lock()
        self._mtime = None
        self._ctx = None

    def __call__(self) -> ssl.SSLContext:
        mtime = config.TRUST_BUNDLE.stat().st_mtime_ns
        with self._lock:
            if self._ctx is None or mtime != self._mtime:
                self._ctx, self._mtime = self._builder(), mtime
            return self._ctx


def create_gateway(host=config.HOST, port=config.PORT, store=None, audit=None) -> ThreadedServer:
    store = store or Store()
    audit = audit or AuditLog()
    return ThreadedServer(host, port, make_session_handler(store, audit),
                          context_factory=ReloadingContext(), audit=audit, name="gateway")


def start_gateway(host=config.HOST, port=config.PORT) -> None:
    ca.init_pki(force=False)
    audit = AuditLog(echo=False)
    gw = create_gateway(host, port, audit=audit)
    audit.event("GATEWAY_START", host=host, port=port, tls="TLSv1.3", mtls=True)
    print(f"[GATEWAY] TLS 1.3 + mTLS escuchando en {host}:{port}  (Ctrl+C para parar)")
    gw.serve_forever()
    audit.event("GATEWAY_STOP")
    print("[GATEWAY] Servidor detenido")


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Gateway TLS 1.3 + mTLS")
    ap.add_argument("--host", default=config.HOST)
    ap.add_argument("--port", type=int, default=config.PORT)
    a = ap.parse_args()
    start_gateway(a.host, a.port)
