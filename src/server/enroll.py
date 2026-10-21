"""Servicio de alta de usuarios (RF1): registro + emisión del certificado.

Un usuario nuevo todavía NO tiene certificado, así que no puede usar el gateway
mTLS. Este servicio usa TLS 1.3 solo-servidor (el cliente verifica al servidor,
pero no al revés). Flujo:
  1. El dispositivo genera su par de claves y una CSR (la clave privada no sale de él).
  2. Envía usuario + contraseña corporativa + código de alta + CSR por el canal TLS.
  3. El servidor valida, guarda el hash Argon2id y la CA firma la CSR.
  4. Devuelve el certificado. La identidad queda inmutable en la BD (triggers).
"""
import hmac
import re
import ssl

from cryptography.hazmat.primitives import serialization

from src import config
from src.pki import ca
from src.protocol import recv_frame, send_frame
from src.security.kdf import hash_password
from src.security.password_policy import WeakPasswordError, validate_password
from src.server.audit import AuditLog
from src.server.net import ThreadedServer
from src.server.store import Store, UserExistsError

_USER_RE = re.compile(r"^[a-z][a-z0-9_]{2,31}$")


def build_enroll_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(config.SERVER_CERT, config.SERVER_KEY)
    ctx.verify_mode = ssl.CERT_NONE
    ctx.num_tickets = 0
    return ctx


def _validate(msg: dict) -> str | None:
    """Devuelve un texto de error o None si la petición es válida."""
    u, role, email = msg.get("username"), msg.get("role"), msg.get("email", "")
    if msg.get("op") != "REGISTER":
        return "Operación no soportada"
    if not isinstance(u, str) or not _USER_RE.match(u):
        return "Usuario inválido (3-32 caracteres: minúsculas, números y _)"
    if role not in config.ROLES:
        return f"Rol inválido (use {', '.join(config.ROLES)})"
    if not isinstance(email, str) or "@" not in email:
        return "Email inválido"
    code = msg.get("enroll_code")
    if not isinstance(code, str) or not hmac.compare_digest(code, config.ENROLL_CODE):
        return "Código de alta incorrecto"
    try:
        validate_password(str(msg.get("password", "")), u)
    except WeakPasswordError as exc:
        return str(exc)
    return None


def make_enroll_handler(store: Store, audit: AuditLog):
    def handler(conn, addr, info):
        msg = recv_frame(conn)
        error = _validate(msg)
        if error:
            audit.event("REGISTER_FAILED", ip=addr[0], user=msg.get("username"), reason=error)
            send_frame(conn, {"status": "ERROR", "msg": error})
            return
        try:
            cert = ca.sign_csr(str(msg.get("csr_pem", "")).encode(), msg["username"], msg["role"])
            store.add_user(msg["username"], msg["role"], msg["email"], hash_password(msg["password"]),
                           format(cert.serial_number, "x"), ca.fingerprint(cert), ca.public_key_pem(cert))
        except UserExistsError:
            audit.event("REGISTER_FAILED", ip=addr[0], user=msg["username"], reason="duplicate")
            send_frame(conn, {"status": "ERROR", "msg": "El usuario ya existe"})
            return
        except ValueError as exc:
            audit.event("REGISTER_FAILED", ip=addr[0], user=msg["username"], reason=f"csr: {exc}")
            send_frame(conn, {"status": "ERROR", "msg": "CSR inválida"})
            return
        audit.event("REGISTER_OK", ip=addr[0], user=msg["username"], role=msg["role"],
                    serial=format(cert.serial_number, "x"))
        send_frame(conn, {"status": "OK", "cert_pem": cert.public_bytes(
            serialization.Encoding.PEM).decode()})
    return handler


def create_enroll_server(host=config.HOST, port=config.ENROLL_PORT, store=None, audit=None):
    store, audit = store or Store(), audit or AuditLog()
    return ThreadedServer(host, port, make_enroll_handler(store, audit),
                          context_factory=build_enroll_context, audit=audit, name="enroll")


if __name__ == "__main__":
    ca.init_pki(force=False)
    srv = create_enroll_server()
    print(f"[ENROLL] Alta de usuarios (TLS 1.3) en {config.HOST}:{config.ENROLL_PORT}")
    srv.serve_forever()
