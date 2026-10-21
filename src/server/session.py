"""Lógica de una sesión de usuario en el gateway (capa de aplicación).

Doble capa de autenticación (RF2):
  Capa 1 (transporte): mTLS. Cuando este código arranca, el handshake ya validó
          que el certificado del dispositivo está firmado por nuestra CA y no
          está revocado. Aquí solo leemos quién es (`info["cn"]`).
  Capa 2 (aplicación): usuario + contraseña (Argon2id). Además exigimos que el
          usuario coincida con el CN del certificado y que ese certificado sea
          el vigente de ese usuario: un carnet robado no sirve para entrar como otro.

Si `info["tls"]` es False (servidor plano del benchmark) la capa 1 se omite.
"""
import threading
import time

from src import config
from src.protocol import ProtocolError, recv_frame, send_frame
from src.security.kdf import hash_password, verify_password

# Recursos corporativos accesibles por perfil (RF5 "perfiles de acceso").
ROLE_RESOURCES = {
    "PDI": {"correo", "docencia_virtual", "gestion_academica"},
    "PTGAS": {"correo", "gestion_administrativa", "repositorio_documental"},
    "Investigador": {"correo", "bases_datos_investigacion", "repositorio_documental"},
}

# Argon2id usa ~64 MB por verificación a propósito. Sin límite, 300 logins a la vez
# gastarían ~19 GB de RAM (y sería una vía de DoS). Dejamos pasar solo unas pocas a la vez.
_VERIFY_SLOTS = threading.BoundedSemaphore(config.MAX_CONCURRENT_VERIFICATIONS)

_dummy_hash = None


def _verify(password: str, stored_hash: str) -> bool:
    with _VERIFY_SLOTS:
        return verify_password(password, stored_hash)


def _burn_hash_time(password: str) -> None:
    """Gasta lo mismo que una verificación real, para que el tiempo no delate si el usuario existe."""
    global _dummy_hash
    if _dummy_hash is None:
        _dummy_hash = hash_password("dummy-password")
    _verify(password, _dummy_hash)


def _err(code: str, msg: str) -> dict:
    return {"status": "ERROR", "code": code, "msg": msg}


def make_session_handler(store, audit):
    """Devuelve el `handler(conn, addr, info)` que usa el ThreadedServer."""

    def handler(conn, addr, info):
        ip = addr[0]
        mode = "mTLS" if info["tls"] else "PLAIN"
        audit.event("CONNECT", ip=ip, mode=mode, cn=info.get("cn"), serial=info.get("serial"),
                    tls=info.get("version"), cipher=info.get("cipher"))
        username, reason = None, "closed"
        try:
            username = _authenticate(conn, ip, info, store, audit)
            if username is None:
                reason = "auth_failed"
                return
            reason = _serve(conn, ip, username, store, audit)
        except ProtocolError as exc:
            audit.event("PROTOCOL_ERROR", ip=ip, user=username, reason=str(exc))
            reason = "protocol_error"
        except (ConnectionError, TimeoutError, OSError):
            reason = "connection_lost"
        finally:
            audit.event("DISCONNECT", ip=ip, user=username, reason=reason)

    return handler


def _authenticate(conn, ip, info, store, audit):
    msg = recv_frame(conn)
    if msg.get("op") != "LOGIN":
        send_frame(conn, _err("EXPECTED_LOGIN", "Primero debe iniciar sesión"))
        return None
    username, password = msg.get("username"), msg.get("password")
    if not isinstance(username, str) or not isinstance(password, str):
        send_frame(conn, _err("BAD_REQUEST", "Formato inválido"))
        return None

    def fail(code, reason):
        audit.event("LOGIN_FAILED", ip=ip, user=username, reason=reason, cn=info.get("cn"))
        send_frame(conn, _err(code, "Credenciales inválidas"))  # mensaje genérico a propósito
        return None

    # Capa 1 reforzada: el usuario debe ser el dueño del certificado presentado.
    if info["tls"]:
        if info["cn"] != username:
            audit.event("UNAUTHORIZED", ip=ip, user=username, cn=info["cn"], reason="cn_mismatch")
            send_frame(conn, _err("AUTH_FAILED", "Credenciales inválidas"))
            return None
        if not store.is_cert_active(info["serial"], username):
            audit.event("UNAUTHORIZED", ip=ip, user=username, serial=info["serial"],
                        reason="cert_not_active")
            send_frame(conn, _err("AUTH_FAILED", "Credenciales inválidas"))
            return None

    user = store.get_user(username)
    if user is not None and store.is_locked(username):
        audit.event("LOGIN_BLOCKED", ip=ip, user=username)
        send_frame(conn, _err("LOCKED", "Cuenta bloqueada temporalmente"))
        return None
    if user is None:
        _burn_hash_time(password)
        return fail("AUTH_FAILED", "unknown_user")
    if not _verify(password, user["pw_hash"]):
        locked = store.register_failure(username)
        if locked:
            audit.event("ACCOUNT_LOCKED", ip=ip, user=username)
        return fail("AUTH_FAILED", "bad_password")

    store.reset_failures(username)
    audit.event("LOGIN_OK", ip=ip, user=username, role=user["role"], cn=info.get("cn"))
    send_frame(conn, {"status": "OK", "role": user["role"],
                      "msg": f"Bienvenido al gateway U-Secure [{user['role']}]"})
    return username


def _serve(conn, ip, username, store, audit) -> str:
    """Bucle de la sesión autenticada. Devuelve el motivo de cierre."""
    role = store.get_user(username)["role"]
    while True:
        msg = recv_frame(conn)
        op = msg.get("op")
        if op == "LOGOUT":
            audit.event("LOGOUT", ip=ip, user=username)
            send_frame(conn, {"status": "BYE", "msg": "Sesión cerrada; claves de sesión descartadas"})
            return "logout"
        if op == "MSG":
            data = str(msg.get("data", ""))
            send_frame(conn, {"status": "OK", "echo": data, "len": len(data)})
        elif op == "RESOURCE":
            name = str(msg.get("name", ""))
            if name in ROLE_RESOURCES[role]:
                audit.event("RESOURCE_OK", ip=ip, user=username, resource=name)
                send_frame(conn, {"status": "OK", "resource": name, "ts": int(time.time())})
            else:
                audit.event("UNAUTHORIZED", ip=ip, user=username, resource=name, reason="role_denied")
                send_frame(conn, _err("FORBIDDEN", f"El perfil {role} no puede acceder a {name}"))
        else:
            send_frame(conn, _err("BAD_OP", "Operación desconocida"))
