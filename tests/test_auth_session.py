"""RF2 / RF4: doble capa (mTLS + contraseña), perfiles de acceso, bloqueo y logout."""
import pytest

from tests.conftest import PASSWORD, events


def test_login_ok_and_message_roundtrip(client, audit):
    c = client("pdi_user1")
    reply = c.login("pdi_user1", PASSWORD)
    assert reply["status"] == "OK" and reply["role"] == "PDI"
    assert c.send_message("hola")["echo"] == "hola"
    assert any(e["user"] == "pdi_user1" for e in events(audit, "LOGIN_OK"))


def test_wrong_password_is_rejected_with_generic_message(client, audit):
    c = client("pdi_user2")
    reply = c.login("pdi_user2", "Equivocada#1")
    assert reply["status"] == "ERROR" and reply["msg"] == "Credenciales inválidas"
    assert any(e["reason"] == "bad_password" for e in events(audit, "LOGIN_FAILED"))


def test_stolen_certificate_cannot_login_as_someone_else(client, audit):
    """Capa 1 válida (carnet de pdi_user1) pero intenta entrar como inv_user1."""
    c = client("pdi_user1")
    reply = c.login("inv_user1", PASSWORD)
    assert reply["status"] == "ERROR"
    assert any(e["reason"] == "cn_mismatch" for e in events(audit, "UNAUTHORIZED"))


def test_role_based_resource_access(client, audit):
    c = client("inv_user1")
    c.login("inv_user1", PASSWORD)
    assert c.get_resource("bases_datos_investigacion")["status"] == "OK"
    denied = c.get_resource("gestion_academica")  # recurso de PDI
    assert denied["status"] == "ERROR" and denied["code"] == "FORBIDDEN"
    assert any(e["reason"] == "role_denied" for e in events(audit, "UNAUTHORIZED"))


def test_must_login_before_anything_else(client):
    c = client("pas_user1")
    assert c.send_message("sin login")["code"] == "EXPECTED_LOGIN"


def test_account_is_locked_after_too_many_failures(gateway, store, audit):
    from src import config
    from src.client.byod_client import ByodClient
    for _ in range(config.MAX_FAILED_ATTEMPTS):
        with ByodClient("inv_user2", port=gateway.bound_port) as c:
            c.login("inv_user2", "Mala#Clave1")
    with ByodClient("inv_user2", port=gateway.bound_port) as c:
        reply = c.login("inv_user2", PASSWORD)  # aunque ahora sea la correcta
    assert reply["code"] == "LOCKED"
    assert events(audit, "ACCOUNT_LOCKED")
    store.reset_failures("inv_user2")


def test_logout_closes_session_and_is_audited(client, audit):
    c = client("pas_user1")
    c.login("pas_user1", PASSWORD)
    assert c.logout()["status"] == "BYE"
    assert c.sock is None  # el túnel se desmontó
    assert any(e["user"] == "pas_user1" for e in events(audit, "LOGOUT"))
    assert any(e["reason"] == "logout" for e in events(audit, "DISCONNECT"))


def test_abrupt_disconnect_is_audited(gateway, audit):
    from src.client.byod_client import ByodClient
    c = ByodClient("pdi_user2", port=gateway.bound_port)
    c.connect()
    c.login("pdi_user2", PASSWORD)
    c.sock.close()  # corte sin logout
    import time
    time.sleep(0.5)
    assert any(e["reason"] in ("connection_lost", "closed") and e["user"] == "pdi_user2"
               for e in events(audit, "DISCONNECT"))
