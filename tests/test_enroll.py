"""RF1: registro de usuarios con emisión de certificado por CSR."""
import pytest

from src import config
from src.client.byod_client import ByodClient
from src.client.register import register_user

GOOD_PW = "Nueva#Clave2026"


def _register(enroll_server, **kw):
    args = dict(username="nuevo_user", password=GOOD_PW, role="PDI", email="n@usecure.es",
                enroll_code=config.ENROLL_CODE, port=enroll_server.bound_port)
    args.update(kw)
    return register_user(**args)


def test_registration_issues_certificate_and_user_can_log_in(enroll_server, gateway):
    reply = _register(enroll_server)
    assert reply["status"] == "OK"
    with ByodClient("nuevo_user", port=gateway.bound_port) as c:  # mTLS con el carnet recién emitido
        assert c.login("nuevo_user", GOOD_PW)["status"] == "OK"


def test_private_key_never_leaves_the_device(enroll_server):
    """El servidor no tiene la clave: solo la CSR. El certificado devuelto no contiene clave privada."""
    reply = _register(enroll_server, username="otro_user")
    assert "PRIVATE KEY" not in reply["cert_pem"]
    assert (config.CLIENTS_DIR / "otro_user" / "otro_user.key").exists()


def test_duplicate_username_is_rejected(enroll_server):
    _register(enroll_server, username="dup_user")
    assert _register(enroll_server, username="dup_user")["status"] == "ERROR"


@pytest.mark.parametrize("kw,fragment", [
    ({"password": "corta"}, "8 caracteres"),
    ({"enroll_code": "mal"}, "Código"),
    ({"role": "Rector"}, "Rol"),
    ({"username": "Mal Nombre!"}, "Usuario"),
])
def test_invalid_registrations_are_rejected(enroll_server, kw, fragment):
    reply = _register(enroll_server, **{"username": "x_user", **kw})
    assert reply["status"] == "ERROR" and fragment in reply["msg"]


def test_ca_refuses_csr_with_another_common_name():
    """Un usuario no puede pedir un certificado a nombre de otro."""
    from src.pki import ca
    key = ca.new_key()
    csr = ca.make_csr("pdi_user1", "PDI", key)
    with pytest.raises(ValueError):
        ca.sign_csr(csr, "inv_user1", "Investigador")
