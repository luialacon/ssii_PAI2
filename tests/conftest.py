"""Fixtures de pytest: una PKI, una BD y un gateway TEMPORALES.

Los tests nunca tocan tu ./certs ni tu BD real: redirigen las rutas de `config`
a una carpeta temporal y levantan el gateway en un puerto libre.
"""
import pytest

from src import config
from src.client.byod_client import ByodClient
from src.pki import preload
from src.server.audit import AuditLog
from src.server.enroll import create_enroll_server
from src.server.gateway import create_gateway
from src.server.store import Store

PASSWORD = config.PRELOAD_PASSWORD


@pytest.fixture(scope="session")
def env(tmp_path_factory):
    root = tmp_path_factory.mktemp("pai2")
    patch = {
        "CERTS_DIR": root / "certs", "CA_DIR": root / "certs" / "ca",
        "SERVER_DIR": root / "certs" / "server", "CLIENTS_DIR": root / "certs" / "clients",
        "CA_CERT": root / "certs" / "ca" / "ca.crt", "CA_KEY": root / "certs" / "ca" / "ca.key",
        "CRL_FILE": root / "certs" / "ca" / "ca.crl",
        "TRUST_BUNDLE": root / "certs" / "ca" / "ca_bundle.pem",
        "SERVER_CERT": root / "certs" / "server" / "server.crt",
        "SERVER_KEY": root / "certs" / "server" / "server.key",
        "DATA_DIR": root / "data", "DB_PATH": root / "data" / "test.db",
        "LOGS_DIR": root / "logs", "AUDIT_LOG": root / "logs" / "audit.jsonl",
    }
    saved = {k: getattr(config, k) for k in patch}
    for k, v in patch.items():
        setattr(config, k, v)
    preload.bootstrap(per_role=2)  # pdi_user1/2, pas_user1/2, inv_user1/2
    yield root
    for k, v in saved.items():
        setattr(config, k, v)


@pytest.fixture(scope="session")
def audit(env):
    return AuditLog()


@pytest.fixture(scope="session")
def store(env):
    return Store()


@pytest.fixture(scope="session")
def gateway(env, store, audit):
    gw = create_gateway(port=0, store=store, audit=audit).start()
    yield gw
    gw.stop()


@pytest.fixture(scope="session")
def enroll_server(env, store, audit):
    srv = create_enroll_server(port=0, store=store, audit=audit).start()
    yield srv
    srv.stop()


@pytest.fixture
def client(gateway):
    """Fábrica de clientes ya conectados: client('pdi_user1')."""
    made = []

    def make(alias):
        c = ByodClient(alias, port=gateway.bound_port)
        c.connect()
        made.append(c)
        return c

    yield make
    for c in made:
        c.close()


def events(audit, name):
    """Eventos del log de auditoría con ese nombre (para comprobar RS4)."""
    import json
    return [json.loads(line) for line in audit.path.read_text(encoding="utf-8").splitlines()
            if json.loads(line)["event"] == name]
