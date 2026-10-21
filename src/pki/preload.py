"""Precarga de usuarios corporativos (RF5): cuentas + certificados listos para las pruebas de carga.

Crea N usuarios por rol (PDI, PTGAS, Investigador). Por defecto 100 de cada = 300 en total,
justo el número de empleados concurrentes del enunciado.

    python -m src.pki.preload --reset        # borra la BD y regenera todo
"""
import argparse
import concurrent.futures as cf
import shutil

from src import config
from src.pki import ca
from src.security.kdf import hash_password
from src.server.store import Store, UserExistsError

PREFIX = {"PDI": "pdi_user", "PTGAS": "pas_user", "Investigador": "inv_user"}


def preload_names(per_role: int) -> list[tuple[str, str]]:
    return [(f"{PREFIX[r]}{i}", r) for r in config.ROLES for i in range(1, per_role + 1)]


def bootstrap(per_role: int = 100, reset: bool = False) -> int:
    """Crea la PKI si falta y precarga usuarios. Con reset=True empieza de cero."""
    if reset:
        for suffix in ("", "-wal", "-shm"):
            config.DB_PATH.with_name(config.DB_PATH.name + suffix).unlink(missing_ok=True)
        shutil.rmtree(config.CERTS_DIR, ignore_errors=True)
    ca.init_pki(force=False)
    store = Store()
    names = [(u, r) for u, r in preload_names(per_role) if store.get_user(u) is None]
    # Argon2id es lento a propósito: lo repartimos en hilos para no tardar minutos.
    with cf.ThreadPoolExecutor() as pool:
        hashes = list(pool.map(lambda _: hash_password(config.PRELOAD_PASSWORD), names))
    for (username, role), pw_hash in zip(names, hashes):
        cert = ca.issue_client_cert(username, role)
        try:
            store.add_user(username, role, f"{username}@usecure.es", pw_hash,
                           format(cert.serial_number, "x"), ca.fingerprint(cert), ca.public_key_pem(cert))
        except UserExistsError:
            pass
    return len(names)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--per-role", type=int, default=100)
    ap.add_argument("--reset", action="store_true")
    args = ap.parse_args()
    n = bootstrap(args.per_role, args.reset)
    print(f"[PRELOAD] {n} usuarios nuevos creados (total en BD: {Store().count_users()})")
