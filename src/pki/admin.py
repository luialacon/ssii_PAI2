"""Operaciones de administración de la PKI desde la terminal.

    python -m src.pki.admin revoke pdi_user1     # anula el carnet de un usuario (robo/pérdida)
    python -m src.pki.admin list                 # muestra los certificados revocados

Revocar = (1) añadir el serial a la CRL de la CA y (2) marcar el certificado como revocado en la BD.
El gateway detecta que la CRL cambió y la recarga solo, sin reiniciar.
"""
import sys

from cryptography import x509

from src import config
from src.pki import ca
from src.server.audit import AuditLog
from src.server.store import Store


def revoke_user(username: str) -> int:
    path = config.CLIENTS_DIR / username / f"{username}.crt"
    cert = x509.load_pem_x509_certificate(path.read_bytes())
    ca.revoke(cert.serial_number)
    Store().revoke_cert(format(cert.serial_number, "x"))
    AuditLog().event("CERT_REVOKED", user=username, serial=format(cert.serial_number, "x"))
    return cert.serial_number


def main(argv: list[str]) -> int:
    if len(argv) == 2 and argv[0] == "revoke":
        serial = revoke_user(argv[1])
        print(f"[PKI] Certificado de '{argv[1]}' revocado (serial {serial:x}); CRL actualizada.")
        return 0
    if argv == ["list"]:
        print(ca._state_file().read_text() if ca._state_file().exists() else "[]")
        return 0
    print(__doc__)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
