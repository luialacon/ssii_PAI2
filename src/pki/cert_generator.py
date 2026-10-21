"""Punto de entrada de la opción 1 del menú: crea la PKI de U-Secure.

La lógica real vive en `src/pki/ca.py`; aquí solo se orquesta.
"""
from src.pki import ca


def setup_pki(force: bool = True) -> None:
    """Genera CA raíz, certificado del servidor y CRL vacía (RS1).

    Los usuarios se emiten aparte con `python -m src.pki.preload` (precarga) o
    mediante el registro por CSR (`src/client/register.py`).
    """
    ca.init_pki(force=force)
    print("[PKI] CA raíz (ECDSA P-384), certificado de servidor y CRL generados en ./certs/")


if __name__ == "__main__":
    setup_pki()
