"""Hash de contraseñas con Argon2id (reutilizado de PAI-1).

Argon2id es un algoritmo lento y "caro en memoria" a propósito: así probar
millones de contraseñas robadas es inviable. La librería genera un salt
aleatorio distinto para cada usuario y lo guarda dentro del propio hash.
"""
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHash, VerifyMismatchError

_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    """Devuelve el hash Argon2id (con salt incluido) de la contraseña."""
    return _hasher.hash(password)


def verify_password(password: str, stored_hash: str) -> bool:
    """True si la contraseña coincide con el hash. La comparación es en tiempo constante."""
    try:
        return _hasher.verify(stored_hash, password)
    except (VerifyMismatchError, InvalidHash):
        return False
