"""Política de robustez de contraseñas (reutilizada de PAI-1).

Reglas: al menos 8 caracteres, mayúsculas, minúsculas, números, un carácter
especial, y que no sea igual al nombre de usuario. Ahora se aplica en el
servidor porque la contraseña viaja dentro del túnel TLS 1.3.
"""
import re

# Carácter especial = cualquiera que no sea letra ASCII ni dígito.
_SPECIAL_CHARS_RE = re.compile(r"[^A-Za-z0-9]")


class WeakPasswordError(ValueError):
    """Indica que la contraseña incumple la política; el mensaje explica la regla fallida."""


def validate_password(password: str, username: str) -> None:
    """Valida la contraseña contra la política de robustez.

    Args:
        password: contraseña en claro elegida por el usuario.
        username: nombre de usuario (la contraseña no puede coincidir con él).
    Raises:
        WeakPasswordError: ante la primera regla incumplida.
    """
    if len(password) < 8:
        raise WeakPasswordError("La contraseña debe tener al menos 8 caracteres.")
    if not any(c.islower() for c in password):
        raise WeakPasswordError("La contraseña debe incluir al menos una minúscula.")
    if not any(c.isupper() for c in password):
        raise WeakPasswordError("La contraseña debe incluir al menos una mayúscula.")
    if not any(c.isdigit() for c in password):
        raise WeakPasswordError("La contraseña debe incluir al menos un número.")
    if not _SPECIAL_CHARS_RE.search(password):
        raise WeakPasswordError("La contraseña debe incluir al menos un carácter especial.")
    if password.lower() == username.lower():
        raise WeakPasswordError("La contraseña no puede ser igual al nombre de usuario.")
