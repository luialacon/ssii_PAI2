"""Base de datos de usuarios y certificados (SQLite).

Inmutabilidad (RF1): la propia base de datos impide con *triggers* modificar la
identidad de un usuario (username, rol, fecha de alta) y la clave pública de un
certificado. Cambiar la identidad solo es posible por el camino explícito:
revocar el certificado y emitir uno nuevo (nueva fila en `certs`).
"""
import sqlite3
import time
from contextlib import closing

from src import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    username        TEXT PRIMARY KEY,
    role            TEXT NOT NULL,
    email           TEXT NOT NULL,
    pw_hash         TEXT NOT NULL,
    created_at      REAL NOT NULL,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until    REAL NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS certs (
    serial       TEXT PRIMARY KEY,          -- hex
    username     TEXT NOT NULL REFERENCES users(username),
    fingerprint  TEXT NOT NULL,
    public_key   TEXT NOT NULL,
    issued_at    REAL NOT NULL,
    revoked_at   REAL                        -- NULL = vigente
);
-- Identidad inmutable: no se puede cambiar ni borrar un usuario ni cambiar su rol.
CREATE TRIGGER IF NOT EXISTS users_immutable_identity
BEFORE UPDATE OF username, role, created_at ON users
BEGIN SELECT RAISE(ABORT, 'IMMUTABLE: la identidad del usuario no se puede modificar'); END;
CREATE TRIGGER IF NOT EXISTS users_no_delete
BEFORE DELETE ON users
BEGIN SELECT RAISE(ABORT, 'IMMUTABLE: los usuarios no se pueden borrar'); END;
-- Certificado inmutable: solo se permite marcarlo como revocado (una vez).
CREATE TRIGGER IF NOT EXISTS certs_immutable
BEFORE UPDATE OF serial, username, fingerprint, public_key, issued_at ON certs
BEGIN SELECT RAISE(ABORT, 'IMMUTABLE: el certificado y su clave pública no se pueden modificar'); END;
CREATE TRIGGER IF NOT EXISTS certs_revoke_once
BEFORE UPDATE OF revoked_at ON certs WHEN OLD.revoked_at IS NOT NULL
BEGIN SELECT RAISE(ABORT, 'IMMUTABLE: el certificado ya estaba revocado'); END;
CREATE TRIGGER IF NOT EXISTS certs_no_delete
BEFORE DELETE ON certs
BEGIN SELECT RAISE(ABORT, 'IMMUTABLE: los certificados no se pueden borrar'); END;
"""


class UserExistsError(Exception):
    pass


class Store:
    """Acceso a la BD. Abre una conexión corta por operación (seguro entre hilos)."""

    def __init__(self, path=None):
        self.path = str(path or config.DB_PATH)
        config.DATA_DIR.mkdir(parents=True, exist_ok=True)
        with closing(self._conn()) as c:
            c.execute("PRAGMA journal_mode=WAL")
            c.executescript(SCHEMA)
            c.commit()

    def _conn(self) -> sqlite3.Connection:
        c = sqlite3.connect(self.path, timeout=30)
        c.row_factory = sqlite3.Row
        return c

    # ---------------------------------------------------------- altas
    def add_user(self, username, role, email, pw_hash, serial, fingerprint, public_key):
        """Alta atómica: usuario + su primer certificado, o nada."""
        now = time.time()
        with closing(self._conn()) as c:
            try:
                c.execute("INSERT INTO users(username, role, email, pw_hash, created_at) "
                          "VALUES (?,?,?,?,?)", (username, role, email, pw_hash, now))
                c.execute("INSERT INTO certs(serial, username, fingerprint, public_key, issued_at) "
                          "VALUES (?,?,?,?,?)", (serial, username, fingerprint, public_key, now))
                c.commit()
            except sqlite3.IntegrityError as exc:
                c.rollback()
                raise UserExistsError(username) from exc

    def add_cert(self, username, serial, fingerprint, public_key):
        """Re-emisión: nuevo certificado para un usuario existente (el anterior debe revocarse)."""
        with closing(self._conn()) as c:
            c.execute("INSERT INTO certs(serial, username, fingerprint, public_key, issued_at) "
                      "VALUES (?,?,?,?,?)", (serial, username, fingerprint, public_key, time.time()))
            c.commit()

    def revoke_cert(self, serial: str) -> None:
        with closing(self._conn()) as c:
            c.execute("UPDATE certs SET revoked_at=? WHERE serial=?", (time.time(), serial))
            c.commit()

    # ------------------------------------------------------ consultas
    def get_user(self, username):
        with closing(self._conn()) as c:
            return c.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()

    def is_cert_active(self, serial: str, username: str) -> bool:
        with closing(self._conn()) as c:
            row = c.execute("SELECT revoked_at FROM certs WHERE serial=? AND username=?",
                            (serial, username)).fetchone()
        return row is not None and row["revoked_at"] is None

    def count_users(self) -> int:
        with closing(self._conn()) as c:
            return c.execute("SELECT COUNT(*) FROM users").fetchone()[0]

    # --------------------------------------------- bloqueo de cuentas
    def is_locked(self, username) -> bool:
        row = self.get_user(username)
        return row is not None and row["locked_until"] > time.time()

    def register_failure(self, username) -> bool:
        """Cuenta un fallo; si llega al límite bloquea la cuenta. Devuelve True si quedó bloqueada."""
        with closing(self._conn()) as c:
            row = c.execute("SELECT failed_attempts FROM users WHERE username=?",
                            (username,)).fetchone()
            if row is None:
                return False
            fails = row["failed_attempts"] + 1
            locked = 0.0
            if fails >= config.MAX_FAILED_ATTEMPTS:
                locked, fails = time.time() + config.LOCKOUT_SECONDS, 0
            c.execute("UPDATE users SET failed_attempts=?, locked_until=? WHERE username=?",
                      (fails, locked, username))
            c.commit()
            return locked > 0

    def reset_failures(self, username) -> None:
        with closing(self._conn()) as c:
            c.execute("UPDATE users SET failed_attempts=0, locked_until=0 WHERE username=?",
                      (username,))
            c.commit()
