"""RF1 (inmutabilidad), RS4 (log encadenado) y protocolo de mensajes."""
import json
import sqlite3
import socket
import struct

import pytest

from src import config
from src.protocol import ProtocolError, encode, recv_frame
from src.server.audit import AuditLog, verify_chain
from src.server.store import Store, UserExistsError


# --------------------------------------------------------------- inmutabilidad
def test_user_identity_cannot_be_modified(store):
    with pytest.raises(sqlite3.DatabaseError, match="IMMUTABLE"):
        with store._conn() as c:
            c.execute("UPDATE users SET role='PDI' WHERE username='inv_user1'")
    with pytest.raises(sqlite3.DatabaseError, match="IMMUTABLE"):
        with store._conn() as c:
            c.execute("UPDATE users SET username='otro' WHERE username='inv_user1'")


def test_users_and_certs_cannot_be_deleted(store):
    with pytest.raises(sqlite3.DatabaseError, match="IMMUTABLE"):
        with store._conn() as c:
            c.execute("DELETE FROM users WHERE username='inv_user1'")
    with pytest.raises(sqlite3.DatabaseError, match="IMMUTABLE"):
        with store._conn() as c:
            c.execute("DELETE FROM certs")


def test_public_key_cannot_be_modified_only_revoked(store):
    with pytest.raises(sqlite3.DatabaseError, match="IMMUTABLE"):
        with store._conn() as c:
            c.execute("UPDATE certs SET public_key='x' WHERE username='inv_user1'")


def test_duplicate_user_is_rejected(store):
    with pytest.raises(UserExistsError):
        store.add_user("inv_user1", "PDI", "a@b.es", "h", "ff", "fp", "pk")


def test_certificate_can_be_revoked_only_once(store, tmp_path):
    s = Store(tmp_path / "t.db")
    s.add_user("alice", "PDI", "a@u.es", "h", "01", "fp", "pk")
    s.revoke_cert("01")
    with pytest.raises(sqlite3.DatabaseError, match="IMMUTABLE"):
        s.revoke_cert("01")


# ------------------------------------------------------------ log encadenado
def test_audit_chain_is_valid_and_detects_tampering(tmp_path):
    log = AuditLog(tmp_path / "a.jsonl")
    for i in range(5):
        log.event("EVT", n=i)
    assert verify_chain(log.path) == (True, 5)
    lines = log.path.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[2])
    rec["n"] = 999  # alguien "arregla" un evento
    lines[2] = json.dumps(rec)
    log.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    ok, upto = verify_chain(log.path)
    assert not ok and upto == 2


def test_audit_chain_detects_deleted_line(tmp_path):
    log = AuditLog(tmp_path / "a.jsonl")
    for i in range(4):
        log.event("EVT", n=i)
    lines = log.path.read_text(encoding="utf-8").splitlines()
    del lines[1]
    log.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert verify_chain(log.path)[0] is False


def test_real_gateway_audit_log_is_intact(audit, gateway, client):
    c = client("pdi_user1")
    c.login("pdi_user1", config.PRELOAD_PASSWORD)
    c.logout()
    ok, n = verify_chain(audit.path)
    assert ok and n > 0


# ------------------------------------------------------------------ protocolo
class _Fake:
    def __init__(self, data):
        self.data = data

    def recv(self, n):
        chunk, self.data = self.data[:n], self.data[n:]
        return chunk


def test_framing_roundtrip_with_fragmented_reads():
    raw = encode({"op": "MSG", "data": "ñandú"})
    assert recv_frame(_Fake(raw)) == {"op": "MSG", "data": "ñandú"}


def test_oversized_frame_is_rejected_before_reading_body():
    header = struct.pack(">I", config.MAX_FRAME_BYTES + 1)
    with pytest.raises(ProtocolError):
        recv_frame(_Fake(header))


def test_invalid_json_is_rejected():
    body = b"no es json"
    with pytest.raises(ProtocolError):
        recv_frame(_Fake(struct.pack(">I", len(body)) + body))


def test_server_survives_garbage_after_valid_handshake(gateway, client, audit):
    c = client("pdi_user1")
    c.sock.sendall(struct.pack(">I", 5) + b"basura")
    import time
    time.sleep(0.3)
    from tests.conftest import events
    assert events(audit, "PROTOCOL_ERROR")
    c2 = client("pdi_user2")  # el servidor sigue atendiendo
    assert c2.login("pdi_user2", config.PRELOAD_PASSWORD)["status"] == "OK"
