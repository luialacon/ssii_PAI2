"""RS1 / RS2: PKI, mTLS estricto, solo TLS 1.3 y suites AEAD+PFS.

Cada test intenta "colarse" de una forma distinta y comprueba que el portero nos echa.
"""
import datetime
import socket
import ssl

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from src import config
from src.client.byod_client import ByodClient, build_client_context
from src.pki import ca
from tests.conftest import PASSWORD, events


def _connect(ctx, port):
    raw = socket.create_connection((config.HOST, port), timeout=5)
    return ctx.wrap_socket(raw, server_hostname=config.SERVER_HOSTNAME)


def _must_be_rejected(ctx, port, audit=None):
    """El servidor debe rechazar el handshake.

    En TLS 1.3 el cliente cree haber terminado antes que el servidor valide su
    certificado, así que el rechazo llega después: como excepción o como lectura
    vacía (conexión cerrada). Ambas valen; además comprobamos en el log de
    auditoría que fue el SERVIDOR quien lo rechazó.
    """
    import time
    before = len(events(audit, "HANDSHAKE_FAILED")) if audit else 0
    try:
        s = _connect(ctx, port)
        s.sendall(b"\x00\x00\x00\x02{}")
        got = s.recv(10)
        assert got == b"", "el servidor respondió a un cliente sin credenciales válidas"
    except (ssl.SSLError, ConnectionError, OSError):
        pass
    if audit:
        time.sleep(0.3)
        assert len(events(audit, "HANDSHAKE_FAILED")) > before


def test_handshake_is_tls13_with_allowed_aead_suite(gateway, client):
    c = client("pdi_user1")
    assert c.tls_version == "TLSv1.3"
    assert c.cipher in config.ALLOWED_CIPHERS


@pytest.mark.parametrize("version", [ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_1])
def test_obsolete_tls_versions_are_rejected(gateway, version):
    ctx = build_client_context("pdi_user1")
    ctx.minimum_version = ctx.maximum_version = version
    with pytest.raises((ssl.SSLError, ConnectionError, OSError)):
        _connect(ctx, gateway.bound_port)
    assert events(gateway.audit, "HANDSHAKE_FAILED")


def test_client_without_certificate_is_rejected(gateway):
    _must_be_rejected(build_client_context(alias=None), gateway.bound_port, gateway.audit)


def test_certificate_from_foreign_ca_is_rejected(gateway, tmp_path):
    """Un atacante crea su propia CA y se firma un carnet con el nombre de un usuario real."""
    evil_key = ec.generate_private_key(ec.SECP384R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Evil CA")])
    now = datetime.datetime.now(datetime.timezone.utc)
    evil_ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
               .public_key(evil_key.public_key()).serial_number(1)
               .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=1))
               .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
               .sign(evil_key, hashes.SHA256()))
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "pdi_user1")]))
            .issuer_name(name).public_key(key.public_key()).serial_number(2)
            .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=True)
            .sign(evil_key, hashes.SHA256()))
    crt, k = tmp_path / "evil.crt", tmp_path / "evil.key"
    crt.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    k.write_bytes(ca.key_to_pem(key))
    ctx = build_client_context(alias=None)
    ctx.load_cert_chain(crt, k)
    _must_be_rejected(ctx, gateway.bound_port, gateway.audit)


def test_client_rejects_server_with_untrusted_certificate(gateway, tmp_path):
    """mTLS es bidireccional: si el cliente no confía en la CA del servidor, no conecta."""
    ctx = build_client_context("pdi_user1")
    other = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # sin cargar nuestra CA
    other.minimum_version = other.maximum_version = ssl.TLSVersion.TLSv1_3
    other.load_cert_chain(config.CLIENTS_DIR / "pdi_user1" / "pdi_user1.crt",
                          config.CLIENTS_DIR / "pdi_user1" / "pdi_user1.key")
    with pytest.raises(ssl.SSLCertVerificationError):
        _connect(other, gateway.bound_port)
    assert ctx.verify_mode == ssl.CERT_REQUIRED


def test_revoked_certificate_is_rejected(gateway, store):
    """Revocamos el carnet de pas_user2: la CRL se recarga y el handshake falla."""
    c = ByodClient("pas_user2", port=gateway.bound_port)
    c.connect()
    c.close()  # antes de revocar funciona
    cert = x509.load_pem_x509_certificate((config.CLIENTS_DIR / "pas_user2" / "pas_user2.crt").read_bytes())
    ca.revoke(cert.serial_number)
    store.revoke_cert(format(cert.serial_number, "x"))
    _must_be_rejected(build_client_context("pas_user2"), gateway.bound_port, gateway.audit)


def _openssl_client(port, suites, extra=()):
    """Cliente OpenSSL real (independiente de Python) para probar el servidor desde fuera."""
    import shutil
    import subprocess
    exe = shutil.which("openssl")
    if not exe:
        pytest.skip("openssl no disponible")
    d = config.CLIENTS_DIR / "pdi_user1"
    cmd = [exe, "s_client", "-connect", f"127.0.0.1:{port}", "-tls1_3", "-ciphersuites", suites,
           "-CAfile", str(config.CA_CERT), "-cert", str(d / "pdi_user1.crt"), "-key", str(d / "pdi_user1.key"),
           "-servername", config.SERVER_HOSTNAME, "-verify_hostname", config.SERVER_HOSTNAME, *extra]
    return subprocess.run(cmd, input=b"", capture_output=True, timeout=20)


def test_unauthorised_suite_is_rejected_after_handshake(gateway):
    """Un cliente que SOLO ofrece AES-128 (AEAD+PFS, pero fuera de nuestra política) no obtiene servicio."""
    import time
    before = len(events(gateway.audit, "CIPHER_REJECTED"))
    r = _openssl_client(gateway.bound_port, "TLS_AES_128_GCM_SHA256")
    time.sleep(0.4)
    assert len(events(gateway.audit, "CIPHER_REJECTED")) == before + 1
    assert b"TLS_AES_128_GCM_SHA256" in r.stdout + r.stderr  # se negoció, y aun así se cortó


def test_openssl_client_gets_aes256_when_offered_both(gateway):
    r = _openssl_client(gateway.bound_port, "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384")
    assert b"TLS_AES_256_GCM_SHA384" in r.stdout + r.stderr  # preferencia del servidor
