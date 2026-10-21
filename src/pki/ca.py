"""Autoridad de Certificación (CA) interna de U-Secure.

Es la "oficina que fabrica y firma carnets digitales" (certificados X.509 v3):
  - crea la CA raíz (se firma a sí misma),
  - emite el certificado del servidor y los de cada usuario/dispositivo,
  - firma CSR (peticiones de certificado) para que la clave privada del
    usuario NUNCA salga de su dispositivo,
  - revoca certificados y publica la CRL (lista negra de carnets anulados).

Requisitos: RS1 (PKI y mTLS), RF1 (emisión ligada al registro).
"""
import datetime
import json
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from src import config

_CRL_DAYS = 30


def _state_file() -> Path:
    """Libro de revocaciones de la CA (se calcula al usar, no al importar)."""
    return config.CA_DIR / "revoked.json"


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _write(path: Path, data: bytes, secret: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    if secret:
        try:
            os.chmod(path, 0o600)  # en Windows no tiene efecto, en Linux protege la clave
        except OSError:
            pass


def key_to_pem(key) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def new_key(curve=ec.SECP256R1):
    """Genera una clave de curva elíptica (ECDSA). P-384 para CA/servidor, P-256 para usuarios."""
    return ec.generate_private_key(curve())


def _name(common_name: str, ou: str | None = None) -> x509.Name:
    attrs = [x509.NameAttribute(NameOID.ORGANIZATION_NAME, config.ORG_NAME)]
    if ou:
        attrs.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou))
    attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, common_name))
    return x509.Name(attrs)


# ----------------------------------------------------------------- CA raíz
def create_ca() -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    """Crea la CA raíz autofirmada. path_length=0: solo puede firmar hojas, no otras CA."""
    key = new_key(ec.SECP384R1)
    name = _name(config.CA_COMMON_NAME)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now() - datetime.timedelta(minutes=5))
        .not_valid_after(_now() + datetime.timedelta(days=config.CA_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA384())
    )
    _write(config.CA_KEY, key_to_pem(key), secret=True)
    _write(config.CA_CERT, cert.public_bytes(serialization.Encoding.PEM))
    return cert, key


def load_ca() -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    cert = x509.load_pem_x509_certificate(config.CA_CERT.read_bytes())
    key = serialization.load_pem_private_key(config.CA_KEY.read_bytes(), password=None)
    return cert, key


# ----------------------------------------------------------------- emisión
def _leaf_builder(subject: x509.Name, public_key, ca_cert, days: int):
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now() - datetime.timedelta(minutes=5))
        .not_valid_after(_now() + datetime.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
            critical=False,
        )
        .add_extension(
            x509.CRLDistributionPoints([x509.DistributionPoint(
                full_name=[x509.UniformResourceIdentifier("http://crl.usecure.es/ca.crl")],
                relative_name=None, reasons=None, crl_issuer=None)]),
            critical=False,
        )
    )


def issue_server_cert() -> x509.Certificate:
    """Certificado del gateway: EKU serverAuth y SAN con los nombres por los que se le llama."""
    ca_cert, ca_key = load_ca()
    key = new_key(ec.SECP384R1)
    import ipaddress
    cert = (
        _leaf_builder(_name(config.SERVER_HOSTNAME), key.public_key(), ca_cert, config.LEAF_DAYS)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(config.SERVER_HOSTNAME), x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
            ]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA384())
    )
    _write(config.SERVER_KEY, key_to_pem(key), secret=True)
    _write(config.SERVER_CERT, cert.public_bytes(serialization.Encoding.PEM))
    return cert


def make_csr(username: str, role: str, key) -> bytes:
    """Lo ejecuta el DISPOSITIVO del usuario: pide un carnet sin enviar su clave privada."""
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(_name(username, role))
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM)


def sign_csr(csr_pem: bytes, username: str, role: str) -> x509.Certificate:
    """La CA firma una CSR. Comprueba la firma de la CSR y que el CN pedido sea el usuario."""
    csr = x509.load_pem_x509_csr(csr_pem)
    if not csr.is_signature_valid:
        raise ValueError("La CSR tiene una firma inválida")
    cns = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if len(cns) != 1 or cns[0].value != username:
        raise ValueError("El CN de la CSR no coincide con el usuario")
    ca_cert, ca_key = load_ca()
    # Ignoramos cualquier extensión que venga en la CSR: la CA decide EKU, KeyUsage, etc.
    return (
        _leaf_builder(_name(username, role), csr.public_key(), ca_cert, config.LEAF_DAYS)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=True)
        .sign(ca_key, hashes.SHA384())
    )


def issue_client_cert(username: str, role: str) -> x509.Certificate:
    """Emisión "administrativa" (precarga RF5): genera clave + CSR + certificado en el momento."""
    key = new_key(ec.SECP256R1)
    cert = sign_csr(make_csr(username, role, key), username, role)
    user_dir = config.CLIENTS_DIR / username
    _write(user_dir / f"{username}.key", key_to_pem(key), secret=True)
    _write(user_dir / f"{username}.crt", cert.public_bytes(serialization.Encoding.PEM))
    return cert


# ------------------------------------------------------------- revocación
def _load_revoked() -> list[dict]:
    if _state_file().exists():
        return json.loads(_state_file().read_text())
    return []


def rebuild_crl() -> None:
    """Regenera la CRL y el "bundle" (CA + CRL) que cargan servidor y pruebas."""
    ca_cert, ca_key = load_ca()
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(_now() - datetime.timedelta(minutes=5))
        .next_update(_now() + datetime.timedelta(days=_CRL_DAYS))
    )
    for entry in _load_revoked():
        builder = builder.add_revoked_certificate(
            x509.RevokedCertificateBuilder()
            .serial_number(int(entry["serial"], 16))
            .revocation_date(datetime.datetime.fromisoformat(entry["date"]))
            .add_extension(x509.CRLReason(x509.ReasonFlags.key_compromise), critical=False)
            .build()
        )
    crl = builder.sign(ca_key, hashes.SHA384())
    crl_pem = crl.public_bytes(serialization.Encoding.PEM)
    _write(config.CRL_FILE, crl_pem)
    _write(config.TRUST_BUNDLE, config.CA_CERT.read_bytes() + crl_pem)


def revoke(serial: int) -> None:
    """Anula un certificado (carnet robado/perdido) y republica la CRL."""
    revoked = _load_revoked()
    hex_serial = format(serial, "x")
    if all(e["serial"] != hex_serial for e in revoked):
        revoked.append({"serial": hex_serial, "date": _now().isoformat()})
        _write(_state_file(), json.dumps(revoked, indent=2).encode())
    rebuild_crl()


def fingerprint(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


def public_key_pem(cert: x509.Certificate) -> str:
    return cert.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()


def init_pki(force: bool = False) -> None:
    """Crea CA + certificado de servidor + CRL vacía. Si ya existe, no toca nada salvo force."""
    if config.CA_CERT.exists() and config.SERVER_CERT.exists() and not force:
        return
    create_ca()
    issue_server_cert()
    _write(_state_file(), b"[]")
    rebuild_crl()
