import datetime
import os
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

CERTS_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "certs")

def generate_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)

def save_pem(data, filepath):
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "wb") as f:
        f.write(data)

def setup_pki():
    """Genera CA Raíz, Certificado de Servidor y Certificados de Cliente X.509v3 (RS1)"""
    # 1. Generar CA Raíz (U-Secure Root CA)
    ca_key = generate_key()
    ca_name = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Universidad U-Secure"),
        x509.NameAttribute(NameOID.COMMON_NAME, "U-Secure Root CA"),
    ])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    save_pem(ca_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    ), os.path.join(CERTS_DIR, "ca", "ca.key"))

    save_pem(ca_cert.public_bytes(serialization.Encoding.PEM), os.path.join(CERTS_DIR, "ca", "ca.crt"))

    # 2. Certificado del Servidor Gateway (TLS Server Authentication)
    server_key = generate_key()
    server_name = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Universidad U-Secure"),
        x509.NameAttribute(NameOID.COMMON_NAME, "gateway.usecure.es"),
    ])
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_name)
        .issuer_name(ca_name)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.DNSName("gateway.usecure.es")]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    save_pem(server_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    ), os.path.join(CERTS_DIR, "server", "server.key"))

    save_pem(server_cert.public_bytes(serialization.Encoding.PEM), os.path.join(CERTS_DIR, "server", "server.crt"))

    # 3. Certificados para Usuarios Preexistentes (mTLS Client Authentication) (RF1, RF5)
    users = ["pdi_user1", "pas_user1", "inv_user1"]
    for user in users:
        client_key = generate_key()
        client_name = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Universidad U-Secure"),
            x509.NameAttribute(NameOID.COMMON_NAME, user),
        ])
        client_cert = (
            x509.CertificateBuilder()
            .subject_name(client_name)
            .issuer_name(ca_name)
            .public_key(client_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=True)
            .sign(ca_key, hashes.SHA256())
        )

        user_dir = os.path.join(CERTS_DIR, "clients", user)
        save_pem(client_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        ), os.path.join(user_dir, f"{user}.key"))

        save_pem(client_cert.public_bytes(serialization.Encoding.PEM), os.path.join(user_dir, f"{user}.crt"))

    print("[PKI] Infraestructura de Clave Pública y Certificados X.509v3 generados con éxito.")

if __name__ == "__main__":
    setup_pki()