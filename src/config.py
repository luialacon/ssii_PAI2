"""Configuración central del proyecto PAI-2 BYODSEC.

Todas las rutas, puertos y límites de seguridad viven aquí para que ningún otro
módulo tenga "números mágicos" repartidos por el código.
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# --- Rutas de la PKI (las claves privadas NO se versionan, ver .gitignore) ---
CERTS_DIR = BASE_DIR / "certs"
CA_DIR = CERTS_DIR / "ca"
SERVER_DIR = CERTS_DIR / "server"
CLIENTS_DIR = CERTS_DIR / "clients"
CA_CERT = CA_DIR / "ca.crt"
CA_KEY = CA_DIR / "ca.key"
CRL_FILE = CA_DIR / "ca.crl"            # lista de certificados revocados (PEM)
TRUST_BUNDLE = CA_DIR / "ca_bundle.pem"  # CA + CRL: es lo que carga OpenSSL para validar
SERVER_CERT = SERVER_DIR / "server.crt"
SERVER_KEY = SERVER_DIR / "server.key"

# --- Datos y evidencias ---
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "usecure.db"
LOGS_DIR = BASE_DIR / "evidences" / "logs"
# USECURE_AUDIT_LOG permite que el benchmark use otro fichero sin ensuciar las evidencias.
AUDIT_LOG = Path(os.environ.get("USECURE_AUDIT_LOG", LOGS_DIR / "audit.jsonl"))
PCAP_DIR = BASE_DIR / "evidences" / "pcap"
BENCH_DIR = BASE_DIR / "evidences" / "bench"
ATTACKS_DIR = BASE_DIR / "evidences" / "attacks"

# --- Red ---
HOST = "127.0.0.1"
PORT = 8443            # gateway: TLS 1.3 + mTLS (exige certificado de cliente)
ENROLL_PORT = 8444     # alta de usuarios: TLS 1.3 solo-servidor (aún no hay certificado)
PLAIN_PORT = 8080      # servidor SIN cifrar, solo para el benchmark comparativo
SERVER_HOSTNAME = "gateway.usecure.es"

# --- Política TLS ---
# En TLS 1.3 todas las suites son AEAD y con PFS (ECDHE obligatorio). Aceptamos
# solo estas dos; el servidor rechaza cualquier otra tras el handshake.
ALLOWED_CIPHERS = frozenset({"TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"})

# --- Protocolo de aplicación ---
MAX_FRAME_BYTES = 64 * 1024   # tamaño máximo de un mensaje (evita agotar memoria)
IO_TIMEOUT = 30               # segundos de inactividad antes de cortar la conexión

# --- Cuentas ---
ROLES = ("PDI", "PTGAS", "Investigador")
MAX_CONCURRENT_VERIFICATIONS = 4   # verificaciones Argon2id simultáneas (ver session.py)
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_SECONDS = 60

# Código corporativo de alta: sin él cualquiera podría pedir un certificado (valor de demo).
ENROLL_CODE = os.environ.get("USECURE_ENROLL_CODE", "USECURE-ALTA-2026")
# Contraseña de los usuarios precargados (valor de PRUEBA para la demo y el benchmark).
PRELOAD_PASSWORD = "U-Secure#2026"

# --- PKI ---
CA_DAYS = 3650
LEAF_DAYS = 365
ORG_NAME = "Universidad U-Secure"
CA_COMMON_NAME = "U-Secure Root CA"
