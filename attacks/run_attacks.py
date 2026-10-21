"""Demostración de ataques contra el gateway (extra +10%, RS4).

Cada ataque se lanza contra el gateway REAL (misma PKI y misma BD) y se comprueba que la
defensa funciona. Al final se escribe evidences/attacks/attacks_report.md (+ .json).

    python -m attacks.run_attacks

IMPORTANTE: son pruebas en un entorno controlado, contra nuestro propio servidor local.
"""
import datetime
import json
import socket
import ssl
import sys
import tempfile
import time
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from attacks.relay import Relay
from src import config
from src.client.byod_client import ByodClient, build_client_context
from src.pki import ca
from src.protocol import recv_frame, send_frame
from src.server.audit import AuditLog, verify_chain
from src.server.gateway import create_gateway
from src.server.store import Store

PORT = 18443
SECRET = "DATOS-CONFIDENCIALES-DE-INVESTIGACION"
VICTIM, OTHER = "pdi_user5", "inv_user5"
RESULTS: list[dict] = []


def audit_events(name: str, since: float) -> list[dict]:
    path = config.AUDIT_LOG
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    return [r for r in rows if r["event"] == name and r["ts"] >= since]


def rejected(fn) -> tuple[bool, str]:
    """Ejecuta un intento de conexión. True si el servidor lo rechazó (excepción o cierre)."""
    try:
        got = fn()
        return got in (b"", None), f"respuesta del servidor: {got!r}"
    except (ssl.SSLError, ConnectionError, OSError) as exc:
        return True, f"{type(exc).__name__}: {str(exc)[:110]}"


def record(num, name, description, defense, ok: bool, observed: str, evidence: str):
    RESULTS.append({"n": num, "name": name, "description": description, "defense": defense,
                    "blocked": ok, "observed": observed, "evidence": evidence})
    print(f"[{'BLOQUEADO' if ok else '¡¡FALLO!!'}] {num:>2}. {name}")


def _raw_connect(ctx):
    s = ctx.wrap_socket(socket.create_connection((config.HOST, PORT), timeout=5),
                        server_hostname=config.SERVER_HOSTNAME)
    s.sendall(b"\x00\x00\x00\x02{}")
    return s.recv(10)


def _evil_ca(tmp: Path):
    """Crea una CA falsa del atacante y devuelve (cert_ca, clave_ca)."""
    key = ec.generate_private_key(ec.SECP384R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "U-Secure Root CA")])  # mismo nombre que la real
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    return cert, key


def _leaf(ca_cert, ca_key, cn, eku, tmp: Path, sans=None):
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    b = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
         .issuer_name(ca_cert.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=30))
         .add_extension(x509.ExtendedKeyUsage([eku]), critical=True))
    if sans:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False)
    cert = b.sign(ca_key, hashes.SHA256())
    crt, k = tmp / f"{cn}.crt", tmp / f"{cn}.key"
    crt.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    k.write_bytes(ca.key_to_pem(key))
    return crt, k


def run() -> None:
    tmp = Path(tempfile.mkdtemp(prefix="attacks_"))
    audit, store = AuditLog(), Store()
    gw = create_gateway(port=PORT, store=store, audit=audit).start()
    t0 = time.time()
    try:
        # 1 ---------------------------------------------------------------- sin certificado
        ok, obs = rejected(lambda: _raw_connect(build_client_context(alias=None)))
        time.sleep(0.3)
        n = len(audit_events("HANDSHAKE_FAILED", t0))
        record(1, "Cliente sin certificado", "Un dispositivo no registrado intenta conectar.",
               "mTLS obligatorio (CERT_REQUIRED)", ok and n >= 1, obs, f"{n} evento(s) HANDSHAKE_FAILED")

        # 2 ------------------------------------- certificado de una CA falsa (suplantación)
        evil, evil_key = _evil_ca(tmp)
        crt, k = _leaf(evil, evil_key, VICTIM, ExtendedKeyUsageOID.CLIENT_AUTH, tmp)
        ctx = build_client_context(alias=None)
        ctx.load_cert_chain(crt, k)
        before = len(audit_events("HANDSHAKE_FAILED", t0))
        ok, obs = rejected(lambda: _raw_connect(ctx))
        time.sleep(0.3)
        n = len(audit_events("HANDSHAKE_FAILED", t0)) - before
        record(2, "Suplantación con certificado de CA falsa",
               f"El atacante crea su propia CA (con el mismo nombre) y se firma un carnet como '{VICTIM}'.",
               "El servidor valida la cadena contra NUESTRA CA, no por el nombre", ok and n >= 1, obs,
               f"{n} HANDSHAKE_FAILED nuevo(s)")

        # 3 ------------------------------------------------------------ TLS 1.2 (degradación)
        ctx = build_client_context(VICTIM)
        ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        before = len(audit_events("HANDSHAKE_FAILED", t0))
        ok, obs = rejected(lambda: _raw_connect(ctx))
        time.sleep(0.3)
        n = len(audit_events("HANDSHAKE_FAILED", t0)) - before
        record(3, "Ataque de degradación a TLS 1.2", "Un cliente (o un atacante) fuerza una versión antigua.",
               "min = max = TLS 1.3 en el servidor", ok and n >= 1, obs, f"{n} HANDSHAKE_FAILED nuevo(s)")

        # 4 ---------------------------------------- certificado robado SIN la contraseña
        with ByodClient(VICTIM, port=PORT) as c:
            r1 = c.login(VICTIM, "Adivinada#123")
        ok = r1.get("status") == "ERROR"
        record(4, "Certificado robado, sin contraseña",
               f"Roban el archivo del carnet de '{VICTIM}' (capa 1 superada) pero no saben la contraseña.",
               "Doble capa: además del carnet se exige la contraseña (Argon2id)", ok,
               f"respuesta: {r1.get('code')} / {r1.get('msg')}",
               f"{len([e for e in audit_events('LOGIN_FAILED', t0) if e.get('user') == VICTIM])} LOGIN_FAILED")

        # 5 ------------------------------------------- certificado propio, otro usuario
        with ByodClient(VICTIM, port=PORT) as c:
            r2 = c.login(OTHER, config.PRELOAD_PASSWORD)  # contraseña correcta de OTRO, carnet de VICTIM
        un = [e for e in audit_events("UNAUTHORIZED", t0) if e.get("reason") == "cn_mismatch"]
        record(5, "Usar un carnet para entrar como otro usuario",
               f"Con el carnet de '{VICTIM}' e intentando identificarse como '{OTHER}' (incluso sabiendo su contraseña).",
               "El usuario debe coincidir con el CN del certificado", r2.get("status") == "ERROR" and len(un) >= 1,
               f"respuesta: {r2.get('code')}", f"{len(un)} UNAUTHORIZED (cn_mismatch)")

        # 6 ---------------------------------------------------------- fuerza bruta
        for _ in range(config.MAX_FAILED_ATTEMPTS):
            with ByodClient(OTHER, port=PORT) as c:
                c.login(OTHER, "Prueba#Fuerza1")
        with ByodClient(OTHER, port=PORT) as c:
            r3 = c.login(OTHER, config.PRELOAD_PASSWORD)  # ahora ni la correcta entra
        record(6, "Fuerza bruta de contraseñas", f"{config.MAX_FAILED_ATTEMPTS} intentos fallidos seguidos.",
               "Bloqueo temporal de la cuenta", r3.get("code") == "LOCKED", f"respuesta: {r3.get('code')}",
               f"{len(audit_events('ACCOUNT_LOCKED', t0))} ACCOUNT_LOCKED")
        store.reset_failures(OTHER)

        # 7 ---------------------------------------------------- servidor falso (MITM activo)
        evil_srv_crt, evil_srv_key = _leaf(evil, evil_key, config.SERVER_HOSTNAME, ExtendedKeyUsageOID.SERVER_AUTH,
                                           tmp, sans=[config.SERVER_HOSTNAME, "localhost"])
        fake_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        fake_ctx.load_cert_chain(evil_srv_crt, evil_srv_key)
        lsock = socket.socket()
        lsock.bind(("127.0.0.1", 0))
        lsock.listen(1)
        fake_port = lsock.getsockname()[1]
        import threading

        def fake_server():
            try:
                c, _ = lsock.accept()
                fake_ctx.wrap_socket(c, server_side=True)
            except (ssl.SSLError, OSError):
                pass
        threading.Thread(target=fake_server, daemon=True).start()
        try:
            ByodClient(VICTIM, port=fake_port).connect()
            ok, obs = False, "¡el cliente aceptó al servidor falso!"
        except ssl.SSLCertVerificationError as exc:
            ok, obs = True, f"SSLCertVerificationError: {exc.verify_message}"
        except (ssl.SSLError, OSError) as exc:
            ok, obs = True, f"{type(exc).__name__}: {str(exc)[:100]}"
        lsock.close()
        record(7, "Servidor falso (suplantación del gateway)",
               "El atacante monta un servidor con el nombre gateway.usecure.es y certificado de su CA falsa.",
               "El cliente solo confía en la CA de U-Secure y valida el nombre (autenticación del servidor)",
               ok, obs, "el cliente corta antes de enviar credenciales")

        # 8 ------------------------------------------------- MITM pasivo: lo que ve el atacante
        relay = Relay(PORT).start()
        with ByodClient(VICTIM, port=relay.port) as c:
            c.login(VICTIM, config.PRELOAD_PASSWORD)
            c.send_message(SECRET)
            c.logout()
        time.sleep(0.3)
        seen = bytes(relay.client_to_server + relay.server_to_client)
        leaked = SECRET.encode() in seen or config.PRELOAD_PASSWORD.encode() in seen
        record(8, "Interceptación (sniffing) en un retransmisor MITM",
               "Un atacante en medio reenvía el tráfico y lo lee.",
               "Cifrado AEAD con TLS 1.3", not leaked,
               f"el atacante capturó {len(seen)} bytes; contienen el secreto o la contraseña: {'SÍ' if leaked else 'NO'}",
               "ver evidences/pcap/analysis.txt para la comparación con tráfico plano")
        relay.stop()

        # 9 ---------------------------------------------- manipulación de un bit en tránsito
        relay = Relay(PORT, flip_after_bytes=2500).start()
        before = len(audit_events("DISCONNECT", t0))
        broken = False
        try:
            with ByodClient(VICTIM, port=relay.port) as c:
                c.login(VICTIM, config.PRELOAD_PASSWORD)
                for i in range(20):
                    c.send_message("mensaje " + str(i) * 200)
        except (ssl.SSLError, ConnectionError, OSError, json.JSONDecodeError) as exc:
            broken = True
            obs = f"{type(exc).__name__}: {str(exc)[:100]}"
        relay.stop()
        record(9, "Manipulación de un bit en tránsito",
               "El atacante cambia UN solo bit de un mensaje cifrado.",
               "Integridad AEAD (AES-GCM / ChaCha20-Poly1305): el registro alterado no se acepta",
               broken and relay.flipped, obs if broken else "la sesión siguió (fallo)",
               "la sesión se corta con bad_record_mac; ningún dato manipulado llega a la aplicación")

        # 10 ------------------------------------------------ repetición de bytes grabados (replay)
        relay = Relay(PORT).start()
        with ByodClient(VICTIM, port=relay.port) as c:
            c.login(VICTIM, config.PRELOAD_PASSWORD)
            c.send_message("transferir-1000-EUR")
            c.logout()
        time.sleep(0.3)
        recorded = bytes(relay.client_to_server)
        relay.stop()

        def replay():
            s = socket.create_connection((config.HOST, PORT), timeout=5)
            s.sendall(recorded)
            s.settimeout(3)
            return s.recv(4096)
        before_fail = len(audit_events("HANDSHAKE_FAILED", t0))
        before_conn = len(audit_events("CONNECT", t0))
        try:
            replay()
        except (ssl.SSLError, OSError):
            pass
        time.sleep(0.5)
        fails = audit_events("HANDSHAKE_FAILED", t0)[before_fail:]
        new_sessions = len(audit_events("CONNECT", t0)) - before_conn
        # El servidor SÍ contesta con un ServerHello (nuevo, con aleatorios y claves distintos) pero
        # los bytes grabados ya no sirven: no descifran y el handshake falla. Eso es lo que prueba la defensa.
        reason = fails[0]["reason"][:90] if fails else "sin evento"
        record(10, "Repetición (replay) de una sesión grabada",
               "El atacante graba la sesión legítima y reenvía exactamente los mismos bytes en una conexión nueva.",
               "Claves efímeras (ECDHE) y aleatorios distintos por sesión: lo grabado no vale en otra sesión",
               len(fails) >= 1 and new_sessions == 0,
               f"el servidor respondió con un ServerHello nuevo y falló al descifrar lo reenviado: {reason}",
               f"{len(fails)} HANDSHAKE_FAILED nuevo(s), {new_sessions} sesiones abiertas")

        # 11 ------------------------------------------- certificado revocado
        victim_crt = x509.load_pem_x509_certificate(
            (config.CLIENTS_DIR / "pas_user5" / "pas_user5.crt").read_bytes())
        ca.revoke(victim_crt.serial_number)
        before = len(audit_events("HANDSHAKE_FAILED", t0))
        ok, obs = rejected(lambda: _raw_connect(build_client_context("pas_user5")))
        time.sleep(0.3)
        n = len(audit_events("HANDSHAKE_FAILED", t0)) - before
        record(11, "Uso de un certificado revocado", "Se revoca el carnet de pas_user5 (robo/pérdida) y se intenta usar.",
               "Comprobación de la CRL en el handshake", ok and n >= 1, obs, f"{n} HANDSHAKE_FAILED nuevo(s)")
    finally:
        # Dejar la PKI como estaba: regeneramos CRL sin esa revocación de prueba.
        state = ca._state_file()
        data = json.loads(state.read_text())
        state.write_text(json.dumps([e for e in data if e["serial"] != format(victim_crt.serial_number, "x")]
                                    if "victim_crt" in locals() else data))
        ca.rebuild_crl()
        gw.stop()

    write_report(*verify_chain())


def write_report(chain_ok: bool, n_events: int) -> None:
    config.ATTACKS_DIR.mkdir(parents=True, exist_ok=True)
    (config.ATTACKS_DIR / "attacks_report.json").write_text(json.dumps(RESULTS, indent=2, ensure_ascii=False),
                                                            encoding="utf-8")
    blocked = sum(r["blocked"] for r in RESULTS)
    lines = ["# Informe de ataques simulados (entorno controlado)\n",
             f"Fecha: {datetime.datetime.now():%Y-%m-%d %H:%M}  |  Ataques bloqueados: **{blocked}/{len(RESULTS)}**\n",
             f"Log de auditoría: {n_events} eventos, cadena de hashes "
             f"{'ÍNTEGRA' if chain_ok else 'ROTA'}.\n",
             "| # | Ataque | Defensa | Resultado | Evidencia |", "|---|---|---|---|---|"]
    for r in RESULTS:
        lines.append(f"| {r['n']} | {r['name']} | {r['defense']} | "
                     f"{'✅ Bloqueado' if r['blocked'] else '❌ NO bloqueado'} | {r['evidence']} |")
    lines.append("\n## Detalle\n")
    for r in RESULTS:
        lines += [f"### {r['n']}. {r['name']}", f"- **Qué se intenta:** {r['description']}",
                  f"- **Defensa:** {r['defense']}", f"- **Observado:** {r['observed']}", ""]
    (config.ATTACKS_DIR / "attacks_report.md").write_text("\n".join(lines), encoding="utf-8")
    print(f"\n{blocked}/{len(RESULTS)} ataques bloqueados. Informe: evidences/attacks/attacks_report.md")
    if blocked != len(RESULTS):
        sys.exit(1)


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    run()
