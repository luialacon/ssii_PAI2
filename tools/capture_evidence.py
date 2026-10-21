"""Genera las evidencias de red (RS4): capturas .pcapng y su análisis con tshark.

Qué hace, en cristiano:
  1. Arranca el servidor en ESTE proceso (cifrado o plano).
  2. Pone a "grabar" dumpcap (la grabadora de red de Wireshark) en la interfaz loopback.
  3. Hace una sesión de cliente con un mensaje secreto reconocible.
  4. Para la grabación y analiza el fichero: ¿se ve el secreto? ¿qué versión TLS? ¿qué suite?

Resultado en evidences/pcap/:
  tls13_mtls_session.pcapng   sesión legítima: TODO cifrado (el secreto no aparece)
  plain_session.pcapng        la misma sesión sin cifrar: usuario, contraseña y mensaje legibles
  tls12_rejected.pcapng       cliente que solo habla TLS 1.2: el servidor lo corta
  no_client_cert.pcapng       cliente sin certificado: el servidor lo corta
  tls13_session.keylog        claves de sesión SOLO de la captura de demo (para descifrar en Wireshark)
  analysis.txt                resumen automático de lo anterior

Requiere Wireshark (dumpcap y tshark) con Npcap. Uso:  python -m tools.capture_evidence
"""
import os
import shutil
import socket
import ssl
import subprocess
import sys
import time
from pathlib import Path

from src import config
from src.client.byod_client import ByodClient, build_client_context
from src.pki import ca
from src.server.audit import AuditLog
from src.server.gateway import create_gateway
from src.server.plain_server import create_plain_server
from src.server.store import Store

SECRET = "INFORME-CONFIDENCIAL-NOTAS-2026"
USER = "pdi_user1"
TLS_PORT, PLAIN_PORT = 18443, 18080
LOOPBACK = r"\Device\NPF_Loopback"


def _tool(name: str) -> str:
    found = shutil.which(name) or str(Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Wireshark" / f"{name}.exe")
    if not Path(found).exists():
        sys.exit(f"No encuentro {name}. Instala Wireshark (con Npcap) y vuelve a intentarlo.")
    return found


DUMPCAP, TSHARK = _tool("dumpcap"), _tool("tshark")


class Capture:
    """Context manager: graba el tráfico del puerto indicado en un .pcapng."""

    def __init__(self, port: int, out: Path):
        self.port, self.out = port, out
        self.proc = None

    def __enter__(self):
        self.out.unlink(missing_ok=True)
        self.proc = subprocess.Popen(
            [DUMPCAP, "-q", "-i", LOOPBACK, "-f", f"tcp port {self.port}", "-w", str(self.out)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1.5)  # darle tiempo a empezar a grabar antes de generar tráfico
        return self

    def __exit__(self, *exc):
        time.sleep(1.0)  # que se vacíen los últimos paquetes
        self.proc.terminate()
        self.proc.wait(10)


def tshark(*args) -> str:
    r = subprocess.run([TSHARK, *args], capture_output=True, text=True, encoding="utf-8", errors="replace")
    return r.stdout.strip()


def contains(pcap: Path, needle: str) -> bool:
    """¿Aparece el texto en claro dentro de los bytes capturados?"""
    return needle.encode() in pcap.read_bytes()


def run_tls_session(pcap: Path, keylog: Path) -> None:
    keylog.unlink(missing_ok=True)
    ctx = build_client_context(USER)
    ctx.keylog_filename = str(keylog)  # solo para esta demo: permite descifrar a posteriori en Wireshark
    with Capture(TLS_PORT, pcap):
        with ByodClient(USER, port=TLS_PORT, context=ctx) as c:
            c.login(USER, config.PRELOAD_PASSWORD)
            c.send_message(SECRET)
            c.get_resource("correo")
            c.logout()


def run_plain_session(pcap: Path) -> None:
    from src.protocol import recv_frame, send_frame
    with Capture(PLAIN_PORT, pcap):
        with socket.create_connection((config.HOST, PLAIN_PORT), timeout=5) as s:
            send_frame(s, {"op": "LOGIN", "username": USER, "password": config.PRELOAD_PASSWORD})
            recv_frame(s)
            send_frame(s, {"op": "MSG", "data": SECRET})
            recv_frame(s)
            send_frame(s, {"op": "LOGOUT"})
            recv_frame(s)


def run_tls12(pcap: Path) -> None:
    ctx = build_client_context(USER)
    ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    with Capture(TLS_PORT, pcap):
        try:
            ctx.wrap_socket(socket.create_connection((config.HOST, TLS_PORT), timeout=5),
                            server_hostname=config.SERVER_HOSTNAME)
        except (ssl.SSLError, OSError):
            pass


def run_no_cert(pcap: Path) -> None:
    ctx = build_client_context(alias=None)
    with Capture(TLS_PORT, pcap):
        try:
            s = ctx.wrap_socket(socket.create_connection((config.HOST, TLS_PORT), timeout=5),
                                server_hostname=config.SERVER_HOSTNAME)
            s.sendall(b"\x00\x00\x00\x02{}")
            s.recv(10)
        except (ssl.SSLError, OSError):
            pass


def _decrypted(pcap: Path, keylog: Path) -> str:
    """Descifra con el keylog (claves de sesión) y devuelve el diálogo en texto."""
    text = tshark("-r", str(pcap), "-o", f"tls.keylog_file:{keylog}", "-q", "-z", "follow,tls,ascii,0")
    text = text.replace(config.PRELOAD_PASSWORD, "********")  # no dejamos la contraseña real en el informe
    return "\n".join("   " + line for line in text.splitlines())


def analyse(pcap_dir: Path) -> str:
    tls, plain = pcap_dir / "tls13_mtls_session.pcapng", pcap_dir / "plain_session.pcapng"
    t12, nocert = pcap_dir / "tls12_rejected.pcapng", pcap_dir / "no_client_cert.pcapng"
    keylog = pcap_dir / "tls13_session.keylog"
    out = []
    add = out.append

    add("ANÁLISIS AUTOMÁTICO DE CAPTURAS (tshark)\n" + "=" * 60)
    add(f"\n[1] {tls.name}")
    add(f"  Paquetes capturados: {len(tshark('-r', str(tls)).splitlines())}")
    add(f"  ¿Aparece el mensaje secreto en claro?      {'SÍ (FALLO)' if contains(tls, SECRET) else 'NO  -> confidencialidad OK'}")
    add(f"  ¿Aparece la contraseña en claro?           {'SÍ (FALLO)' if contains(tls, config.PRELOAD_PASSWORD) else 'NO  -> confidencialidad OK'}")
    add("  Handshake TLS (tipo de mensaje 1=ClientHello 2=ServerHello 11=Certificate 15=CertVerify):")
    add(tshark("-r", str(tls), "-Y", "tls.handshake.type", "-T", "fields", "-e", "frame.number",
               "-e", "tcp.srcport", "-e", "tls.handshake.type", "-e", "tls.handshake.version",
               "-e", "tls.handshake.ciphersuite", "-e", "tls.handshake.extensions.supported_version"))
    add("  Versión en la capa de registro TLS (0x0303 es el valor 'de compatibilidad' que usa TLS 1.3):")
    add("  Versiones TLS realmente negociadas (extensión supported_versions; 0x0304 = TLS 1.3):")
    add("   " + tshark("-r", str(tls), "-Y", "tls.handshake.type == 2", "-T", "fields",
                       "-e", "tls.handshake.extensions.supported_version").replace("\n", " | "))
    add("  Suite negociada (0x1302 = TLS_AES_256_GCM_SHA384, 0x1303 = TLS_CHACHA20_POLY1305_SHA256):")
    add("   " + tshark("-r", str(tls), "-Y", "tls.handshake.type == 2", "-T", "fields",
                       "-e", "tls.handshake.ciphersuite").replace("\n", " | "))
    add("  Registros 'Application Data' (carga cifrada, ininteligible):")
    add("   trama  puerto_origen  bytes_cifrados")
    add(tshark("-r", str(tls), "-Y", "tls.record.opaque_type == 23", "-T", "fields",
               "-e", "frame.number", "-e", "tcp.srcport", "-e", "tls.record.length").replace("	", "      "))
    add("  Certificados: en TLS 1.3 viajan CIFRADOS tras el ServerHello (no se ven en claro).")
    if keylog.exists():
        add("\n  Con las claves de sesión (tls13_session.keylog) Wireshark SÍ puede descifrar; "
            "sin ellas, no. Contenido recuperado (solo demostración):")
        add(_decrypted(tls, keylog))

    add(f"\n[2] {plain.name}  (sesión idéntica SIN cifrar, solo para comparar)")
    add(f"  ¿Aparece el mensaje secreto en claro?      {'SÍ -> cualquiera en la red lo lee' if contains(plain, SECRET) else 'NO'}")
    add(f"  ¿Aparece la contraseña en claro?           {'SÍ -> credenciales robadas' if contains(plain, config.PRELOAD_PASSWORD) else 'NO'}")
    add("  Flujo TCP reconstruido (lo que vería un atacante):")
    add(tshark("-r", str(plain), "-q", "-z", "follow,tcp,ascii,0")[:1200])

    add(f"\n[3] {t12.name}  (cliente que solo habla TLS 1.2)")
    add("  Mensajes de handshake y alertas (tls.alert_message.desc 70 = protocol_version):")
    add(tshark("-r", str(t12), "-Y", "tls", "-T", "fields", "-e", "frame.number", "-e", "tcp.srcport",
               "-e", "tls.handshake.type", "-e", "tls.alert_message.desc"))
    add(f"  Registros Application Data: {len(tshark('-r', str(t12), '-Y', 'tls.record.opaque_type == 23').splitlines())} (0 = no hubo sesión)")

    add(f"\n[4] {nocert.name}  (cliente sin certificado)")
    add("  Nota: en TLS 1.3 el servidor pide el certificado DENTRO del handshake cifrado y su alerta")
    add("  (certificate_required) también va cifrada, por eso no se ve el motivo en el pcap; la causa")
    add("  queda registrada en el log de auditoría del servidor (evento HANDSHAKE_FAILED).")
    add("  Tramas (trama, puerto origen, flags TCP; 0x0011 = FIN+ACK, 0x0004 = RST, 0x0010 = ACK):")
    add(tshark("-r", str(nocert), "-T", "fields", "-e", "frame.number", "-e", "tcp.srcport", "-e", "tcp.flags"))
    add(f"  Registros Application Data: {len(tshark('-r', str(nocert), '-Y', 'tls.record.opaque_type == 23').splitlines())} "
        "(solo los de cierre del handshake; ningún dato de aplicación llega a intercambiarse)")
    return "\n".join(out)


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")  # la consola de Windows (cp1252) no admite todos los símbolos
    config.PCAP_DIR.mkdir(parents=True, exist_ok=True)
    ca.init_pki(force=False)
    audit = AuditLog()
    store = Store()
    gw = create_gateway(port=TLS_PORT, store=store, audit=audit).start()
    plain = create_plain_server(port=PLAIN_PORT, store=store, audit=audit).start()
    d = config.PCAP_DIR
    try:
        print("[1/4] Sesión TLS 1.3 + mTLS ...");  run_tls_session(d / "tls13_mtls_session.pcapng", d / "tls13_session.keylog")
        print("[2/4] Misma sesión sin cifrar ..."); run_plain_session(d / "plain_session.pcapng")
        print("[3/4] Intento con TLS 1.2 ...");     run_tls12(d / "tls12_rejected.pcapng")
        print("[4/4] Intento sin certificado ..."); run_no_cert(d / "no_client_cert.pcapng")
    finally:
        gw.stop()
        plain.stop()
    report = analyse(d)
    (d / "analysis.txt").write_text(report, encoding="utf-8")
    print(report)


if __name__ == "__main__":
    main()
