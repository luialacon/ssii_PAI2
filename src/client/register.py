"""Alta de un usuario nuevo desde su dispositivo (RF1).

La clave privada se genera AQUÍ y nunca se envía: al servidor solo viaja la CSR
(la "solicitud de carnet", que contiene la clave pública). La CA devuelve el
certificado firmado y se guarda junto a la clave en certs/clients/<usuario>/.
"""
import getpass
import socket
import ssl

from src import config
from src.client.byod_client import build_client_context
from src.pki import ca
from src.protocol import recv_frame, send_frame


def register_user(username, password, role, email, enroll_code,
                  host=config.HOST, port=config.ENROLL_PORT) -> dict:
    key = ca.new_key()
    csr_pem = ca.make_csr(username, role, key).decode()
    ctx = build_client_context(alias=None)  # aún no tenemos certificado: TLS solo-servidor
    with socket.create_connection((host, port), timeout=config.IO_TIMEOUT) as raw:
        with ctx.wrap_socket(raw, server_hostname=config.SERVER_HOSTNAME) as conn:
            send_frame(conn, {"op": "REGISTER", "username": username, "password": password,
                              "role": role, "email": email, "enroll_code": enroll_code,
                              "csr_pem": csr_pem})
            reply = recv_frame(conn)
    if reply.get("status") == "OK":
        d = config.CLIENTS_DIR / username
        d.mkdir(parents=True, exist_ok=True)
        (d / f"{username}.key").write_bytes(ca.key_to_pem(key))
        (d / f"{username}.crt").write_text(reply["cert_pem"])
    return reply


def run_register_interactive() -> None:
    print("\n=== ALTA DE USUARIO (RF1) ===")
    username = input("Usuario (minúsculas, números, _): ").strip()
    role = input(f"Rol {config.ROLES}: ").strip()
    email = input("Email corporativo: ").strip()
    code = getpass.getpass("Código de alta: ")
    password = getpass.getpass("Contraseña corporativa: ")
    try:
        reply = register_user(username, password, role, email, code)
    except (ssl.SSLError, ConnectionRefusedError) as exc:
        print(f"[-] No se pudo registrar: {exc} (¿está en marcha el servicio de alta?)")
        return
    if reply.get("status") == "OK":
        print(f"[+] Registrado. Certificado guardado en certs/clients/{username}/")
    else:
        print(f"[-] {reply.get('msg')}")
