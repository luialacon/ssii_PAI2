"""Cliente BYOD: el dispositivo personal del empleado que se conecta al gateway.

Hace de "visitante": enseña su carnet (certificado) al portero, comprueba el
carnet del portero, se identifica con usuario y contraseña, manda mensajes y
se despide cerrando la sesión de forma segura (RF4).
"""
import getpass
import socket
import ssl

from src import config
from src.protocol import recv_frame, send_frame


def build_client_context(alias: str | None = None) -> ssl.SSLContext:
    """Contexto TLS del cliente: solo TLS 1.3, verifica al servidor y (si hay alias) presenta su certificado."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_verify_locations(cafile=str(config.CA_CERT))  # solo confiamos en NUESTRA CA
    ctx.check_hostname = True                              # el nombre debe estar en el SAN del servidor
    ctx.verify_mode = ssl.CERT_REQUIRED
    if alias:
        d = config.CLIENTS_DIR / alias
        crt, key = d / f"{alias}.crt", d / f"{alias}.key"
        if not crt.exists() or not key.exists():
            raise FileNotFoundError(f"No hay certificado para '{alias}' en {d}")
        ctx.load_cert_chain(crt, key)
    return ctx


def list_aliases() -> list[str]:
    return sorted(p.name for p in config.CLIENTS_DIR.iterdir() if p.is_dir()) if config.CLIENTS_DIR.exists() else []


class ByodClient:
    """Sesión del cliente contra el gateway. Uso: `with ByodClient('pdi_user1') as c: ...`"""

    def __init__(self, alias, host=config.HOST, port=config.PORT, context=None):
        self.alias, self.host, self.port = alias, host, port
        self.ctx = context or build_client_context(alias)
        self.sock = None
        self.tls_version = self.cipher = None

    def connect(self) -> None:
        raw = socket.create_connection((self.host, self.port), timeout=config.IO_TIMEOUT)
        try:
            self.sock = self.ctx.wrap_socket(raw, server_hostname=config.SERVER_HOSTNAME)
        except Exception:
            raw.close()
            raise
        self.tls_version, self.cipher = self.sock.version(), self.sock.cipher()[0]
        if self.cipher not in config.ALLOWED_CIPHERS:
            self.sock.close()
            raise ssl.SSLError(f"Suite no permitida por la política: {self.cipher}")

    def request(self, **msg) -> dict:
        send_frame(self.sock, msg)
        return recv_frame(self.sock)

    def login(self, username: str, password: str) -> dict:
        return self.request(op="LOGIN", username=username, password=password)

    def send_message(self, data: str) -> dict:
        return self.request(op="MSG", data=data)

    def get_resource(self, name: str) -> dict:
        return self.request(op="RESOURCE", name=name)

    def logout(self) -> dict:
        """RF4: avisa al servidor, espera su confirmación y cierra el túnel TLS (close_notify)."""
        reply = self.request(op="LOGOUT")
        self.close()
        return reply

    def close(self) -> None:
        if self.sock is None:
            return
        try:
            self.sock.settimeout(2)
            self.sock.unwrap()  # envía close_notify
        except (OSError, ssl.SSLError, ValueError):
            pass
        finally:
            self.sock.close()
            self.sock = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *exc):
        self.close()


def run_client(username="pdi_user1", password=config.PRELOAD_PASSWORD, host=config.HOST, port=config.PORT):
    """Demostración automática: conecta, entra, pide un recurso, manda un mensaje y sale."""
    try:
        with ByodClient(username, host, port) as c:
            print(f"[CLIENTE] Handshake OK -> {c.tls_version} / {c.cipher}")
            print(f"[CLIENTE] Login: {c.login(username, password)}")
            print(f"[CLIENTE] Recurso 'correo': {c.get_resource('correo')}")
            print(f"[CLIENTE] Mensaje cifrado: {c.send_message('informe confidencial de notas')}")
            print(f"[CLIENTE] Logout: {c.logout()}")
    except ConnectionRefusedError:
        print("[-] El gateway no está en marcha (opción 2 del menú).")
    except ssl.SSLError as exc:
        print(f"[-] Fallo TLS/mTLS: {exc}")
    except Exception as exc:
        print(f"[-] Error: {exc}")


def run_interactive_client(host=config.HOST, port=config.PORT):
    """Modo manual: eliges certificado, usuario y contraseña, y mandas mensajes por el túnel."""
    print("\n=== CLIENTE BYOD (mTLS + credenciales) ===")
    aliases = list_aliases()
    print(f"Certificados disponibles: {len(aliases)} (ej. {', '.join(aliases[:3])})")
    alias = input("Certificado a usar (alias): ").strip()
    username = input("Usuario: ").strip()
    try:
        password = getpass.getpass("Contraseña: ")
    except Exception:
        password = input("Contraseña: ")
    try:
        with ByodClient(alias, host, port) as c:
            print(f"[+] Handshake OK: {c.tls_version} / {c.cipher}")
            reply = c.login(username, password)
            if reply.get("status") != "OK":
                print(f"[-] Acceso denegado: {reply.get('msg')}")
                return
            print(f"[+] {reply['msg']}")
            print("Comandos: 'recurso <nombre>', 'logout', o cualquier texto para enviarlo.")
            while True:
                line = input(f"({username})> ").strip()
                if not line:
                    continue
                if line.lower() in ("logout", "exit"):
                    print(f"[+] {c.logout()}")
                    return
                if line.lower().startswith("recurso "):
                    print(c.get_resource(line.split(" ", 1)[1]))
                else:
                    print(c.send_message(line))
    except FileNotFoundError as exc:
        print(f"[-] {exc}")
    except ssl.SSLError as exc:
        print(f"[-] Handshake rechazado: {exc}")
    except ConnectionRefusedError:
        print("[-] El gateway no está en marcha (opción 2 del menú).")


if __name__ == "__main__":
    run_interactive_client()
