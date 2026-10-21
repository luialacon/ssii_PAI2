"""Servidor TCP genérico: un hilo por conexión, con o sin TLS.

Lo reutilizan el gateway mTLS, el servicio de alta de usuarios y el servidor
"plano" del benchmark, así los tres comparten la misma concurrencia y la
comparación de rendimiento es justa (lo único que cambia es el cifrado).

El handshake TLS se hace DENTRO del hilo de cada cliente: un cliente lento o
malicioso no bloquea al resto (en la versión original se hacía en el hilo de
aceptación y 300 clientes simultáneos se serializaban).
"""
import socket
import ssl
import threading

from cryptography import x509

from src import config


def close_tls(conn) -> None:
    """Cierre limpio: envía `close_notify` (aviso TLS de fin de sesión) y libera el socket.

    Al cerrar, OpenSSL descarta los secretos de tráfico de la sesión. Como
    desactivamos los tickets de reanudación (`num_tickets = 0`), no queda
    ningún material con el que reabrir o descifrar la sesión después (PFS, RF4).
    """
    try:
        if isinstance(conn, ssl.SSLSocket):
            conn.settimeout(2)
            conn.unwrap()
    except (OSError, ssl.SSLError, ValueError):
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


class ThreadedServer:
    """Escucha en (host, port) y llama a `handler(conn, addr, info)` por cada cliente.

    context_factory: función que devuelve el SSLContext vigente (None = sin TLS).
    on_handshake_error / on_bad_cipher: callbacks de auditoría.
    """

    def __init__(self, host, port, handler, context_factory=None, audit=None, name="server"):
        self.host, self.port = host, port
        self.handler = handler
        self.context_factory = context_factory
        self.audit = audit
        self.name = name
        self._sock = None
        self._stop = threading.Event()
        self._thread = None
        self.bound_port = None

    # ------------------------------------------------------------ ciclo
    def start(self) -> "ThreadedServer":
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.listen(1024)
        self._sock.settimeout(0.5)  # para poder comprobar la señal de parada
        self.bound_port = self._sock.getsockname()[1]
        self._thread = threading.Thread(target=self._accept_loop, daemon=True, name=self.name)
        self._thread.start()
        return self

    def serve_forever(self) -> None:
        self.start()
        try:
            while self._thread.is_alive():
                self._thread.join(0.5)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    def stop(self) -> None:
        self._stop.set()
        if self._sock:
            self._sock.close()
        if self._thread:
            self._thread.join(2)

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                raw, addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._serve_client, args=(raw, addr), daemon=True).start()

    # ---------------------------------------------------------- cliente
    def _serve_client(self, raw, addr) -> None:
        raw.settimeout(config.IO_TIMEOUT)
        conn, info = raw, {"tls": False}
        try:
            if self.context_factory is not None:
                conn = self.context_factory().wrap_socket(raw, server_side=True)  # handshake
                info = self._tls_info(conn)
                if info["cipher"] not in config.ALLOWED_CIPHERS:
                    self._log("CIPHER_REJECTED", addr, cipher=info["cipher"])
                    return
        except (ssl.SSLError, OSError) as exc:
            # Sin certificado, certificado de otra CA, revocado, TLS 1.2... todo llega aquí.
            self._log("HANDSHAKE_FAILED", addr, reason=str(exc))
            raw.close()
            return
        try:
            self.handler(conn, addr, info)
        except (ConnectionError, TimeoutError, OSError):
            pass
        finally:
            close_tls(conn)

    @staticmethod
    def _tls_info(conn: ssl.SSLSocket) -> dict:
        info = {"tls": True, "version": conn.version(), "cipher": conn.cipher()[0],
                "cn": None, "serial": None}
        der = conn.getpeercert(binary_form=True)
        if der:
            cert = x509.load_der_x509_certificate(der)
            cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
            info["cn"] = cn[0].value if cn else None
            info["serial"] = format(cert.serial_number, "x")
        return info

    def _log(self, event, addr, **fields) -> None:
        if self.audit:
            self.audit.event(event, service=self.name, ip=addr[0], port=addr[1], **fields)
