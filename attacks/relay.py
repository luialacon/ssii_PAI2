"""Atacante "hombre en el medio" (MITM) para las demostraciones.

Es un retransmisor TCP: el cliente cree hablar con el gateway, pero en realidad habla con
este programa, que reenvía los bytes y, si se le pide, los modifica. Lo usamos para probar
dos cosas:
  - CONFIDENCIALIDAD: lo que el atacante "ve" pasar es ruido cifrado.
  - INTEGRIDAD: si cambia UN solo bit, el receptor lo detecta y corta la conexión.
"""
import socket
import threading


class Relay:
    def __init__(self, target_port: int, listen_port: int = 0, flip_after_bytes: int | None = None):
        self.target_port = target_port
        self.flip_after = flip_after_bytes  # None = solo observar; N = cambiar un bit pasados N bytes
        self.client_to_server = bytearray()
        self.server_to_client = bytearray()
        self.flipped = False
        self._srv = socket.socket()
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", listen_port))
        self._srv.listen(5)
        self._srv.settimeout(0.5)
        self.port = self._srv.getsockname()[1]
        self._stop = threading.Event()
        self._t = threading.Thread(target=self._accept, daemon=True)

    def start(self):
        self._t.start()
        return self

    def stop(self):
        self._stop.set()
        self._srv.close()

    def _accept(self):
        while not self._stop.is_set():
            try:
                c, _ = self._srv.accept()
            except (socket.timeout, OSError):
                continue
            s = socket.create_connection(("127.0.0.1", self.target_port))
            threading.Thread(target=self._pipe, args=(c, s, self.client_to_server, True), daemon=True).start()
            threading.Thread(target=self._pipe, args=(s, c, self.server_to_client, False), daemon=True).start()

    def _pipe(self, src, dst, log: bytearray, tamper: bool):
        try:
            while True:
                data = src.recv(4096)
                if not data:
                    break
                if tamper and self.flip_after is not None and not self.flipped and len(log) >= self.flip_after:
                    data = bytearray(data)
                    data[-1] ^= 0x01  # un único bit
                    data = bytes(data)
                    self.flipped = True
                log += data
                dst.sendall(data)
        except OSError:
            pass
        finally:
            for s in (src, dst):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
