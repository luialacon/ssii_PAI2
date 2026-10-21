"""Protocolo de aplicación: mensajes JSON con prefijo de longitud ("framing").

Por qué: TCP es un flujo de bytes sin "fronteras". Si mandas dos mensajes seguidos
`recv()` puede devolverte medio mensaje o dos pegados. La solución es anteponer a
cada mensaje 4 bytes con su longitud, así el receptor sabe cuánto leer.

    [4 bytes: longitud N (big-endian)] [N bytes: JSON en UTF-8]

Hay variantes síncronas (sockets, servidor y cliente CLI) y asíncronas (asyncio,
usadas por el generador de carga de 300 clientes).
"""
import json
import struct

from src import config

_HDR = struct.Struct(">I")


class ProtocolError(Exception):
    """Mensaje mal formado o demasiado grande."""


def encode(obj: dict) -> bytes:
    body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    if len(body) > config.MAX_FRAME_BYTES:
        raise ProtocolError("mensaje demasiado grande")
    return _HDR.pack(len(body)) + body


def _decode(body: bytes) -> dict:
    try:
        obj = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("JSON inválido") from exc
    if not isinstance(obj, dict):
        raise ProtocolError("el mensaje debe ser un objeto JSON")
    return obj


def _check_len(n: int) -> int:
    if n > config.MAX_FRAME_BYTES:
        raise ProtocolError("longitud declarada excesiva")  # defensa contra agotar memoria
    return n


# ---------------------------------------------------------------- síncrono
def _recv_exact(sock, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("conexión cerrada por el otro extremo")
        buf += chunk
    return bytes(buf)


def send_frame(sock, obj: dict) -> None:
    sock.sendall(encode(obj))


def recv_frame(sock) -> dict:
    (n,) = _HDR.unpack(_recv_exact(sock, _HDR.size))
    return _decode(_recv_exact(sock, _check_len(n)))


# ---------------------------------------------------------------- asyncio
async def asend_frame(writer, obj: dict) -> None:
    writer.write(encode(obj))
    await writer.drain()


async def arecv_frame(reader) -> dict:
    (n,) = _HDR.unpack(await reader.readexactly(_HDR.size))
    return _decode(await reader.readexactly(_check_len(n)))
