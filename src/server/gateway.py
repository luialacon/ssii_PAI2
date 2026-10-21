import json
import logging
import os
import socket
import ssl
import threading

BASE_DIR = os.path.join(os.path.dirname(__file__), "..", "..")
LOG_FILE = os.path.join(BASE_DIR, "evidences", "logs", "audit.log")

os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

def load_users():
    path = os.path.join(BASE_DIR, "data", "preloaded_users.json")
    with open(path, "r") as f:
        return json.load(f)

def build_server_context():
    """Configura TLS 1.3 nativo con mTLS estricto (RS1, RS2)"""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3

    ca_crt = os.path.join(BASE_DIR, "certs", "ca", "ca.crt")
    srv_crt = os.path.join(BASE_DIR, "certs", "server", "server.crt")
    srv_key = os.path.join(BASE_DIR, "certs", "server", "server.key")

    ctx.load_cert_chain(certfile=srv_crt, keyfile=srv_key)
    ctx.load_verify_locations(cafile=ca_crt)
    ctx.verify_mode = ssl.CERT_REQUIRED  # Exigir certificado de cliente (mTLS)
    
    # NOTA: En TLS 1.3, OpenSSL aplica automáticamente las ciphers AEAD seguras.
    # No se debe llamar a set_ciphers() para TLS 1.3.

    return ctx

def handle_client(ssl_conn, addr, users_db):
    try:
        # Capa 1: Validación mTLS completada en Handshake
        peer_cert = ssl_conn.getpeercert()
        client_cn = dict(x[0] for x in peer_cert['subject'])['commonName']
        logging.info(f"Conexión mTLS establecida desde {addr} | CN Certificado: {client_cn}")

        # Capa 2: Autenticación por Credenciales (RF2)
        data = ssl_conn.recv(1024).decode('utf-8').strip()
        auth_data = json.loads(data)
        username = auth_data.get("username")
        password = auth_data.get("password")

        if username in users_db and users_db[username]["password"] == password:
            user_role = users_db[username]["role"]
            response = {"status": "AUTH_SUCCESS", "role": user_role, "msg": f"Bienvenido al Gateway U-Secure [{user_role}]"}
            ssl_conn.sendall(json.dumps(response).encode('utf-8'))
            logging.info(f"Autenticación exitosa usuario: {username} ({user_role})")

            # Bucle de comunicación cifrada dentro del túnel
            while True:
                payload = ssl_conn.recv(2048)
                if not payload:
                    break
                msg = payload.decode('utf-8').strip()
                if msg == "LOGOUT":
                    logging.info(f"Cierre seguro de sesión (RF4) solicitado por: {username}")
                    ssl_conn.sendall(b"LOGOUT_ACK")
                    break
                
                # Respuesta a solicitudes internas
                reply = f"GATEWAY_ECHO: {msg} [OK]"
                ssl_conn.sendall(reply.encode('utf-8'))
        else:
            logging.warning(f"Intento de acceso no autorizado para usuario: {username} desde {addr}")
            response = {"status": "AUTH_FAILED", "msg": "Credenciales inválidas"}
            ssl_conn.sendall(json.dumps(response).encode('utf-8'))

    except Exception as e:
        logging.error(f"Error procesando cliente {addr}: {str(e)}")
    finally:
        ssl_conn.close()

def start_gateway(host="127.0.0.1", port=8443):
    users_db = load_users()
    context = build_server_context()

    bind_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bind_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    bind_sock.bind((host, port))
    bind_sock.listen(500)

    print(f"[GATEWAY] Servidor VPN U-Secure escuchando en TLS 1.3 mTLS ({host}:{port})...")
    logging.info(f"Gateway VPN arrancado en {host}:{port}")

    try:
        while True:
            newsock, addr = bind_sock.accept()
            try:
                ssl_conn = context.wrap_socket(newsock, server_side=True)
                t = threading.Thread(target=handle_client, args=(ssl_conn, addr, users_db), daemon=True)
                t.start()
            except ssl.SSLError as e:
                logging.warning(f"Fallo Handshake mTLS desde {addr}: {str(e)}")
                newsock.close()
    except KeyboardInterrupt:
        print("\n[GATEWAY] Apagando Servidor...")
    finally:
        bind_sock.close()

if __name__ == "__main__":
    start_gateway()