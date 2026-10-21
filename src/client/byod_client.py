import json
import os
import socket
import ssl
import getpass

BASE_DIR = os.path.join(os.path.dirname(__file__), "..", "..")

def get_available_certificates():
    """Obtiene la lista de certificados de clientes generados en certs/clients/"""
    clients_dir = os.path.join(BASE_DIR, "certs", "clients")
    if not os.path.exists(clients_dir):
        return []
    return [d for d in os.listdir(clients_dir) if os.path.isdir(os.path.join(clients_dir, d))]

def build_client_context(cert_alias):
    """Configura mTLS con el certificado especificado (RS1, RS2)"""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3

    ca_crt = os.path.join(BASE_DIR, "certs", "ca", "ca.crt")
    cli_crt = os.path.join(BASE_DIR, "certs", "clients", cert_alias, f"{cert_alias}.crt")
    cli_key = os.path.join(BASE_DIR, "certs", "clients", cert_alias, f"{cert_alias}.key")

    if not os.path.exists(cli_crt) or not os.path.exists(cli_key):
        raise FileNotFoundError(f"No se encontraron los archivos .crt/.key para '{cert_alias}' en 'certs/clients/'")

    ctx.load_verify_locations(cafile=ca_crt)
    ctx.load_cert_chain(certfile=cli_crt, keyfile=cli_key)
    ctx.check_hostname = False  # Permitir validación local
    return ctx

def run_interactive_client(host="127.0.0.1", port=8443):
    """Modo interactivo: permite probar login manual y enviar tráfico por el túnel"""
    print("\n==================================================")
    print("   INICIO DE SESIÓN MANUAL - CLIENTE BYOD (mTLS)   ")
    print("==================================================")

    # 1. Selección del Certificado (Capa 1: Validación mTLS)
    available_certs = get_available_certificates()
    print("\n[CAPA 1 - Certificado Digital X.509v3]")
    if available_certs:
        print(f"Certificados detectados: {', '.join(available_certs)}")
    else:
        print("¡Atención! No hay certificados en 'certs/clients/'. Ejecuta la Opción 1 primero.")

    cert_alias = input("Alias del certificado a usar (ej. pdi_user1): ").strip()
    
    try:
        ctx = build_client_context(cert_alias)
    except FileNotFoundError as e:
        print(f"\n[-] ERROR PKI/mTLS: {e}")
        return
    except Exception as e:
        print(f"\n[-] ERROR CONFIGURACIÓN TLS: {str(e)}")
        return

    # 2. Entrada de Credenciales (Capa 2: Aplicación)
    print("\n[CAPA 2 - Credenciales Corporativas]")
    username = input("Usuario: ").strip()
    # Oculta la contraseña al escribir; si falla la consola usa input normal
    try:
        password = getpass.getpass("Contraseña: ").strip()
    except Exception:
        password = input("Contraseña: ").strip()

    # 3. Establecimiento del Túnel Seguro mTLS + TLS 1.3
    try:
        raw_sock = socket.create_connection((host, port))
        ssl_conn = ctx.wrap_socket(raw_sock, server_hostname="gateway.usecure.es")
        print("\n[+] HANDSHAKE mTLS COMPLETADO")
        print(f"    Protocolo: {ssl_conn.version()}")
        print(f"    Cifrado:   {ssl_conn.cipher()[0]}")

        # 4. Enviar payload de autenticación
        auth_payload = json.dumps({"username": username, "password": password})
        ssl_conn.sendall(auth_payload.encode('utf-8'))

        res = ssl_conn.recv(1024).decode('utf-8')
        res_data = json.loads(res)

        if res_data.get("status") == "AUTH_SUCCESS":
            print(f"\n[+] AUTENTICACIÓN EXITOSA: {res_data.get('msg')}")
            print("==================================================")
            print(" Escriba datos para enviar por el túnel cifrado.")
            print(" Escriba 'LOGOUT' o 'exit' para cerrar sesión (RF4).")
            print("==================================================\n")

            # Bucle interactivo de mensajes dentro del túnel
            while True:
                msg = input(f"BYOD-Tunnel ({username})> ").strip()
                if not msg:
                    continue

                if msg.upper() in ["LOGOUT", "EXIT"]:
                    print("\n[+] Solicitando cierre seguro de sesión...")
                    ssl_conn.sendall(b"LOGOUT")
                    ack = ssl_conn.recv(1024).decode('utf-8')
                    print(f"[+] Confirmación del servidor: {ack}")
                    break

                ssl_conn.sendall(msg.encode('utf-8'))
                reply = ssl_conn.recv(2048).decode('utf-8')
                print(f"[<- Gateway]: {reply}")

        else:
            print(f"\n[-] ACCESO DENEGADO: {res_data.get('msg')}")

        ssl_conn.close()

    except ssl.SSLError as e:
        print(f"\n[-] ERROR EN HANDSHAKE mTLS (Capa 1): {e}")
        print("    El certificado presentado no fue aceptado por la CA corporativa.")
    except ConnectionRefusedError:
        print("\n[-] ERROR CONEXIÓN: El servidor Gateway no está activo. Inicie la Opción 2 primero.")
    except Exception as e:
        print(f"\n[-] ERROR: {str(e)}")

def run_client(username="pdi_user1", password="Password123!", host="127.0.0.1", port=8443):
    """Cliente automatizado para pruebas rápidas"""
    try:
        ctx = build_client_context(username)
        raw_sock = socket.create_connection((host, port))
        ssl_conn = ctx.wrap_socket(raw_sock, server_hostname="gateway.usecure.es")

        print(f"[CLIENTE] Handshake TLS 1.3 mTLS completado exitosamente.")
        print(f"[CLIENTE] Cifrado activo: {ssl_conn.cipher()}")

        auth_payload = json.dumps({"username": username, "password": password})
        ssl_conn.sendall(auth_payload.encode('utf-8'))

        res = ssl_conn.recv(1024).decode('utf-8')
        res_data = json.loads(res)
        print(f"[CLIENTE] Respuesta Servidor: {res_data}")

        if res_data.get("status") == "AUTH_SUCCESS":
            ssl_conn.sendall(b"GET /api/recursos_investigacion")
            echo_res = ssl_conn.recv(1024).decode('utf-8')
            print(f"[CLIENTE] Recibido por Túnel: {echo_res}")

            print("[CLIENTE] Desmontando túnel VPN de forma segura...")
            ssl_conn.sendall(b"LOGOUT")
            logout_ack = ssl_conn.recv(1024).decode('utf-8')
            print(f"[CLIENTE] Confirmación cierre: {logout_ack}")

        ssl_conn.close()
    except ConnectionRefusedError:
        print("\n[-] ERROR: El Servidor Gateway no está en ejecución (Opción 2).")
    except Exception as e:
        print(f"\n[-] ERROR: {str(e)}")

if __name__ == "__main__":
    run_interactive_client()