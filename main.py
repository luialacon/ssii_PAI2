import os
import sys

def menu():
    print("""
==================================================
   PROYECTO PAI-2: BYODSEC ROAD WARRIOR VPN TLS
==================================================
1. Generar PKI y Certificados X.509v3 (RS1)
2. Arrancar Servidor Gateway VPN (TLS 1.3 + mTLS)
3. Cliente BYOD - Prueba Automática Rápida
4. Cliente BYOD - Login Manual Interactivo (Pruebas)
5. Lanzar Benchmark de Carga (300 Usuarios - RS3)
0. Salir
==================================================
    """)

def main():
    while True:
        menu()
        opt = input("Seleccione una opción: ").strip()
        if opt == "1":
            from src.pki.cert_generator import setup_pki
            setup_pki()
        elif opt == "2":
            from src.server.gateway import start_gateway
            start_gateway()
        elif opt == "3":
            from src.client.byod_client import run_client
            run_client()
        elif opt == "4":
            from src.client.byod_client import run_interactive_client
            run_interactive_client()
        elif opt == "5":
            import asyncio
            from benchmarks.load_test_300 import run_300_benchmark
            asyncio.run(run_300_benchmark())
        elif opt == "0":
            print("Saliendo...")
            sys.exit(0)
        else:
            print("Opción inválida.")

if __name__ == "__main__":
    main()