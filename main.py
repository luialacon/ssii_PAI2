"""Menú principal de PAI-2 BYODSEC (VPN SSL road-warrior para U-Secure).

Cada opción llama a un módulo de `src/`. Para automatizar usa los comandos
`python -m ...` descritos en GUIA.md.
"""
import sys


def menu() -> None:
    print("""
==================================================================
   PAI-2 BYODSEC  -  ROAD WARRIOR VPN TLS 1.3 + mTLS  (U-Secure)
==================================================================
 1. Generar PKI + precargar 300 usuarios con certificado (RS1/RF5)
 2. Arrancar gateway VPN (TLS 1.3 + mTLS)                 (RS2/RF2)
 3. Arrancar servicio de alta de usuarios (TLS 1.3)          (RF1)
 4. Cliente BYOD: demo automática
 5. Cliente BYOD: sesión interactiva
 6. Registrar un usuario nuevo (CSR + certificado)           (RF1)
 7. Benchmark de 300 sesiones: TLS frente a texto plano      (RS3)
 8. Verificar integridad del log de auditoría                (RS4)
 9. Revocar el certificado de un usuario
 0. Salir
==================================================================""")


def main() -> None:
    while True:
        menu()
        opt = input("Seleccione una opción: ").strip()
        if opt == "1":
            from src.pki.preload import bootstrap
            print("[PKI] Esto BORRA la PKI y la BD actuales y las regenera.")
            if input("¿Continuar? (s/N): ").strip().lower() == "s":
                n = bootstrap(per_role=100, reset=True)
                print(f"[PKI] CA, servidor y {n} usuarios con certificado creados.")
        elif opt == "2":
            from src.server.gateway import start_gateway
            start_gateway()
        elif opt == "3":
            from src.server.enroll import create_enroll_server
            from src.pki import ca
            ca.init_pki(force=False)
            create_enroll_server().serve_forever()
        elif opt == "4":
            from src.client.byod_client import run_client
            run_client()
        elif opt == "5":
            from src.client.byod_client import run_interactive_client
            run_interactive_client()
        elif opt == "6":
            from src.client.register import run_register_interactive
            run_register_interactive()
        elif opt == "7":
            from benchmarks.load_test import run_300_benchmark
            raw = input("Rondas (cada una ~1 min; 3 = resultado de la memoria) [1]: ").strip()
            runs = int(raw) if raw.isdigit() and int(raw) > 0 else 1
            print(f"[BENCH] {runs} ronda(s) x (plano + TLS) con 300 sesiones. Tarda unos {runs} min; no está colgado.")
            run_300_benchmark(runs=runs)
        elif opt == "8":
            from src.server.audit import verify_chain
            ok, n = verify_chain()
            print(f"[AUDIT] {n} eventos leídos. Cadena de hashes: {'ÍNTEGRA' if ok else 'ROTA (manipulada)'}")
        elif opt == "9":
            from src.pki.admin import revoke_user
            user = input("Usuario a revocar: ").strip()
            try:
                print(f"[PKI] Revocado (serial {revoke_user(user):x}).")
            except FileNotFoundError:
                print("[-] Ese usuario no tiene certificado local.")
        elif opt == "0":
            print("Saliendo...")
            sys.exit(0)
        else:
            print("Opción inválida.")


if __name__ == "__main__":
    main()
