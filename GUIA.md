# GUÍA DE DESARROLLADOR — PAI-2 BYODSEC

Cómo **preparar, lanzar, probar y comprobar** todo el proyecto. Todos los comandos se ejecutan desde la raíz del repositorio. Pensada para Windows (PowerShell o Git Bash); en Linux/macOS son idénticos salvo la captura de red (ver §7).

> Convención: `terminal 1`, `terminal 2`… = ventanas distintas que se dejan abiertas a la vez.

## 0. Requisitos

| Necesitas | Para qué | Comprobar |
|---|---|---|
| Python ≥ 3.10 | Todo | `python --version` |
| `pip install -r requirements-dev.txt` | Dependencias (cryptography, argon2-cffi, psutil, matplotlib, pytest, reportlab) | `python -c "import cryptography, argon2"` |
| OpenSSL (opcional) | Prueba de suites con un cliente independiente y verificar certificados | `openssl version` |
| Wireshark + Npcap (opcional) | Capturas `.pcap` (`dumpcap`, `tshark`) | `"C:\Program Files\Wireshark\tshark.exe" -v` |

Si falta OpenSSL, el test que lo usa se **omite** (no falla). Si falta Wireshark, `tools/capture_evidence.py` te avisa y no captura.

## 1. Primera puesta en marcha

```bash
pip install -r requirements-dev.txt
python -m src.pki.preload --reset      # ~25 s: CA + certificado de servidor + 300 usuarios con certificado
```

`--reset` **borra** `certs/` y `data/usecure.db` y lo regenera. Sin `--reset` solo añade lo que falte.
Resultado: `certs/ca/` (CA, CRL), `certs/server/`, `certs/clients/<usuario>/` (un `.crt` y un `.key` por usuario) y `data/usecure.db`.

> `certs/` y `data/*.db` **no se suben a git** (contienen claves privadas). Cada desarrollador genera los suyos.

Usuarios precargados: `pdi_user1…100` (rol PDI), `pas_user1…100` (PTGAS), `inv_user1…100` (Investigador). Contraseña de **prueba** común: `PRELOAD_PASSWORD` en `src/config.py`.

## 2. Lanzar los servicios

| Servicio | Comando | Puerto | Notas |
|---|---|---|---|
| Gateway VPN (TLS 1.3 + mTLS) | `python -m src.server.gateway` | 8443 | `--port N` para cambiarlo |
| Alta de usuarios (TLS 1.3) | `python -m src.server.enroll` | 8444 | Solo para registrar usuarios nuevos |
| Servidor sin cifrar | `python -m src.server.plain_server` | 8080 | **Solo benchmark/comparación**. Nunca fuera del laboratorio |
| Todo desde menú | `python main.py` | — | Opciones 2 (gateway) y 3 (alta) |

Parar: `Ctrl+C`. Cada arranque queda en el log (`GATEWAY_START` / `GATEWAY_STOP`).

## 3. Usar el cliente

```bash
# terminal 1
python -m src.server.gateway
# terminal 2
python main.py            # opción 4 = demo automática, 5 = sesión interactiva
```

Sesión interactiva: eliges el alias del certificado (p. ej. `pdi_user1`), usuario y contraseña. Comandos: `recurso <nombre>`, `logout`, o cualquier texto (eco cifrado). Recursos por perfil:

| Perfil | Recursos permitidos |
|---|---|
| PDI | `correo`, `docencia_virtual`, `gestion_academica` |
| PTGAS | `correo`, `gestion_administrativa`, `repositorio_documental` |
| Investigador | `correo`, `bases_datos_investigacion`, `repositorio_documental` |

Pedir un recurso de otro perfil devuelve `FORBIDDEN` y queda registrado como `UNAUTHORIZED`.

### Registrar un usuario nuevo (RF1)
```bash
# terminal 1
python -m src.server.enroll
# terminal 2
python main.py            # opción 6; código de alta = USECURE_ENROLL_CODE (por defecto en src/config.py)
```
Tu dispositivo genera la clave y la CSR; **la clave privada nunca viaja**. Se guarda `certs/clients/<usuario>/`. Después ya puedes entrar con ese certificado en el gateway.

### Revocar un certificado
```bash
python -m src.pki.admin revoke pdi_user1
python -m src.pki.admin list
```
El gateway recarga la CRL **sin reiniciarse**: el siguiente intento de ese carnet falla en el handshake.

## 4. Pruebas automáticas

```bash
python -m pytest                       # 37 pruebas, ~7 s
python -m pytest tests/test_tls_mtls.py -v
```

Los tests usan una **PKI, BD y puerto temporales**: no tocan tu `certs/` ni tu BD.

| Fichero | Qué comprueba |
|---|---|
| `test_tls_mtls.py` | TLS 1.3 y suite AEAD; TLS 1.2/1.1 rechazados; sin certificado, CA falsa y certificado revocado rechazados; el cliente rechaza un servidor no confiable; suite fuera de política cortada (con `openssl s_client` real) |
| `test_auth_session.py` | Doble capa; mensaje genérico ante contraseña errónea; carnet robado ≠ otro usuario; perfiles; bloqueo tras fallos; logout y corte brusco auditados |
| `test_store_audit_protocol.py` | Triggers de inmutabilidad; duplicados; log encadenado y detección de manipulación/borrado; framing, tamaño máximo y basura tras handshake |
| `test_enroll.py` | Registro completo por CSR; la clave privada no viaja; duplicados; entradas inválidas; CSR a nombre de otro |

## 5. Benchmark de 300 sesiones (RS3)

```bash
python -m benchmarks.load_test --sessions 300 --runs 3     # ~3 min
python -m benchmarks.load_test --sessions 30 --runs 1      # prueba rápida
```

Arranca el servidor (plano y luego TLS) en un **proceso aparte**, lanza N clientes a la vez (cada uno con su certificado), espera a que **todos** estén dentro (barrera → prueba de simultaneidad), mide mensajes pequeños (RTT) y grandes (throughput), hace logout y repite. Sale la **mediana** de las ejecuciones.

Salida en `evidences/bench/`: `benchmark_results.json` (todo), `benchmark_comparison.png`, `benchmark_latency.png`, y los logs de auditoría de cada modo.
Requiere que ya exista la precarga (§1) con ≥ N/3 usuarios por rol.

**Cómo leer el resultado:** el handshake TLS (firmas + ECDHE) es lo caro; cifrar los datos cuesta mucho menos. "Handshake sin carga" aísla el coste criptográfico; "Conexión con 300 a la vez" incluye la cola de 300 handshakes simultáneos. Cliente y servidor comparten máquina (loopback), así que las cifras son relativas, no absolutas.

## 6. Ataques simulados (extra)

```bash
python -m attacks.run_attacks
```
Lanza 11 ataques contra el gateway real (sin certificado, CA falsa, degradación a TLS 1.2, certificado robado, suplantación de usuario, fuerza bruta, servidor falso, sniffing MITM, manipulación de un bit, replay, certificado revocado). Escribe `evidences/attacks/attacks_report.md` y `.json`. Sale con error si **alguno** no queda bloqueado. Al terminar deja la PKI como estaba.

## 7. Capturas de red (RS4)

```bash
python -m tools.capture_evidence
```
Arranca los servidores, graba con `dumpcap` en la interfaz de **loopback** (`\Device\NPF_Loopback`), ejecuta 4 escenarios y analiza con `tshark`. Salida en `evidences/pcap/`:

| Fichero | Contenido |
|---|---|
| `tls13_mtls_session.pcapng` | Sesión legítima: el secreto y la contraseña **no aparecen** |
| `plain_session.pcapng` | La misma sesión sin cifrar: todo legible (comparación) |
| `tls12_rejected.pcapng` | Cliente solo-TLS 1.2: alerta `protocol_version` (70) y cierre |
| `no_client_cert.pcapng` | Cliente sin certificado: handshake abortado |
| `tls13_session.keylog` | Claves de sesión **de esa captura de demo** (para descifrarla) |
| `analysis.txt` | Informe automático |

Para abrirlo a mano en Wireshark: *Edit → Preferences → Protocols → TLS → (Pre)-Master-Secret log filename* = `tls13_session.keylog`.
Filtros útiles: `tls.handshake.type == 2` (ServerHello), `tls.record.opaque_type == 23` (datos cifrados).

> En TLS 1.3 el certificado del servidor y las alertas posteriores al ServerHello van **cifrados**; por eso `no_client_cert` no muestra el motivo en el pcap. La causa queda en el log de auditoría (`HANDSHAKE_FAILED`).

**Linux/macOS:** cambia `LOOPBACK` en `tools/capture_evidence.py` por `lo` (Linux) o `lo0` (macOS) y ejecuta con permisos de captura.

## 8. Log de auditoría (RS4)

`evidences/logs/audit.jsonl`: una línea JSON por evento, cada una con `prev` y `hash` (SHA-256 encadenado).

| Evento | Cuándo |
|---|---|
| `GATEWAY_START` / `GATEWAY_STOP` | Arranque y parada |
| `CONNECT` / `DISCONNECT` | Conexión (con CN, serial, versión TLS y suite) y desconexión (con motivo) |
| `HANDSHAKE_FAILED` | Rechazo en el handshake: sin certificado, CA ajena, revocado, TLS 1.2… (con motivo) |
| `CIPHER_REJECTED` | Suite fuera de política |
| `LOGIN_OK` / `LOGIN_FAILED` / `LOGIN_BLOCKED` / `ACCOUNT_LOCKED` | Autenticación de capa 2 |
| `UNAUTHORIZED` | CN ≠ usuario, certificado no vigente o recurso fuera del perfil |
| `REGISTER_OK` / `REGISTER_FAILED` | Altas |
| `LOGOUT`, `RESOURCE_OK`, `PROTOCOL_ERROR`, `CERT_REVOKED` | Resto |

Verificar que nadie lo ha manipulado:
```bash
python main.py            # opción 8
# o:
python -c "from src.server.audit import verify_chain; print(verify_chain())"   # (True, nº_eventos)
```

## 9. Comprobaciones manuales con OpenSSL

```bash
# Verificar la cadena de un certificado
openssl verify -CAfile certs/ca/ca.crt certs/clients/pdi_user1/pdi_user1.crt

# Inspeccionar EKU, SAN, KeyUsage...
openssl x509 -in certs/server/server.crt -noout -text

# Con el gateway en marcha: TLS 1.2 debe FALLAR, TLS 1.3 con certificado debe FUNCIONAR
openssl s_client -connect 127.0.0.1:8443 -tls1_2 -CAfile certs/ca/ca.crt
openssl s_client -connect 127.0.0.1:8443 -tls1_3 -CAfile certs/ca/ca.crt \
  -cert certs/clients/pdi_user1/pdi_user1.crt -key certs/clients/pdi_user1/pdi_user1.key \
  -servername gateway.usecure.es
```

## 10. Empaquetar la entrega

```bash
python -m tools.generate_memoria_pdf    # docs/Memoria_PAI2_ST2.pdf (si se usa el generador)
python -m tools.build_zip               # PAI2-ST2.zip (lista blanca; sin claves privadas)
```
El zip **no** incluye `certs/` ni la BD: quien lo descomprima ejecuta §1 y listo. Plazo: **27 de octubre, 23:59**, por Blackboard (no por email: penaliza).

## 11. Problemas frecuentes

| Síntoma | Causa y solución |
|---|---|
| `FileNotFoundError ... ca.crt` | No hay PKI: ejecuta §1 |
| El cliente: `certificate verify failed` | Regeneraste la PKI y el cliente usa certificados antiguos (o al revés): regenera todo con `--reset` |
| `Address already in use` | Otro gateway sigue vivo: ciérralo o usa `--port` |
| `tshark`/`dumpcap` no encontrados | Instala Wireshark con Npcap; la ruta por defecto es `C:\Program Files\Wireshark` |
| Captura vacía en Windows | Hay que grabar en `\Device\NPF_Loopback` (ya configurado); Npcap debe estar instalado con soporte de loopback |
| El benchmark da `ConnectionRefused` | Los puertos 18443/18080 están ocupados; usa `--tls-port` / `--plain-port` |
| `UnicodeEncodeError` en consola Windows | `set PYTHONIOENCODING=utf-8` |
| Cuenta `LOCKED` | Esperar `LOCKOUT_SECONDS` (60 s) o `Store().reset_failures("usuario")` |
