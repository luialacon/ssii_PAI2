# CHANGELOG — cambios respecto a la versión original

**Base:** commit `7ea80f8` ("commit inicial") de la rama `raimundo_dev`, trabajo previo de Luis (~500 líneas).
**Resultado:** el mismo concepto (sockets TLS 1.3 + mTLS en Python) elevado a los requisitos completos del enunciado y de la rúbrica.

La base de Luis ya acertaba en lo esencial: sockets TLS nativos, `min=max=TLS 1.3`, `CERT_REQUIRED`, CA interna y un flujo de login + logout. Se **conserva** esa idea y se corrigen las carencias que impedían cumplir RS1–RS4 y RF1–RF5.

## Resumen por requisito

| Req. | Versión original | Ahora |
|---|---|---|
| RS1 PKI/mTLS | CA y certificados RSA-2048 sin SKI/AKI/KeyUsage; sin revocación; claves privadas **en git** | CA ECDSA P-384 (`pathlen=0`), KeyUsage/SKI/AKI/CRLDP, emisión por CSR, **revocación con CRL** recargada en caliente; claves fuera de git |
| RS2 TLS 1.3 | TLS 1.3 forzado; suites "por defecto" sin comprobar | TLS 1.3 + preferencia del servidor + lista blanca de suites (`CIPHER_REJECTED`) + sin tickets; **probado** con tests y cliente OpenSSL |
| RS3 300 usuarios | 300 tareas con **un solo certificado**; sin comparativa ni CPU/RAM reales; handshake en el hilo de aceptación | 300 usuarios/certificados distintos, barrera de simultaneidad, servidor en proceso aparte, **TLS frente a plano**, CPU/RAM/latencia p50-p99/throughput, gráficas |
| RS4 Auditoría | `audit.log` de texto, sin fallos de handshake ni cadena | Log JSON con **cadena de hashes**, 15+ tipos de evento, pcaps y análisis con tshark |
| RF1 Registro | No existía | Alta con CSR (la clave privada no viaja), política de contraseñas, **inmutabilidad por triggers** |
| RF2 Doble capa | mTLS + contraseña, pero sin relacionarlas | Además **CN del certificado == usuario** y certificado vigente en BD |
| RF4 Cierre | `LOGOUT` y cierre de socket | `LOGOUT` → `close_notify` → cierre; sin tickets de reanudación; todo auditado |
| RF5 Precarga | 3 usuarios con contraseña **en texto plano** | 300 usuarios (100 por rol) con **Argon2id** y certificado |

## Detalle por área

### Seguridad de la PKI — `src/pki/`
- **Nuevo `ca.py`**: toda la lógica de CA (antes mezclada en un único `setup_pki`). Curvas elípticas (P-384 CA/servidor, P-256 usuarios) en vez de RSA-2048; firma SHA-384.
- La CA es `pathlen=0` y solo `keyCertSign`/`cRLSign`; las hojas llevan `digitalSignature`, EKU `serverAuth`/`clientAuth`, SKI, AKI y punto de distribución de CRL. *Por qué:* un certificado de usuario no puede actuar como CA ni como servidor.
- **CSR** (`make_csr`/`sign_csr`): la CA firma peticiones, comprueba la firma y que el CN sea el usuario, e **ignora las extensiones pedidas** por el cliente. *Por qué:* el solicitante no debe poder auto-concederse permisos.
- **Revocación** (`revoke`, `rebuild_crl`, `admin.py`) y `ca_bundle.pem` (CA + CRL).
- **Nuevo `preload.py`**: 300 usuarios; Argon2id calculado en paralelo.
- `cert_generator.py` pasa a ser un envoltorio de una línea de `ca.init_pki`.

### Servidor — `src/server/`
- **`gateway.py` reescrito**: `VERIFY_CRL_CHECK_LEAF`, `num_tickets = 0`, `OP_CIPHER_SERVER_PREFERENCE`, y `ReloadingContext` para que una revocación surta efecto sin reiniciar.
- **Nuevo `net.py`**: el handshake TLS pasó del hilo de aceptación al hilo de cada cliente. *Por qué:* en la versión original un cliente lento bloqueaba a todos los demás y los 300 handshakes se serializaban. Incluye `close_tls()` (`close_notify`).
- **Nuevo `session.py`** (lógica de sesión): doble capa real, perfiles de acceso a recursos (RF5), bloqueo por intentos fallidos (mismo concepto que PAI-1, reimplementado sobre la nueva BD), mensaje de error **genérico** y verificación "señuelo" para usuarios inexistentes (no se filtra por tiempo si el usuario existe), y un **semáforo** que limita las verificaciones Argon2id simultáneas (cada una usa ~64 MB; sin límite, 300 logins agotarían la RAM y sería una vía de DoS).
- **Nuevo `store.py`**: SQLite con triggers que impiden modificar identidad, rol, clave pública o borrar registros (RF1).
- **Nuevo `audit.py`**: log JSONL encadenado por hash + `verify_chain()`.
- **Nuevo `enroll.py`**: servicio de alta (TLS 1.3 sin certificado de cliente, porque aún no existe). **Nuevo `plain_server.py`** (solo benchmark).
- **Eliminado** `data/preloaded_users.json` (contraseñas en claro): sustituido por la BD.

### Protocolo — `src/protocol.py` (nuevo)
- Mensajes JSON con **prefijo de longitud**. *Por qué:* la versión original hacía `recv(1024)` y asumía un mensaje por lectura; TCP no garantiza eso (mensajes partidos o pegados) y no había límite de tamaño. Ahora hay límite (64 KB) y los datos corruptos se rechazan sin tumbar el servidor.

### Cliente — `src/client/`
- `byod_client.py` reescrito como clase `ByodClient` reutilizable por tests, benchmark y ataques. `check_hostname = True` (antes `False`): el cliente ahora **valida el nombre** del servidor además de la CA.
- **Nuevo `register.py`**: alta con CSR.

### Rendimiento — `benchmarks/`
- `load_test_300.py` **sustituido** por `load_test.py` + `plot.py`. Antes: un único certificado, medía solo TLS, CPU/RAM del *equipo* completo antes/después. Ahora: 300 certificados, comparativa **plano frente a TLS** con el mismo código de servidor (la diferencia es el cifrado), CPU/RAM **del proceso servidor**, p50/p95/p99, throughput, handshake con y sin carga, mediana de varias ejecuciones y gráficas.

### Evidencias y ataques
- **Nuevo `tools/capture_evidence.py`**: 4 capturas reproducibles con `dumpcap` + análisis con `tshark` (incluye descifrado con keylog solo para la demo).
- **Nuevo `attacks/`**: 11 ataques con informe `evidences/attacks/attacks_report.md` (extra +10 %).

### Pruebas
- **Nuevo `tests/`**: 37 pruebas (no había ninguna). Corren sobre PKI/BD/puerto temporales.

### Higiene del repositorio
- **Nuevo `.gitignore`**; **retiradas de git** las claves privadas (`certs/**/*.key`), los `__pycache__` y el log antiguo. *Por qué:* una clave privada en un repositorio deja de ser privada. **Importante:** las claves que estuvieron en el historial de `7ea80f8` deben considerarse comprometidas; no se reutilizan (la PKI se regenera).
- `requirements.txt`: se quita `flask` (no se usaba) y `pytest` pasa a `requirements-dev.txt`; se añade `argon2-cffi`.
- Nuevo `tools/build_zip.py` (lista blanca que impide empaquetar claves).
- `main.py`: menú ampliado de 5 a 9 opciones.

### Documentación
- Nuevos `README.md`, `GUIA.md`, este `CHANGELOG.md` y la memoria.

## Decisiones y limitaciones declaradas
- **Suites TLS 1.3:** Python no ofrece API para recortarlas en el handshake; se impone preferencia + lista blanca post-handshake (ver README §5).
- **Banco de pruebas en una sola máquina** (loopback): las cifras del benchmark son relativas.
- **Valores de demostración** (`PRELOAD_PASSWORD`, `ENROLL_CODE`) para que el proyecto sea reproducible; en producción se sustituirían y el código de alta no estaría en el repositorio.
- **Claves de usuario sin passphrase** en disco (como el original); en un despliegue real irían en el almacén seguro del sistema.
