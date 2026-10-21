# PAI-2 BYODSEC — VPN SSL "road warrior" para la Universidad U-Secure

> Seguridad en Sistemas de Información e Internet (SSII) · ETSII · Universidad de Sevilla · Grupo **ST-2**
> Este documento explica **qué es el proyecto, cómo está construido y por qué**. Para *usarlo y probarlo* ver [`GUIA.md`](./GUIA.md); para saber qué cambió respecto a la versión inicial ver [`CHANGELOG.md`](./CHANGELOG.md).

## 1. Qué es

Un gateway VPN mínimo y un cliente BYOD (*Bring Your Own Device*) que permiten a PDI, PTGAS e Investigadores acceder a recursos corporativos desde dispositivos personales a través de Internet, cumpliendo la política de seguridad de la universidad:

* **Confidencialidad, integridad y autenticidad** de todo el tráfico: **TLS 1.3** exclusivamente.
* **Autenticación en dos capas (RF2)**: certificado X.509 del dispositivo (**mTLS**, capa de transporte) **+** usuario/contraseña corporativos (capa de aplicación).
* **PKI propia** (CA interna) con ciclo de vida completo: emisión por CSR, revocación (CRL) y precarga de usuarios.
* **Evidencias** (RS4): capturas `.pcap`, logs de auditoría con cadena de hashes y benchmark de 300 sesiones simultáneas.

Tecnología de transporte elegida: **sockets TLS nativos** (módulo `ssl` de Python sobre OpenSSL), no REST ni gRPC. Motivo: control total del handshake, nada que oculte lo que se ve en el `.pcap`, y cero dependencias de servidor web.

## 2. Arquitectura

```
   DISPOSITIVO BYOD (cliente)                      INFRAESTRUCTURA U-SECURE
 ┌─────────────────────────────┐                ┌──────────────────────────────────────────┐
 │ byod_client.py              │                │  gateway.py  (TLS 1.3 + mTLS, :8443)      │
 │  · carnet X.509 (.crt/.key) │  TLS 1.3 + mTLS│   ├─ net.py       hilo por conexión       │
 │  · CA raíz de U-Secure      │ ◄────────────► │   ├─ session.py   login 2 capas, recursos │
 │                             │   (Internet)   │   ├─ store.py     SQLite (inmutable)      │
 │ register.py                 │                │   └─ audit.py     log JSON encadenado     │
 │  · genera clave + CSR       │  TLS 1.3       │  enroll.py   (TLS 1.3 sin cert cliente,   │
 │                             │ ◄────────────► │               :8444) alta + firma de CSR  │
 └─────────────────────────────┘                │  pki/ca.py   CA interna + CRL             │
                                                └──────────────────────────────────────────┘
```

### 2.1 Flujo de una sesión (las dos capas)

```
Cliente                                           Gateway
  │── ClientHello (solo TLS 1.3) ───────────────────►│
  │◄── ServerHello + cert. servidor + CertRequest ───│  (cifrado desde aquí, claves ECDHE efímeras)
  │  [1] cliente valida cert. servidor: CA propia + nombre gateway.usecure.es
  │── cert. cliente + CertificateVerify ────────────►│
  │                    [2] servidor valida: firma de la CA, vigencia, EKU clientAuth, NO en CRL
  │════════════ túnel TLS 1.3 (AES-256-GCM / ChaCha20-Poly1305) ═══════════
  │── LOGIN {usuario, contraseña} ──────────────────►│  [3] CN del cert == usuario; cert vigente en BD;
  │                                                  │      cuenta no bloqueada; Argon2id verifica
  │◄── OK {rol} ─────────────────────────────────────│
  │── MSG / RESOURCE ───────────────────────────────►│  acceso a recursos según el perfil (rol)
  │── LOGOUT ───────────────────────────────────────►│
  │◄── BYE ──────────────────────────────────────────│  close_notify → claves de sesión descartadas
```

### 2.2 Ciclo de vida de los certificados

```
 init_pki ──► CA raíz (ECDSA P-384, pathlen=0) ──► cert. servidor (EKU serverAuth, SAN)
 Alta (RF1): dispositivo genera clave ──► CSR ──► enroll.py valida ──► CA firma (EKU clientAuth) ──► cert. al dispositivo
 Precarga (RF5): preload.py ──► N usuarios por rol, con certificado
 Revocación: admin.py revoke <usuario> ──► serial a la CRL + marca en BD ──► el gateway recarga la CRL solo
```

## 3. Estructura de carpetas

```
PAI_2/
├── main.py                    Menú principal (PKI, servidores, clientes, benchmark, auditoría)
├── src/
│   ├── config.py              Rutas, puertos, política TLS y límites (único sitio con "números mágicos")
│   ├── protocol.py            Mensajes JSON con prefijo de longitud (síncrono y asyncio)
│   ├── pki/
│   │   ├── ca.py              CA: crear, emitir, firmar CSR, revocar, CRL
│   │   ├── cert_generator.py  Opción 1 del menú (envoltorio de ca.init_pki)
│   │   ├── preload.py         Precarga de usuarios + certificados (RF5)
│   │   └── admin.py           `revoke <usuario>` / `list`
│   ├── server/
│   │   ├── gateway.py         Contexto TLS 1.3 + mTLS y arranque del gateway
│   │   ├── net.py             Servidor TCP con hilos, handshake TLS por conexión, cierre limpio
│   │   ├── session.py         Lógica de sesión: login 2 capas, perfiles, logout
│   │   ├── enroll.py          Servicio de alta (registro + CSR)
│   │   ├── store.py           SQLite con triggers de inmutabilidad
│   │   ├── audit.py           Log JSONL con cadena de hashes + verificador
│   │   └── plain_server.py    Servidor SIN cifrar (solo para el benchmark)
│   ├── client/
│   │   ├── byod_client.py     Cliente mTLS (clase ByodClient, demo y modo interactivo)
│   │   └── register.py        Alta desde el dispositivo (clave + CSR)
│   └── security/
│       ├── kdf.py             Argon2id (hash/verify)
│       └── password_policy.py Política de contraseñas robustas
├── benchmarks/                load_test.py (300 sesiones, TLS vs plano) y plot.py (gráficas)
├── attacks/                   run_attacks.py (11 ataques) y relay.py (retransmisor MITM)
├── tests/                     pytest (37 pruebas)
├── tools/                     capture_evidence.py (pcaps + tshark), build_zip.py
├── evidences/                 logs/ · pcap/ · bench/ · attacks/   (se generan, ver GUIA.md)
├── certs/  data/              PKI y BD generadas (NO se versionan: contienen claves privadas)
└── docs/                      Enunciado, presentación y memoria
```

## 4. Funciones y clases principales

| Módulo | Elemento | Qué hace |
|---|---|---|
| `pki/ca.py` | `create_ca()` | CA raíz autofirmada ECDSA P-384, `pathlen=0`, `keyCertSign`+`cRLSign` |
| | `issue_server_cert()` | Certificado del gateway (EKU serverAuth, SAN DNS+IP) |
| | `make_csr()` / `sign_csr()` | El dispositivo pide el carnet; la CA comprueba firma y CN y **ignora** extensiones de la CSR |
| | `issue_client_cert()` | Emisión administrativa (precarga) con EKU clientAuth |
| | `revoke()` / `rebuild_crl()` | Añade serial a la CRL y regenera `ca_bundle.pem` (CA + CRL) |
| `server/gateway.py` | `build_server_context()` | `min=max=TLS1.3`, `CERT_REQUIRED`, `VERIFY_CRL_CHECK_LEAF`, `num_tickets=0` |
| | `ReloadingContext` | Recarga el contexto si cambia la CRL (revocación sin reiniciar) |
| `server/net.py` | `ThreadedServer` | Hilo por cliente; handshake dentro del hilo; lista blanca de suites; auditoría de fallos |
| | `close_tls()` | `unwrap()` → `close_notify` → cierre (RF4) |
| `server/session.py` | `make_session_handler()` | Orquesta conexión → autenticación → bucle → desconexión (todo auditado) |
| | `_authenticate()` | Capa 2: CN==usuario, cert vigente, bloqueo, Argon2id con semáforo anti-DoS |
| `server/store.py` | `Store` | Altas atómicas, revocación, bloqueo de cuentas; triggers `IMMUTABLE` |
| `server/audit.py` | `AuditLog`, `verify_chain()` | Una línea JSON por evento, cada una con el SHA-256 de la anterior |
| `server/enroll.py` | `make_enroll_handler()` | Valida usuario/rol/código/contraseña, firma la CSR y da de alta |
| `protocol.py` | `send_frame/recv_frame` (+`a*`) | Longitud (4 bytes) + JSON; límite de tamaño |
| `client/byod_client.py` | `ByodClient` | `connect`, `login`, `send_message`, `get_resource`, `logout` |
| `benchmarks/load_test.py` | `run_once()` | 300 sesiones con barrera de simultaneidad; CPU/RAM del proceso servidor |

## 5. Decisiones de seguridad (resumen)

| Requisito | Cómo se cumple | Dónde |
|---|---|---|
| RS1 PKI + mTLS | CA interna; `CERT_REQUIRED`; el cliente valida servidor (CA + nombre) | `ca.py`, `gateway.py`, `byod_client.py` |
| RS2 TLS 1.3 | `min=max=TLSv1_3`; suites AEAD+PFS (`TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`); sin tickets | `gateway.py`, `net.py` |
| RS3 300 usuarios | Hilos + semáforo Argon2id; benchmark con 300 sesiones reales y comparativa con plano | `benchmarks/` |
| RS4 Auditoría | pcaps + log encadenado (CONNECT, LOGIN_*, UNAUTHORIZED, HANDSHAKE_FAILED, LOGOUT, DISCONNECT…) | `tools/capture_evidence.py`, `audit.py` |
| RF1 Registro/inmutabilidad | CSR; triggers SQLite; re-emisión solo revocando | `enroll.py`, `store.py` |
| RF2 Doble capa | mTLS + contraseña Argon2id + CN==usuario | `session.py` |
| RF4 Cierre | `LOGOUT` → `close_notify`; sin tickets de reanudación | `session.py`, `net.py` |
| RF5 Precarga | 300 usuarios (100 por rol) con certificado | `preload.py` |

**Limitación conocida y declarada.** El módulo `ssl` de Python no ofrece una llamada para fijar las suites de TLS 1.3 (`set_ciphers()` solo gobierna TLS ≤ 1.2; con nombres TLS 1.3 falla con *No cipher can be selected*). Por eso las suites no se *recortan* en el contexto: el servidor impone su preferencia (`OP_CIPHER_SERVER_PREFERENCE`, AES-256-GCM primero) y **rechaza tras el handshake** cualquier suite fuera de `config.ALLOWED_CIPHERS` (evento `CIPHER_REJECTED`). Está demostrado con un cliente OpenSSL real independiente (`tests/test_tls_mtls.py`). Recortarlas en el propio handshake requeriría una librería con acceso directo a OpenSSL (no evaluada) o un proxy TLS delante; no se adoptó para no añadir dependencias. La tercera suite de OpenSSL (`TLS_AES_128_GCM_SHA256`) también es AEAD+PFS, pero queda fuera de la política del enunciado.

## 6. Tecnologías

Python 3.10 · `ssl`/`socket`/`asyncio` (OpenSSL) · `cryptography` (X.509, CSR, CRL) · `argon2-cffi` (Argon2id) · SQLite · `psutil` + `matplotlib` (benchmark) · `pytest` · Wireshark (`dumpcap`/`tshark`) + Npcap (capturas) · `reportlab` (memoria).

## 7. Arranque rápido

```bash
pip install -r requirements-dev.txt
python -m src.pki.preload --reset     # PKI + 300 usuarios con certificado
python -m src.server.gateway          # terminal 1
python main.py                        # terminal 2 → opción 4 (demo) o 5 (interactivo)
python -m pytest                      # 37 pruebas
```

Credenciales de **prueba** de los usuarios precargados (`pdi_user1…100`, `pas_user1…100`, `inv_user1…100`): ver `PRELOAD_PASSWORD` en `src/config.py`. Son valores de demostración; en un despliegue real se sustituirían.
