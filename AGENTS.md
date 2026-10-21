# AGENTS.md — Registro del uso de IA en PAI-2

Este fichero es la **evidencia del uso de IA** (Claude Code) y la base de la reflexión de la memoria. Resume *qué generó la IA, cómo se validó y qué hubo que corregir*. Se incluye en el zip.

## 1. Reparto del trabajo

| Quién | Qué |
|---|---|
| Equipo (humano) | Elegir tecnología (sockets TLS), aprobar el plan, fijar prioridades, revisar y aceptar cada bloque, rellenar el seguimiento, decidir qué se entrega |
| Luis (humano) | Base inicial del proyecto (commit `7ea80f8`): sockets TLS 1.3 + mTLS, CA, benchmark básico |
| IA (Claude Code) | Auditoría de la base frente a la rúbrica, plan, código de `src/`, `tests/`, `benchmarks/`, `attacks/`, `tools/` y la documentación |

La IA **no** decidió el alcance: partió de la rúbrica y del enunciado (`docs/`), propuso un plan y no empezó a implementar hasta que el equipo lo aprobó.

## 2. Cómo se validó lo generado

Ningún bloque se dio por bueno solo porque "compilara":
1. **Pruebas automáticas** (`pytest`, 37) escritas para *intentar romper* la defensa, no para confirmar el camino feliz (sin certificado, CA falsa, TLS 1.2, revocado, carnet de otro usuario, log manipulado, trigger de inmutabilidad…).
2. **Herramientas independientes** del código generado: `openssl verify`/`x509` para certificados, `openssl s_client` para suites, `tshark` para los pcaps.
3. **Ejecución real**: gateway y cliente como procesos separados, benchmark con 300 sesiones, 11 ataques.
4. **Lectura de los logs de auditoría** para confirmar que *quien rechazó* fue el servidor, no un error del cliente.

## 3. Errores de la IA detectados y corregidos

| # | Qué falló | Cómo se detectó | Corrección |
|---|---|---|---|
| 1 | Los tests de "cliente sin certificado / CA falsa / revocado" fallaron (3 de 35): esperaba que el rechazo llegara como excepción al conectar | `pytest` | En TLS 1.3 el cliente cree terminar el handshake **antes** de que el servidor valide su certificado, así que el rechazo llega después. El test ahora acepta excepción **o** cierre, y además exige el evento `HANDSHAKE_FAILED` en el log del servidor (más estricto, no más laxo) |
| 2 | El ataque de *replay* salió "NO bloqueado" | `attacks.run_attacks` | **No era un fallo de la defensa, sino del criterio de la prueba**: se asumía que un servidor que rechaza no responde nada. Se leyó el log (`DECRYPTION_FAILED_OR_BAD_RECORD_MAC`, 0 sesiones abiertas) y se corrigió el criterio. Se documentó en lugar de "arreglar" la prueba para que pasara |
| 3 | Primer benchmark: el handshake TLS aparecía como **+2657 %**, una cifra engañosa | Revisión crítica del resultado | Se añadió una medición *sin carga* (11 ms frente a 0,4 ms) que separa el coste criptográfico del efecto cola de 300 handshakes simultáneos, y se explican ambos |
| 4 | Se pretendía "forzar" las suites TLS 1.3 con `set_ciphers`; falla (*No cipher can be selected*) | Probando en el intérprete | Se descubrió que este Python/OpenSSL no permite recortar suites TLS 1.3. Solución: preferencia del servidor + lista blanca post-handshake + **prueba con `openssl s_client`**. La limitación se declara en README y memoria |
| 5 | Una frase de la IA afirmaba que "con Python ≥ 3.13 bastaría `set_ciphersuites()`" | Revisión del texto | **No se podía respaldar**: se eliminó. Lo mismo con una mención a `pyOpenSSL`, suavizada a "no evaluada" |
| 6 | 300 logins simultáneos usarían ~19 GB de RAM (Argon2id ≈ 64 MB cada uno) | Cálculo antes de lanzar el benchmark | Semáforo que limita a 4 verificaciones simultáneas |
| 7 | El análisis con `tshark` mostraba basura en lugar del texto descifrado | Revisar el informe generado | El campo `tls.app_data` es el texto **cifrado**; se cambió a `follow,tls` con keylog |
| 8 | Errores de escritura de los scripts (f-string con `\`, saltos de línea reales dentro de cadenas) | Ejecución | Corregidos con la herramienta de edición y comprobación de sintaxis |
| 9 | Rutas de la CA calculadas al importar el módulo: los tests no podían redirigirlas a una PKI temporal | Diseño de los tests | Se calculan al usarlas |

## 4. Qué se revisó a mano y por qué

- **Que las defensas sean reales**: comprobar en el log que el rechazo viene del servidor y por el motivo esperado.
- **Que el informe no exagere**: p. ej. "las alertas de TLS 1.3 van cifradas, por eso no se ven en el pcap" se explica en lugar de ocultarse.
- **Material sensible**: claves privadas fuera de git y del zip (`build_zip.py` aborta si detecta una); contraseñas de demo etiquetadas como tales.

## 5. Límites del uso de IA (reflexión)

- La IA es muy buena generando estructura y tests, pero **tiende a dar por correcto lo que "debería" funcionar**: casi todos los errores de §3 aparecieron al *ejecutar*, no al leer el código.
- Un resultado desfavorable (el replay) puede ser un fallo de la prueba y no de la defensa; y lo contrario también. Hay que **leer el log**, no el semáforo verde/rojo.
- Responsabilidad: el equipo responde de lo entregado; todo lo que aparece en la memoria se ha ejecutado y se puede reproducir con `GUIA.md`.
