# Informe de ataques simulados (entorno controlado)

Fecha: 2026-10-21 16:11  |  Ataques bloqueados: **11/11**

Log de auditoría: 52 eventos, cadena de hashes ÍNTEGRA.

| # | Ataque | Defensa | Resultado | Evidencia |
|---|---|---|---|---|
| 1 | Cliente sin certificado | mTLS obligatorio (CERT_REQUIRED) | ✅ Bloqueado | 1 evento(s) HANDSHAKE_FAILED |
| 2 | Suplantación con certificado de CA falsa | El servidor valida la cadena contra NUESTRA CA, no por el nombre | ✅ Bloqueado | 1 HANDSHAKE_FAILED nuevo(s) |
| 3 | Ataque de degradación a TLS 1.2 | min = max = TLS 1.3 en el servidor | ✅ Bloqueado | 1 HANDSHAKE_FAILED nuevo(s) |
| 4 | Certificado robado, sin contraseña | Doble capa: además del carnet se exige la contraseña (Argon2id) | ✅ Bloqueado | 1 LOGIN_FAILED |
| 5 | Usar un carnet para entrar como otro usuario | El usuario debe coincidir con el CN del certificado | ✅ Bloqueado | 1 UNAUTHORIZED (cn_mismatch) |
| 6 | Fuerza bruta de contraseñas | Bloqueo temporal de la cuenta | ✅ Bloqueado | 1 ACCOUNT_LOCKED |
| 7 | Servidor falso (suplantación del gateway) | El cliente solo confía en la CA de U-Secure y valida el nombre (autenticación del servidor) | ✅ Bloqueado | el cliente corta antes de enviar credenciales |
| 8 | Interceptación (sniffing) en un retransmisor MITM | Cifrado AEAD con TLS 1.3 | ✅ Bloqueado | ver evidences/pcap/analysis.txt para la comparación con tráfico plano |
| 9 | Manipulación de un bit en tránsito | Integridad AEAD (AES-GCM / ChaCha20-Poly1305): el registro alterado no se acepta | ✅ Bloqueado | la sesión se corta con bad_record_mac; ningún dato manipulado llega a la aplicación |
| 10 | Repetición (replay) de una sesión grabada | Claves efímeras (ECDHE) y aleatorios distintos por sesión: lo grabado no vale en otra sesión | ✅ Bloqueado | 1 HANDSHAKE_FAILED nuevo(s), 0 sesiones abiertas |
| 11 | Uso de un certificado revocado | Comprobación de la CRL en el handshake | ✅ Bloqueado | 1 HANDSHAKE_FAILED nuevo(s) |

## Detalle

### 1. Cliente sin certificado
- **Qué se intenta:** Un dispositivo no registrado intenta conectar.
- **Defensa:** mTLS obligatorio (CERT_REQUIRED)
- **Observado:** SSLError: [SSL: TLSV13_ALERT_CERTIFICATE_REQUIRED] tlsv13 alert certificate required (_ssl.c:2578)

### 2. Suplantación con certificado de CA falsa
- **Qué se intenta:** El atacante crea su propia CA (con el mismo nombre) y se firma un carnet como 'pdi_user5'.
- **Defensa:** El servidor valida la cadena contra NUESTRA CA, no por el nombre
- **Observado:** respuesta del servidor: b''

### 3. Ataque de degradación a TLS 1.2
- **Qué se intenta:** Un cliente (o un atacante) fuerza una versión antigua.
- **Defensa:** min = max = TLS 1.3 en el servidor
- **Observado:** SSLError: [SSL: TLSV1_ALERT_PROTOCOL_VERSION] tlsv1 alert protocol version (_ssl.c:1007)

### 4. Certificado robado, sin contraseña
- **Qué se intenta:** Roban el archivo del carnet de 'pdi_user5' (capa 1 superada) pero no saben la contraseña.
- **Defensa:** Doble capa: además del carnet se exige la contraseña (Argon2id)
- **Observado:** respuesta: AUTH_FAILED / Credenciales inválidas

### 5. Usar un carnet para entrar como otro usuario
- **Qué se intenta:** Con el carnet de 'pdi_user5' e intentando identificarse como 'inv_user5' (incluso sabiendo su contraseña).
- **Defensa:** El usuario debe coincidir con el CN del certificado
- **Observado:** respuesta: AUTH_FAILED

### 6. Fuerza bruta de contraseñas
- **Qué se intenta:** 5 intentos fallidos seguidos.
- **Defensa:** Bloqueo temporal de la cuenta
- **Observado:** respuesta: LOCKED

### 7. Servidor falso (suplantación del gateway)
- **Qué se intenta:** El atacante monta un servidor con el nombre gateway.usecure.es y certificado de su CA falsa.
- **Defensa:** El cliente solo confía en la CA de U-Secure y valida el nombre (autenticación del servidor)
- **Observado:** SSLCertVerificationError: unable to get local issuer certificate

### 8. Interceptación (sniffing) en un retransmisor MITM
- **Qué se intenta:** Un atacante en medio reenvía el tráfico y lo lee.
- **Defensa:** Cifrado AEAD con TLS 1.3
- **Observado:** el atacante capturó 3775 bytes; contienen el secreto o la contraseña: NO

### 9. Manipulación de un bit en tránsito
- **Qué se intenta:** El atacante cambia UN solo bit de un mensaje cifrado.
- **Defensa:** Integridad AEAD (AES-GCM / ChaCha20-Poly1305): el registro alterado no se acepta
- **Observado:** SSLError: [SSL: SSLV3_ALERT_BAD_RECORD_MAC] sslv3 alert bad record mac (_ssl.c:2578)

### 10. Repetición (replay) de una sesión grabada
- **Qué se intenta:** El atacante graba la sesión legítima y reenvía exactamente los mismos bytes en una conexión nueva.
- **Defensa:** Claves efímeras (ECDHE) y aleatorios distintos por sesión: lo grabado no vale en otra sesión
- **Observado:** el servidor respondió con un ServerHello nuevo y falló al descifrar lo reenviado: [SSL: DECRYPTION_FAILED_OR_BAD_RECORD_MAC] decryption failed or bad record mac (_ssl.c:100

### 11. Uso de un certificado revocado
- **Qué se intenta:** Se revoca el carnet de pas_user5 (robo/pérdida) y se intenta usar.
- **Defensa:** Comprobación de la CRL en el handshake
- **Observado:** respuesta del servidor: b''
