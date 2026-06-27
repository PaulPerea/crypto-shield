# DAC Crypto Demo
## Arquitectura de Datos Sensibles con AES-256-GCM + RSA-2048-OAEP
### Stack: Quarkus 3.9 · Java 21 · Maven 3.9.9

---

## Índice

1. [Estructura del proyecto](#1-estructura-del-proyecto)
2. [Pre-requisitos](#2-pre-requisitos)
3. [Cómo levantar los servicios](#3-cómo-levantar-los-servicios)
4. [Conceptos de cifrado explicados](#4-conceptos-de-cifrado-explicados)
5. [Cómo funciona la ofuscación](#5-cómo-funciona-la-ofuscación)
6. [Endpoints y curls manuales](#6-endpoints-y-curls-manuales)
7. [Ejecutar el script completo de pruebas](#7-ejecutar-el-script-completo-de-pruebas)
8. [Buenas prácticas aplicadas](#8-buenas-prácticas-aplicadas)
9. [Diagrama del flujo de datos](#9-diagrama-del-flujo-de-datos)

---

## 1. Estructura del proyecto

```
dac-crypto-demo/
├── pom.xml                          ← POM raíz (multi-módulo)
├── test-api.sh                      ← Script de pruebas completo
│
├── crypto-service/                  ← Puerto 8081
│   ├── pom.xml
│   └── src/main/java/com/bcp/dac/crypto/
│       ├── model/CryptoModels.java  ← Records de request/response
│       ├── service/
│       │   ├── KeyStoreService.java ← Gestión de claves RSA
│       │   ├── CryptoService.java   ← AES-GCM + RSA-OAEP
│       │   └── ObfuscationService.java ← Enmascaramiento
│       └── resource/CryptoResource.java ← Endpoints REST
│
├── account-service/                 ← Puerto 8082
│   ├── pom.xml
│   └── src/main/java/com/bcp/dac/account/
│       ├── client/CryptoClient.java ← REST Client → crypto-service
│       ├── model/AccountModels.java
│       ├── service/AccountService.java
│       └── resource/AccountResource.java
│
└── identity-service/                ← Puerto 8083
    ├── pom.xml
    └── src/main/java/com/bcp/dac/identity/
        └── resource/IdentityResource.java
```

---

## 2. Pre-requisitos

| Herramienta | Versión mínima | Verificar |
|---|---|---|
| Java JDK | 21 | `java --version` |
| Maven | 3.9.x | `mvn --version` |
| curl | cualquiera | `curl --version` |
| jq | cualquiera | `jq --version` (opcional, para formato JSON) |

---

## 3. Cómo levantar los servicios

Abrir **3 terminales** separadas.

### Terminal 1 – Crypto Service (primero, siempre)

```bash
cd dac-crypto-demo/crypto-service
mvn quarkus:dev
```

Quarkus Dev Mode incluye:
- Hot reload automático (cambios de código se aplican sin reiniciar)
- Swagger UI en http://localhost:8081/swagger-ui
- Dev UI en http://localhost:8081/q/dev

### Terminal 2 – Account Service

```bash
cd dac-crypto-demo/account-service
mvn quarkus:dev
```

### Terminal 3 – Identity Service

```bash
cd dac-crypto-demo/identity-service
mvn quarkus:dev
```

### Verificar que todo está UP

```bash
curl http://localhost:8081/health/live
curl http://localhost:8082/health/live
curl http://localhost:8083/health/live
```

---

## 4. Conceptos de cifrado explicados

### 4.1 AES-256-GCM (Cifrado simétrico)

**AES** = Advanced Encryption Standard  
**256** = tamaño de clave en bits  
**GCM** = Galois/Counter Mode (modo de operación)

```
┌────────────────────────────────────────────────────────┐
│  AES-256-GCM = Cifrado + Autenticación en un solo paso │
│                                                        │
│  Entradas:                                             │
│    plaintext  = "4111111111111234"                     │
│    CEK        = 32 bytes aleatorios (clave secreta)    │
│    IV         = 12 bytes aleatorios (único por op.)    │
│                                                        │
│  Salidas:                                              │
│    ciphertext = bytes cifrados                         │
│    authTag    = 16 bytes de firma de integridad        │
│                                                        │
│  Si alguien modifica el ciphertext → authTag inválido  │
│  → descifrado falla → se detecta el tampering          │
└────────────────────────────────────────────────────────┘
```

**¿Por qué GCM y no CBC?**
- CBC solo cifra. Si alguien modifica el ciphertext, no te enteras.
- GCM cifra Y autentica (AEAD = Authenticated Encryption with Associated Data).

### 4.2 RSA-2048-OAEP (Cifrado asimétrico)

**RSA** = Rivest–Shamir–Adleman  
**2048** = tamaño de clave en bits  
**OAEP** = Optimal Asymmetric Encryption Padding

```
┌────────────────────────────────────────────────────────┐
│  CÓMO FUNCIONA EL PAR DE CLAVES                        │
│                                                        │
│  K-pub (pública): TODOS pueden usarla para cifrar      │
│  K-priv (privada): SOLO el dueño puede descifrar       │
│                                                        │
│  Cifrar con K-pub:                                     │
│    RSA_OAEP(CEK, K-pub) → encryptedCek                 │
│                                                        │
│  Descifrar con K-priv:                                 │
│    RSA_OAEP(encryptedCek, K-priv) → CEK               │
│                                                        │
│  Si alguien intercepta encryptedCek:                   │
│    Sin K-priv → no puede obtener la CEK               │
│    Sin la CEK → no puede descifrar el dato             │
└────────────────────────────────────────────────────────┘
```

**¿Por qué no usar RSA para cifrar el dato directamente?**
- RSA-2048 solo puede cifrar ~190 bytes. Un JSON puede ser mayor.
- RSA es ~1000x más lento que AES.
- Solución: AES cifra el dato (rápido), RSA cifra solo la clave AES (pequeña).

### 4.3 Envelope Encryption (la combinación)

```
CIFRADO:
  plaintext = "4111111111111234"
       │
       ├─► [1] Generar CEK aleatoria (AES-256, 32 bytes, efímera)
       │         CEK = a1b2c3d4e5f6... (nunca repetida)
       │
       ├─► [2] AES_GCM(plaintext, CEK, IV) → ciphertext + authTag
       │
       ├─► [3] RSA_OAEP(CEK, K-pub) → encryptedCek
       │
       └─► [4] Envelope = {
                 encryptedCek,  ← RSA(CEK)
                 ciphertext,    ← AES(dato)
                 iv,            ← vector de inicialización
                 authTag,       ← sello de integridad
                 keyId          ← "rsa-key-v1"
               }

DESCIFRADO (solo con K-priv):
  Envelope → RSA_OAEP(encryptedCek, K-priv) → CEK
           → AES_GCM(ciphertext, CEK, iv, authTag) → plaintext
```

**¿Por qué CEK efímera?**
Si una CEK se compromete, solo **UN** dato queda expuesto.
Con una sola clave para todo, un compromiso expone **TODO**.

---

## 5. Cómo funciona la ofuscación

La ofuscación es **enmascaramiento visual**, NO cifrado.

| Tipo | Input | Output | Técnica |
|---|---|---|---|
| CARD_NUMBER | 4111111111111234 | 411111\*\*\*\*\*\*1234 | PCI-DSS: primeros 6 + últimos 4 |
| ACCOUNT_NUMBER | 19302938471923 | \*\*\*\*\*\*\*\*\*\*1923 | Últimos 4 visibles |
| NATIONAL_ID | 12345678 | \*\*\*\*5678 | Últimos 4 visibles |
| EMAIL | juan@gmail.com | j\*\*\*n@gmail.com | Primer + último carácter de la parte local |

**Cuándo usar cada uno:**

| Herramienta | Cuándo usar |
|---|---|
| Cifrado | Cuando necesitas recuperar el dato original |
| Ofuscación | Para logs, trazas, UI (no necesitas recuperar) |
| Hash SHA-256 | Para búsquedas sin exponer el dato (email search) |

---

## 6. Endpoints y curls manuales

### 6.1 Crypto Service (puerto 8081)

#### Cifrar un número de tarjeta

```bash
curl -X POST http://localhost:8081/api/v1/crypto/encrypt \
  -H "Content-Type: application/json" \
  -d '{
    "plaintext": "4111111111111234",
    "dataType": "CARD_NUMBER",
    "contextInfo": "pago-compra-001"
  }'
```

**Respuesta:**
```json
{
  "encryptedCek": "TW96aSBGaXJlZm94...(Base64, ~344 chars)",
  "ciphertext":   "xK9mP2...(Base64)",
  "iv":           "abc123...(Base64, 16 chars)",
  "authTag":      "def456...(Base64, 24 chars)",
  "keyId":        "rsa-key-v1",
  "dataType":     "CARD_NUMBER",
  "maskedPreview":"411111******1234"
}
```

#### Descifrar el envelope

```bash
# Usar los valores del paso anterior
curl -X POST http://localhost:8081/api/v1/crypto/decrypt \
  -H "Content-Type: application/json" \
  -d '{
    "encryptedCek": "<encryptedCek del paso anterior>",
    "ciphertext":   "<ciphertext del paso anterior>",
    "iv":           "<iv del paso anterior>",
    "authTag":      "<authTag del paso anterior>",
    "keyId":        "rsa-key-v1",
    "dataType":     "CARD_NUMBER"
  }'
```

**Respuesta:**
```json
{
  "plaintext":         "4111111111111234",
  "maskedPreview":     "411111******1234",
  "dataType":          "CARD_NUMBER",
  "integrityVerified": true
}
```

#### Ofuscar un email

```bash
curl -X POST http://localhost:8081/api/v1/crypto/obfuscate \
  -H "Content-Type: application/json" \
  -d '{
    "value": "juan.perez@gmail.com",
    "dataType": "EMAIL"
  }'
```

### 6.2 Account Service (puerto 8082)

#### Crear cuenta

```bash
curl -X POST http://localhost:8082/api/v1/accounts \
  -H "Content-Type: application/json" \
  -d '{
    "holderName":    "Juan Pablo Pérez",
    "accountNumber": "19302938471923",
    "cardNumber":    "4111111111111234",
    "accountType":   "SAVINGS"
  }'
```

#### Listar cuentas

```bash
curl http://localhost:8082/api/v1/accounts
```

#### Consultar cuenta por ID

```bash
# Reemplazar {accountId} con el ID obtenido al crear
curl http://localhost:8082/api/v1/accounts/{accountId}
```

#### Revelar número de cuenta (operación privilegiada)

```bash
curl -X POST http://localhost:8082/api/v1/accounts/{accountId}/reveal \
  -H "Content-Type: application/json" \
  -d '{"field": "accountNumber"}'
```

#### Revelar número de tarjeta

```bash
curl -X POST http://localhost:8082/api/v1/accounts/{accountId}/reveal \
  -H "Content-Type: application/json" \
  -d '{"field": "cardNumber"}'
```

### 6.3 Identity Service (puerto 8083)

#### Registrar identidad

```bash
curl -X POST http://localhost:8083/api/v1/identities \
  -H "Content-Type: application/json" \
  -d '{
    "fullName":   "Juan Pablo Pérez Camacho",
    "nationalId": "12345678",
    "email":      "jperez@bcp.com.pe"
  }'
```

#### Listar identidades

```bash
curl http://localhost:8083/api/v1/identities
```

#### Revelar DNI

```bash
curl -X POST http://localhost:8083/api/v1/identities/{identityId}/reveal \
  -H "Content-Type: application/json" \
  -d '{"field": "nationalId"}'
```

#### Revelar Email

```bash
curl -X POST http://localhost:8083/api/v1/identities/{identityId}/reveal \
  -H "Content-Type: application/json" \
  -d '{"field": "email"}'
```

---

## 7. Ejecutar el script completo de pruebas

```bash
# Dar permisos de ejecución
chmod +x test-api.sh

# Ejecutar (requiere los 3 servicios UP)
./test-api.sh
```

El script ejecuta en orden:
1. Health checks de los 3 servicios
2. Pruebas de ofuscación (4 tipos de dato)
3. Cifrado y descifrado directo + prueba de tampering
4. Flujo completo del Account Service
5. Flujo completo del Identity Service
6. Muestra URLs de Swagger UI

---

## 8. Buenas prácticas aplicadas

### Seguridad
- **Nunca loguear datos sensibles en claro**: todos los logs usan `maskedPreview`
- **CEK efímera por operación**: compromiso localizado
- **IV aleatorio único**: nunca reutilizar IV con la misma clave
- **AES-GCM sobre AES-CBC**: autenticación integrada
- **RSA-OAEP sobre RSA-PKCS1v1.5**: resistente a Bleichenbacher
- **SecureRandom**: nunca usar `Math.random()` ni `new Random()` para criptografía
- **char[] sobre String**: los datos descifrados en memoria deberían poder hacerse zero-out (String es inmutable en Java)

### Diseño de código
- **Java 21 Records**: modelos inmutables por diseño
- **@ApplicationScoped**: singletons para servicios stateful (KeyStore)
- **Excepciones de dominio**: `CryptoException`, `AccountNotFoundException` en lugar de exponer excepciones de la JCA
- **Validación con @Valid + @NotBlank**: nunca confiar en el input del cliente
- **Versión en URL** (`/api/v1/`): facilita evolución sin romper clientes
- **Separación de capas**: Resource → Service → Client (hexagonal simplificado)

### Observabilidad
- **Logs estructurados** con nivel y clase
- **maskedPreview** en todas las operaciones de audit
- **Swagger UI** habilitado para desarrollo (`quarkus.swagger-ui.always-include=true`)
- **Health checks** liveness + readiness con SmallRye Health

### Lo que falta para producción (intencionalmente simplificado)
- Autenticación JWT en todos los endpoints
- HashiCorp Vault / Azure Key Vault reales (aquí se simula en memoria)
- Persistencia real con JPA/Panache + base de datos
- mTLS entre microservicios
- Rate limiting en endpoints `/reveal`
- OpenTelemetry para trazas distribuidas
- Rotación automática de claves

---

## 9. Diagrama del flujo de datos

```
Cliente (Browser/App)
       │  HTTPS/TLS 1.3
       ▼
  Account Service (8082)
       │
       ├─► 1. Recibe { accountNumber: "193029...", cardNumber: "4111..." }
       │
       ├─► 2. Llama Crypto Service:  POST /encrypt { plaintext: "193029..." }
       │         Crypto Service devuelve: { encryptedCek, ciphertext, iv, authTag, keyId }
       │
       ├─► 3. Llama Crypto Service:  POST /encrypt { plaintext: "4111..." }
       │         Crypto Service devuelve: { encryptedCek, ciphertext, iv, authTag, keyId }
       │
       ├─► 4. Persiste SOLO los envelopes cifrados (nunca el dato en claro)
       │
       └─► 5. Devuelve al cliente: { maskedAccountNumber: "**1923", maskedCardNumber: "411111**1234" }

Consulta posterior:
  GET /accounts/{id}  →  devuelve datos enmascarados + envelopes cifrados
  POST /accounts/{id}/reveal  →  llama Crypto Service para descifrar
```
