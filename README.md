# DAC Crypto Demo
## Sensitive Data Architecture with AES-256-GCM + RSA-2048-OAEP
### Stack: Quarkus 3.9 · Java 21 · Maven 3.9.9

---

## Table of Contents

1. [Project Structure](#1-project-structure)
2. [Prerequisites](#2-prerequisites)
3. [How to Start the Services](#3-how-to-start-the-services)
4. [Encryption Concepts Explained](#4-encryption-concepts-explained)
5. [How Obfuscation Works](#5-how-obfuscation-works)
6. [Endpoints and Manual Curls](#6-endpoints-and-manual-curls)
7. [Running the Full Test Script](#7-running-the-full-test-script)
8. [Applied Best Practices](#8-applied-best-practices)
9. [Data Flow Diagram](#9-data-flow-diagram)

---

## 1. Project Structure

```
dac-crypto-demo/
├── pom.xml                          ← Root POM (multi-module)
├── test-api.sh                      ← Full test script
│
├── crypto-service/                  ← Port 8081
│   ├── pom.xml
│   └── src/main/java/com/bcp/dac/crypto/
│       ├── model/CryptoModels.java  ← Request/response records
│       ├── service/
│       │   ├── KeyStoreService.java ← RSA key management
│       │   ├── CryptoService.java   ← AES-GCM + RSA-OAEP
│       │   └── ObfuscationService.java ← Masking
│       └── resource/CryptoResource.java ← REST endpoints
│
├── account-service/                 ← Port 8082
│   ├── pom.xml
│   └── src/main/java/com/bcp/dac/account/
│       ├── client/CryptoClient.java ← REST Client → crypto-service
│       ├── model/AccountModels.java
│       ├── service/AccountService.java
│       └── resource/AccountResource.java
│
└── identity-service/                ← Port 8083
    ├── pom.xml
    └── src/main/java/com/bcp/dac/identity/
        └── resource/IdentityResource.java
```

---

## 2. Prerequisites

| Tool      | Minimum Version | Check                                      |
|-----------|-----------------|--------------------------------------------|
| Java JDK  | 21              | `java --version`                           |
| Maven     | 3.9.x           | `mvn --version`                            |
| curl      | any             | `curl --version`                           |
| jq        | any             | `jq --version` (optional, for JSON format) |

---

## 3. How to Start the Services

Open **3 separate terminals**.

### Terminal 1 – Crypto Service (always first)

```bash
cd dac-crypto-demo/crypto-service
mvn quarkus:dev
```

Quarkus Dev Mode includes:
- Automatic hot reload (code changes apply without restarting)
- Swagger UI at http://localhost:8081/swagger-ui
- Dev UI at http://localhost:8081/q/dev

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

### Verify Everything is UP

```bash
curl http://localhost:8081/health/live
curl http://localhost:8082/health/live
curl http://localhost:8083/health/live
```

---

## 4. Encryption Concepts Explained

### 4.1 AES-256-GCM (Symmetric Encryption)

**AES** = Advanced Encryption Standard  
**256** = key size in bits  
**GCM** = Galois/Counter Mode (operation mode)

```
┌────────────────────────────────────────────────────────┐
│  AES-256-GCM = Encryption + Authentication in one step │
│                                                        │
│  Inputs:                                               │
│    plaintext  = "4111111111111234"                     │
│    CEK        = 32 random bytes (secret key)           │
│    IV         = 12 random bytes (unique per operation) │
│                                                        │
│  Outputs:                                              │
│    ciphertext = encrypted bytes                        │
│    authTag    = 16-byte integrity signature            │
│                                                        │
│  If someone modifies the ciphertext → invalid authTag  │
│  → decryption fails → tampering is detected            │
└────────────────────────────────────────────────────────┘
```

**Why GCM and not CBC?**
- CBC only encrypts. If someone modifies the ciphertext, you won't know.
- GCM encrypts AND authenticates (AEAD = Authenticated Encryption with Associated Data).

### 4.2 RSA-2048-OAEP (Asymmetric Encryption)

**RSA** = Rivest–Shamir–Adleman  
**2048** = key size in bits  
**OAEP** = Optimal Asymmetric Encryption Padding

```
┌────────────────────────────────────────────────────────┐
│  HOW THE KEY PAIR WORKS                                │
│                                                        │
│  K-pub (public):  ANYONE can use it to encrypt         │
│  K-priv (private): ONLY the owner can decrypt          │
│                                                        │
│  Encrypt with K-pub:                                   │
│    RSA_OAEP(CEK, K-pub) → encryptedCek                 │
│                                                        │
│  Decrypt with K-priv:                                  │
│    RSA_OAEP(encryptedCek, K-priv) → CEK               │
│                                                        │
│  If someone intercepts encryptedCek:                   │
│    Without K-priv → cannot obtain the CEK             │
│    Without the CEK → cannot decrypt the data           │
└────────────────────────────────────────────────────────┘
```

**Why not use RSA to encrypt the data directly?**
- RSA-2048 can only encrypt ~190 bytes. A JSON payload may be larger.
- RSA is ~1000x slower than AES.
- Solution: AES encrypts the data (fast), RSA encrypts only the AES key (small).

### 4.3 Envelope Encryption (the combination)

```
ENCRYPTION:
  plaintext = "4111111111111234"
       │
       ├─► [1] Generate random CEK (AES-256, 32 bytes, ephemeral)
       │         CEK = a1b2c3d4e5f6... (never reused)
       │
       ├─► [2] AES_GCM(plaintext, CEK, IV) → ciphertext + authTag
       │
       ├─► [3] RSA_OAEP(CEK, K-pub) → encryptedCek
       │
       └─► [4] Envelope = {
                 encryptedCek,  ← RSA(CEK)
                 ciphertext,    ← AES(data)
                 iv,            ← initialization vector
                 authTag,       ← integrity seal
                 keyId          ← "rsa-key-v1"
               }

DECRYPTION (only with K-priv):
  Envelope → RSA_OAEP(encryptedCek, K-priv) → CEK
           → AES_GCM(ciphertext, CEK, iv, authTag) → plaintext
```

**Why an ephemeral CEK?**  
If a CEK is compromised, only **ONE** piece of data is exposed.  
With a single key for everything, one compromise exposes **EVERYTHING**.

---

## 5. How Obfuscation Works

Obfuscation is **visual masking**, NOT encryption.

| Type           | Input            | Output                 | Technique                            |
|----------------|------------------|------------------------|--------------------------------------|
| CARD_NUMBER    | 4111111111111234 | 411111\*\*\*\*\*\*1234 | PCI-DSS: first 6 + last 4 digits    |
| ACCOUNT_NUMBER | 19302938471923   | \*\*\*\*\*\*\*\*\*\*1923 | Last 4 digits visible              |
| NATIONAL_ID    | 12345678         | \*\*\*\*5678           | Last 4 digits visible                |
| EMAIL          | juan@gmail.com   | j\*\*\*n@gmail.com     | First + last char of the local part  |

**When to use each:**

| Tool         | When to use                                           |
|--------------|-------------------------------------------------------|
| Encryption   | When you need to recover the original data            |
| Obfuscation  | For logs, traces, UI (no recovery needed)             |
| SHA-256 Hash | For searches without exposing the data (email lookup) |

---

## 6. Endpoints and Manual Curls

### 6.1 Crypto Service (port 8081)

#### Encrypt a card number

```bash
curl -X POST http://localhost:8081/api/v1/crypto/encrypt \
  -H "Content-Type: application/json" \
  -d '{
    "plaintext": "4111111111111234",
    "dataType": "CARD_NUMBER",
    "contextInfo": "purchase-payment-001"
  }'
```

**Response:**
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

#### Decrypt the envelope

```bash
# Use the values from the previous step
curl -X POST http://localhost:8081/api/v1/crypto/decrypt \
  -H "Content-Type: application/json" \
  -d '{
    "encryptedCek": "<encryptedCek from previous step>",
    "ciphertext":   "<ciphertext from previous step>",
    "iv":           "<iv from previous step>",
    "authTag":      "<authTag from previous step>",
    "keyId":        "rsa-key-v1",
    "dataType":     "CARD_NUMBER"
  }'
```

**Response:**
```json
{
  "plaintext":         "4111111111111234",
  "maskedPreview":     "411111******1234",
  "dataType":          "CARD_NUMBER",
  "integrityVerified": true
}
```

#### Obfuscate an email

```bash
curl -X POST http://localhost:8081/api/v1/crypto/obfuscate \
  -H "Content-Type: application/json" \
  -d '{
    "value": "juan.perez@gmail.com",
    "dataType": "EMAIL"
  }'
```

### 6.2 Account Service (port 8082)

#### Create account

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

#### List accounts

```bash
curl http://localhost:8082/api/v1/accounts
```

#### Get account by ID

```bash
# Replace {accountId} with the ID obtained when creating
curl http://localhost:8082/api/v1/accounts/{accountId}
```

#### Reveal account number (privileged operation)

```bash
curl -X POST http://localhost:8082/api/v1/accounts/{accountId}/reveal \
  -H "Content-Type: application/json" \
  -d '{"field": "accountNumber"}'
```

#### Reveal card number

```bash
curl -X POST http://localhost:8082/api/v1/accounts/{accountId}/reveal \
  -H "Content-Type: application/json" \
  -d '{"field": "cardNumber"}'
```

### 6.3 Identity Service (port 8083)

#### Register identity

```bash
curl -X POST http://localhost:8083/api/v1/identities \
  -H "Content-Type: application/json" \
  -d '{
    "fullName":   "Juan Pablo Pérez Camacho",
    "nationalId": "12345678",
    "email":      "jperez@bcp.com.pe"
  }'
```

#### List identities

```bash
curl http://localhost:8083/api/v1/identities
```

#### Reveal national ID

```bash
curl -X POST http://localhost:8083/api/v1/identities/{identityId}/reveal \
  -H "Content-Type: application/json" \
  -d '{"field": "nationalId"}'
```

#### Reveal Email

```bash
curl -X POST http://localhost:8083/api/v1/identities/{identityId}/reveal \
  -H "Content-Type: application/json" \
  -d '{"field": "email"}'
```

---

## 7. Running the Full Test Script

```bash
# Grant execution permissions
chmod +x test-api.sh

# Run (requires all 3 services UP)
./test-api.sh
```

The script runs in order:
1. Health checks for all 3 services
2. Obfuscation tests (4 data types)
3. Direct encryption and decryption + tampering test
4. Full Account Service flow
5. Full Identity Service flow
6. Displays Swagger UI URLs

---

## 8. Applied Best Practices

### Security
- **Never log sensitive data in plaintext**: all logs use `maskedPreview`
- **Ephemeral CEK per operation**: breach impact is localized
- **Unique random IV**: never reuse an IV with the same key
- **AES-GCM over AES-CBC**: built-in authentication
- **RSA-OAEP over RSA-PKCS1v1.5**: resistant to Bleichenbacher attacks
- **SecureRandom**: never use `Math.random()` or `new Random()` for cryptography
- **char[] over String**: decrypted data in memory should be zero-outable (String is immutable in Java)

### Code Design
- **Java 21 Records**: immutable models by design
- **@ApplicationScoped**: singletons for stateful services (KeyStore)
- **Domain exceptions**: `CryptoException`, `AccountNotFoundException` instead of exposing JCA exceptions
- **Validation with @Valid + @NotBlank**: never trust client input
- **Version in URL** (`/api/v1/`): enables evolution without breaking clients
- **Layer separation**: Resource → Service → Client (simplified hexagonal)

### Observability
- **Structured logs** with level and class
- **maskedPreview** in all audit operations
- **Swagger UI** enabled for development (`quarkus.swagger-ui.always-include=true`)
- **Health checks** liveness + readiness with SmallRye Health

### What's Missing for Production (intentionally simplified)
- JWT authentication on all endpoints
- Real HashiCorp Vault / Azure Key Vault (simulated in-memory here)
- Real persistence with JPA/Panache + database
- mTLS between microservices
- Rate limiting on `/reveal` endpoints
- OpenTelemetry for distributed tracing
- Automatic key rotation

---

## 9. Data Flow Diagram

```
Client (Browser/App)
       │  HTTPS/TLS 1.3
       ▼
  Account Service (8082)
       │
       ├─► 1. Receives { accountNumber: "193029...", cardNumber: "4111..." }
       │
       ├─► 2. Calls Crypto Service:  POST /encrypt { plaintext: "193029..." }
       │         Crypto Service returns: { encryptedCek, ciphertext, iv, authTag, keyId }
       │
       ├─► 3. Calls Crypto Service:  POST /encrypt { plaintext: "4111..." }
       │         Crypto Service returns: { encryptedCek, ciphertext, iv, authTag, keyId }
       │
       ├─► 4. Persists ONLY the encrypted envelopes (never plaintext data)
       │
       └─► 5. Returns to client: { maskedAccountNumber: "**1923", maskedCardNumber: "411111**1234" }

Subsequent query:
  GET /accounts/{id}  →  returns masked data + encrypted envelopes
  POST /accounts/{id}/reveal  →  calls Crypto Service to decrypt
```
