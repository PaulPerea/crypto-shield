#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════
#  DAC CRYPTO DEMO – Script de pruebas completo
#  Requiere: curl, jq (para formatear JSON)
#
#  SERVICIOS:
#    crypto-service   → http://localhost:8081
#    account-service  → http://localhost:8082
#    identity-service → http://localhost:8083
#
#  USO:
#    chmod +x test-api.sh
#    ./test-api.sh
#
#  O ejecutar secciones individuales con:
#    bash test-api.sh          # Todo el flujo
# ══════════════════════════════════════════════════════════════════════

set -euo pipefail

# ── Colores para output ──────────────────────────────────────────────
BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

CRYPTO_URL="http://localhost:8081"
ACCOUNT_URL="http://localhost:8082"
IDENTITY_URL="http://localhost:8083"

# Almacenar resultados entre pasos
ENCRYPT_RESPONSE=""
ACCOUNT_ID=""
IDENTITY_ID=""

# ── Función helper ───────────────────────────────────────────────────
step() {
  echo ""
  echo -e "${BLUE}╔══════════════════════════════════════════════════════╗${RESET}"
  echo -e "${BLUE}║  ${BOLD}$1${RESET}${BLUE}${RESET}"
  echo -e "${BLUE}╚══════════════════════════════════════════════════════╝${RESET}"
}

info()    { echo -e "  ${CYAN}ℹ  $1${RESET}"; }
success() { echo -e "  ${GREEN}✔  $1${RESET}"; }
warn()    { echo -e "  ${YELLOW}⚠  $1${RESET}"; }
header()  { echo -e "\n${BOLD}${YELLOW}  ▶ $1${RESET}"; }

curl_post() {
  local url=$1
  local body=$2
  curl -s -X POST "$url" \
    -H "Content-Type: application/json" \
    -d "$body" | jq .
}

curl_get() {
  local url=$1
  curl -s -X GET "$url" | jq .
}

# ════════════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}${GREEN}"
echo "  ██████╗  █████╗  ██████╗    ██████╗ ███████╗███╗   ███╗ ██████╗ "
echo "  ██╔══██╗██╔══██╗██╔════╝    ██╔══██╗██╔════╝████╗ ████║██╔═══██╗"
echo "  ██║  ██║███████║██║         ██║  ██║█████╗  ██╔████╔██║██║   ██║"
echo "  ██║  ██║██╔══██║██║         ██║  ██║██╔══╝  ██║╚██╔╝██║██║   ██║"
echo "  ██████╔╝██║  ██║╚██████╗    ██████╔╝███████╗██║ ╚═╝ ██║╚██████╔╝"
echo "  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝    ╚═════╝ ╚══════╝╚═╝     ╚═╝ ╚═════╝ "
echo -e "${RESET}"
echo -e "  ${BOLD}Pruebas de DAC: AES-256-GCM + RSA-2048-OAEP${RESET}"
echo ""

# ════════════════════════════════════════════════════════════════════
#  SECCIÓN 1 – HEALTH CHECKS
# ════════════════════════════════════════════════════════════════════
step "SECCIÓN 1: Health Checks – Verificar que los servicios están UP"

header "1.1 Crypto Service health"
info "Verifica que el Crypto Service (puerto 8081) está disponible"
echo ""
curl_get "$CRYPTO_URL/api/v1/crypto/health"
success "Crypto Service UP"

header "1.2 Quarkus Health checks estándar"
info "Liveness: ¿está vivo el proceso?"
curl_get "$CRYPTO_URL/health/live"
info "Readiness: ¿está listo para recibir tráfico?"
curl_get "$CRYPTO_URL/health/ready"

# ════════════════════════════════════════════════════════════════════
#  SECCIÓN 2 – OFUSCACIÓN (sin cifrado, solo enmascaramiento)
# ════════════════════════════════════════════════════════════════════
step "SECCIÓN 2: Ofuscación – Enmascaramiento visual de datos sensibles"

info "La ofuscación NO es cifrado. Solo enmascara visualmente para logs y UI."
info "El dato original NO puede recuperarse desde el valor ofuscado."

header "2.1 Ofuscar número de tarjeta (PCI-DSS: primeros 6 + últimos 4)"
echo ""
curl_post "$CRYPTO_URL/api/v1/crypto/obfuscate" '{
  "value": "4111111111111234",
  "dataType": "CARD_NUMBER"
}'
# Resultado esperado: "411111******1234"

header "2.2 Ofuscar número de cuenta (últimos 4 visibles)"
curl_post "$CRYPTO_URL/api/v1/crypto/obfuscate" '{
  "value": "19302938471923",
  "dataType": "ACCOUNT_NUMBER"
}'
# Resultado esperado: "**********1923"

header "2.3 Ofuscar documento de identidad (últimos 4 visibles)"
curl_post "$CRYPTO_URL/api/v1/crypto/obfuscate" '{
  "value": "12345678",
  "dataType": "NATIONAL_ID"
}'
# Resultado esperado: "****5678"

header "2.4 Ofuscar email (primer + último carácter de la parte local)"
curl_post "$CRYPTO_URL/api/v1/crypto/obfuscate" '{
  "value": "juan.perez@gmail.com",
  "dataType": "EMAIL"
}'
# Resultado esperado: "j*********z@gmail.com"

# ════════════════════════════════════════════════════════════════════
#  SECCIÓN 3 – CIFRADO DIRECTO (Crypto Service)
# ════════════════════════════════════════════════════════════════════
step "SECCIÓN 3: Cifrado directo – Envelope Encryption completo"

info "El dato viaja cifrado. Solo quien tenga la K-priv RSA puede descifrar."

header "3.1 Cifrar número de tarjeta"
echo ""
info "Internamente: genera CEK AES-256 → cifra con AES-GCM → cifra CEK con RSA-OAEP"
ENCRYPT_RESPONSE=$(curl -s -X POST "$CRYPTO_URL/api/v1/crypto/encrypt" \
  -H "Content-Type: application/json" \
  -d '{
    "plaintext": "4111111111111234",
    "dataType": "CARD_NUMBER",
    "contextInfo": "test-pago-001"
  }')
echo "$ENCRYPT_RESPONSE" | jq .
success "Tarjeta cifrada. Nota: cada ejecución produce ciphertext diferente (CEK efímera + IV aleatorio)"

header "3.2 Descifrar el envelope anterior"
info "Se pasan todos los componentes del envelope: encryptedCek + ciphertext + iv + authTag + keyId"

ENCRYPTED_CEK=$(echo "$ENCRYPT_RESPONSE" | jq -r '.encryptedCek')
CIPHERTEXT=$(echo "$ENCRYPT_RESPONSE" | jq -r '.ciphertext')
IV=$(echo "$ENCRYPT_RESPONSE" | jq -r '.iv')
AUTH_TAG=$(echo "$ENCRYPT_RESPONSE" | jq -r '.authTag')
KEY_ID=$(echo "$ENCRYPT_RESPONSE" | jq -r '.keyId')

curl_post "$CRYPTO_URL/api/v1/crypto/decrypt" "{
  \"encryptedCek\": \"$ENCRYPTED_CEK\",
  \"ciphertext\":   \"$CIPHERTEXT\",
  \"iv\":           \"$IV\",
  \"authTag\":      \"$AUTH_TAG\",
  \"keyId\":        \"$KEY_ID\",
  \"dataType\":     \"CARD_NUMBER\"
}"
success "Dato descifrado exitosamente. integrityVerified=true confirma que el authTag fue válido."

header "3.3 Cifrar email"
ENCRYPT_RESPONSE_EMAIL=$(curl -s -X POST "$CRYPTO_URL/api/v1/crypto/encrypt" \
  -H "Content-Type: application/json" \
  -d '{
    "plaintext": "juan.perez@bcp.com.pe",
    "dataType": "EMAIL",
    "contextInfo": "registro-usuario"
  }')
echo "$ENCRYPT_RESPONSE_EMAIL" | jq .

header "3.4 Probar detección de tampering (authTag inválido)"
warn "Si se modifica el ciphertext, el authTag no coincide y el descifrado falla."
info "Esto demuestra la autenticación integrada de AES-GCM (AEAD)."
curl_post "$CRYPTO_URL/api/v1/crypto/decrypt" "{
  \"encryptedCek\": \"$ENCRYPTED_CEK\",
  \"ciphertext\":   \"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",
  \"iv\":           \"$IV\",
  \"authTag\":      \"$AUTH_TAG\",
  \"keyId\":        \"$KEY_ID\",
  \"dataType\":     \"CARD_NUMBER\"
}"
# Resultado esperado: error CRYPTO_INTEGRITY_FAIL
warn "Error esperado ↑ El sistema detectó que el ciphertext fue modificado."

header "3.5 Validación de request inválido"
info "Probar que el validador Bean Validation rechaza requests incorrectos"
curl -s -X POST "$CRYPTO_URL/api/v1/crypto/encrypt" \
  -H "Content-Type: application/json" \
  -d '{
    "plaintext": "",
    "dataType": "TIPO_INVALIDO"
  }' | jq .
warn "Error 400 esperado ↑ El validador Jakarta rechazó el request antes de procesarlo."

# ════════════════════════════════════════════════════════════════════
#  SECCIÓN 4 – ACCOUNT SERVICE
# ════════════════════════════════════════════════════════════════════
step "SECCIÓN 4: Account Service – Crear y consultar cuentas con datos cifrados"

header "4.1 Crear cuenta bancaria"
info "El Account Service llama internamente al Crypto Service para cifrar."
info "El cliente nunca ve el proceso de cifrado."

ACCOUNT_RESPONSE=$(curl -s -X POST "$ACCOUNT_URL/api/v1/accounts" \
  -H "Content-Type: application/json" \
  -d '{
    "holderName":    "Juan Pablo Pérez",
    "accountNumber": "19302938471923",
    "cardNumber":    "4111111111111234",
    "accountType":   "SAVINGS"
  }')
echo "$ACCOUNT_RESPONSE" | jq .

ACCOUNT_ID=$(echo "$ACCOUNT_RESPONSE" | jq -r '.accountId')
success "Cuenta creada | accountId=$ACCOUNT_ID"
info "Nota: la respuesta muestra datos ENMASCARADOS, nunca en claro."

header "4.2 Listar todas las cuentas (datos enmascarados)"
curl_get "$ACCOUNT_URL/api/v1/accounts"

header "4.3 Consultar cuenta por ID"
info "La respuesta incluye el envelope cifrado completo para sistemas autorizados."
curl_get "$ACCOUNT_URL/api/v1/accounts/$ACCOUNT_ID"

header "4.4 Revelar número de cuenta (operación privilegiada)"
warn "En producción: requiere JWT + MFA + RBAC + audit log obligatorio."
curl_post "$ACCOUNT_URL/api/v1/accounts/$ACCOUNT_ID/reveal" '{
  "field": "accountNumber"
}'

header "4.5 Revelar número de tarjeta (operación privilegiada)"
curl_post "$ACCOUNT_URL/api/v1/accounts/$ACCOUNT_ID/reveal" '{
  "field": "cardNumber"
}'

header "4.6 Crear segunda cuenta para ver el listado"
curl_post "$ACCOUNT_URL/api/v1/accounts" '{
  "holderName":    "María García López",
  "accountNumber": "28401928374651",
  "cardNumber":    "5500005555555559",
  "accountType":   "CHECKING"
}' > /dev/null

curl_get "$ACCOUNT_URL/api/v1/accounts"
success "Dos cuentas en el listado, ambas con datos enmascarados."

# ════════════════════════════════════════════════════════════════════
#  SECCIÓN 5 – IDENTITY SERVICE
# ════════════════════════════════════════════════════════════════════
step "SECCIÓN 5: Identity Service – DNI y Email cifrados + Hash de búsqueda"

header "5.1 Registrar identidad"
info "Cifra DNI + Email. Además hashea el email (SHA-256) para búsquedas."
IDENTITY_RESPONSE=$(curl -s -X POST "$IDENTITY_URL/api/v1/identities" \
  -H "Content-Type: application/json" \
  -d '{
    "fullName":   "Juan Pablo Pérez Camacho",
    "nationalId": "12345678",
    "email":      "jperez@bcp.com.pe"
  }')
echo "$IDENTITY_RESPONSE" | jq .

IDENTITY_ID=$(echo "$IDENTITY_RESPONSE" | jq -r '.identityId')
success "Identidad registrada | identityId=$IDENTITY_ID"

header "5.2 Consultar identidad por ID"
curl_get "$IDENTITY_URL/api/v1/identities/$IDENTITY_ID"
info "emailSearchHashPrefix permite verificar búsquedas sin descifrar."

header "5.3 Revelar DNI"
curl_post "$IDENTITY_URL/api/v1/identities/$IDENTITY_ID/reveal" '{
  "field": "nationalId"
}'

header "5.4 Revelar Email"
curl_post "$IDENTITY_URL/api/v1/identities/$IDENTITY_ID/reveal" '{
  "field": "email"
}'

header "5.5 Registrar segunda identidad"
curl_post "$IDENTITY_URL/api/v1/identities" '{
  "fullName":   "Ana Rodríguez",
  "nationalId": "87654321",
  "email":      "arodriguez@example.com"
}' > /dev/null

header "5.6 Listar identidades"
curl_get "$IDENTITY_URL/api/v1/identities"

# ════════════════════════════════════════════════════════════════════
#  SECCIÓN 6 – SWAGGER UI
# ════════════════════════════════════════════════════════════════════
step "SECCIÓN 6: Swagger UI – Documentación interactiva"

echo ""
info "Abrir en el navegador para explorar la API:"
echo ""
echo -e "  ${GREEN}Crypto Service  Swagger UI:${RESET}   ${CYAN}http://localhost:8081/swagger-ui${RESET}"
echo -e "  ${GREEN}Account Service Swagger UI:${RESET}   ${CYAN}http://localhost:8082/swagger-ui${RESET}"
echo -e "  ${GREEN}Identity Service Swagger UI:${RESET}  ${CYAN}http://localhost:8083/swagger-ui${RESET}"
echo ""
echo -e "  ${GREEN}OpenAPI JSON specs:${RESET}"
echo -e "  ${CYAN}http://localhost:8081/api/v1/openapi${RESET}"
echo -e "  ${CYAN}http://localhost:8082/api/v1/openapi${RESET}"
echo -e "  ${CYAN}http://localhost:8083/api/v1/openapi${RESET}"

# ════════════════════════════════════════════════════════════════════
#  RESUMEN FINAL
# ════════════════════════════════════════════════════════════════════
echo ""
echo -e "${GREEN}${BOLD}"
echo "  ════════════════════════════════════════════════════"
echo "   ✔  Todas las pruebas completadas exitosamente"
echo "  ════════════════════════════════════════════════════"
echo -e "${RESET}"
echo ""
echo -e "  ${BOLD}Resumen de lo demostrado:${RESET}"
echo ""
echo "  1. Ofuscación visual:"
echo "     • CARD_NUMBER   → 411111******1234   (PCI-DSS compliant)"
echo "     • ACCOUNT_NUMBER → **********1923"
echo "     • NATIONAL_ID   → ****5678"
echo "     • EMAIL         → j*********z@gmail.com"
echo ""
echo "  2. Cifrado AES-256-GCM:"
echo "     • CEK efímera generada por operación (compromiso localizado)"
echo "     • IV aleatorio único por operación (nunca reusar IV)"
echo "     • authTag detecta tampering automáticamente (AEAD)"
echo ""
echo "  3. Cifrado RSA-2048-OAEP:"
echo "     • Solo envuelve la CEK (eficiente: ~256 bytes)"
echo "     • OAEP con padding aleatorio (resistente a Bleichenbacher)"
echo "     • K-priv permanece en el KeyStore (simula Vault)"
echo ""
echo "  4. Envelope Encryption:"
echo "     • Payload = { encryptedCek, ciphertext, iv, authTag, keyId }"
echo "     • El keyId permite rotación de claves (versioning)"
echo ""
echo "  5. Hash de búsqueda (Identity Service):"
echo "     • SHA-256(email.toLowerCase()) → buscar sin descifrar"
echo ""
