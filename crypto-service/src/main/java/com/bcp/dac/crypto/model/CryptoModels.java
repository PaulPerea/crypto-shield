package com.bcp.dac.crypto.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

/**
 * ══════════════════════════════════════════════════════════════
 *  MODELOS DE DATOS – Crypto Service
 *  Fin educativo: muestra cómo estructurar requests/responses
 *  para operaciones de cifrado sin exponer datos internos.
 * ══════════════════════════════════════════════════════════════
 *
 * Se usan Java 21 Records para inmutabilidad: una vez creados,
 * los objetos no pueden modificarse (buena práctica de seguridad).
 */
public final class CryptoModels {

    // Constructor privado: esta clase solo agrupa records, no se instancia
    private CryptoModels() {}

    // ──────────────────────────────────────────────
    //  REQUEST: Cifrar un dato sensible
    // ──────────────────────────────────────────────

    /**
     * Request para cifrar un dato sensible.
     *
     * CONCEPTO: El campo "dataType" indica QUÉ tipo de dato es.
     * Esto nos permite aplicar reglas específicas por tipo:
     *   - CARD_NUMBER   → cifrado + tokenización PCI
     *   - ACCOUNT_NUMBER → cifrado estándar
     *   - NATIONAL_ID   → cifrado + hash de búsqueda
     *   - EMAIL         → cifrado + hash SHA-256 para búsquedas
     *
     * BUENA PRÁCTICA: @NotBlank asegura que no lleguen datos vacíos.
     * BUENA PRÁCTICA: El dato viaja en el body (no en la URL).
     */
    public record EncryptRequest(

        @NotBlank(message = "El dato sensible no puede estar vacío")
        @JsonProperty("plaintext")
        String plaintext,           // Dato en claro: "4111111111111111"

        @NotBlank(message = "El tipo de dato es obligatorio")
        @Pattern(
            regexp = "CARD_NUMBER|ACCOUNT_NUMBER|NATIONAL_ID|EMAIL",
            message = "dataType debe ser: CARD_NUMBER, ACCOUNT_NUMBER, NATIONAL_ID o EMAIL"
        )
        @JsonProperty("dataType")
        String dataType,            // Tipo: CARD_NUMBER, EMAIL, etc.

        @JsonProperty("contextInfo")
        String contextInfo          // Contexto opcional: "pago-123" para auditoría
    ) {}

    // ──────────────────────────────────────────────
    //  RESPONSE: Resultado del cifrado
    // ──────────────────────────────────────────────

    /**
     * Respuesta del cifrado. Contiene el "Envelope" completo:
     *
     * CONCEPTO ENVELOPE ENCRYPTION:
     * ┌─────────────────────────────────────────────┐
     * │  encryptedCek  = RSA_OAEP( CEK )            │  ← CEK cifrada con K-pub RSA
     * │  ciphertext    = AES_GCM( plaintext, CEK )  │  ← Dato cifrado con CEK
     * │  iv            = 12 bytes aleatorios         │  ← Vector de inicialización
     * │  authTag       = 16 bytes GCM               │  ← Integridad del ciphertext
     * │  keyId         = identificador de la clave   │  ← Qué clave RSA usamos
     * └─────────────────────────────────────────────┘
     *
     * El receptor necesita:
     * 1. Usar keyId para saber qué K-priv RSA usar
     * 2. Descifrar encryptedCek con la K-priv → obtiene CEK
     * 3. Usar CEK + iv + authTag para descifrar ciphertext
     */
    public record EncryptResponse(

        @JsonProperty("encryptedCek")
        String encryptedCek,        // Base64( RSA_OAEP( CEK de 32 bytes ) )

        @JsonProperty("ciphertext")
        String ciphertext,          // Base64( AES_256_GCM( plaintext ) )

        @JsonProperty("iv")
        String iv,                  // Base64( 12 bytes aleatorios )

        @JsonProperty("authTag")
        String authTag,             // Base64( 16 bytes GCM auth tag )

        @JsonProperty("keyId")
        String keyId,               // "rsa-key-v1" → identifica la clave RSA usada

        @JsonProperty("dataType")
        String dataType,            // Tipo de dato cifrado

        @JsonProperty("maskedPreview")
        String maskedPreview        // Vista enmascarada para logs: "4111****1111"
    ) {}

    // ──────────────────────────────────────────────
    //  REQUEST: Descifrar un envelope
    // ──────────────────────────────────────────────

    /**
     * Request para descifrar. Recibe el envelope completo.
     * BUENA PRÁCTICA: Se valida que todos los campos del envelope estén presentes.
     */
    public record DecryptRequest(

        @NotBlank(message = "encryptedCek es obligatorio")
        @JsonProperty("encryptedCek")
        String encryptedCek,

        @NotBlank(message = "ciphertext es obligatorio")
        @JsonProperty("ciphertext")
        String ciphertext,

        @NotBlank(message = "iv es obligatorio")
        @JsonProperty("iv")
        String iv,

        @NotBlank(message = "authTag es obligatorio")
        @JsonProperty("authTag")
        String authTag,

        @NotBlank(message = "keyId es obligatorio")
        @JsonProperty("keyId")
        String keyId,

        @JsonProperty("dataType")
        String dataType
    ) {}

    // ──────────────────────────────────────────────
    //  RESPONSE: Resultado del descifrado
    // ──────────────────────────────────────────────

    /**
     * Respuesta de descifrado.
     *
     * IMPORTANTE EDUCATIVO: En un sistema real, el dato descifrado
     * NUNCA debería viajar por HTTP sin TLS. Aquí lo mostramos
     * solo con fines educativos.
     *
     * En producción: el microservicio descifraría internamente
     * y usaría el dato sin exponerlo en la respuesta.
     */
    public record DecryptResponse(

        @JsonProperty("plaintext")
        String plaintext,           // El dato descifrado

        @JsonProperty("maskedPreview")
        String maskedPreview,       // Versión enmascarada para logs

        @JsonProperty("dataType")
        String dataType,            // Tipo de dato

        @JsonProperty("integrityVerified")
        boolean integrityVerified   // ¿El authTag fue válido? true = no hubo tampering
    ) {}

    // ──────────────────────────────────────────────
    //  REQUEST: Solo ofuscar (para logs seguros)
    // ──────────────────────────────────────────────

    /**
     * Request para ofuscar un dato (sin cifrado, solo para mostrar en logs).
     * CONCEPTO: La ofuscación enmascara visualmente, NO protege criptográficamente.
     * Sirve para: logs, trazas, respuestas parciales al usuario.
     */
    public record ObfuscateRequest(

        @NotBlank(message = "El dato no puede estar vacío")
        @JsonProperty("value")
        String value,

        @NotBlank(message = "El tipo de dato es obligatorio")
        @JsonProperty("dataType")
        String dataType
    ) {}

    /**
     * Respuesta de ofuscación.
     */
    public record ObfuscateResponse(

        @JsonProperty("masked")
        String masked,              // "4111****1111" o "jua***@gmail.com"

        @JsonProperty("dataType")
        String dataType,

        @JsonProperty("technique")
        String technique            // Describe qué técnica se usó
    ) {}

    // ──────────────────────────────────────────────
    //  RESPONSE: Error estándar
    // ──────────────────────────────────────────────

    /**
     * Respuesta de error estandarizada.
     * BUENA PRÁCTICA: Nunca exponer stack traces al cliente.
     * Solo devolver un código y mensaje genérico.
     */
    public record ErrorResponse(

        @JsonProperty("code")
        String code,                // "CRYPTO_001", "INVALID_REQUEST", etc.

        @JsonProperty("message")
        String message,             // Mensaje para el desarrollador

        @JsonProperty("timestamp")
        String timestamp            // Cuándo ocurrió el error
    ) {}
}
