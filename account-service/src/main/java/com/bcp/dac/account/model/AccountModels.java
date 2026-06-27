package com.bcp.dac.account.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

/**
 * ══════════════════════════════════════════════════════════════
 *  MODELOS – Account Service
 * ══════════════════════════════════════════════════════════════
 *
 * CONCEPTO DE SEPARACIÓN DE MODELOS:
 * Los modelos de request/response del Account Service son distintos
 * a los del Crypto Service. El Account Service trabaja con conceptos
 * de negocio (Account, Card), no con conceptos criptográficos.
 *
 * El cifrado es un detalle de implementación que el cliente
 * de Account Service no necesita conocer.
 */
public final class AccountModels {

    private AccountModels() {}

    // ──────────────────────────────────────────────
    //  REQUEST: Crear cuenta con datos sensibles
    // ──────────────────────────────────────────────

    /**
     * Request para registrar una nueva cuenta.
     * El cliente envía los datos en claro a través de TLS.
     * Internamente, el Account Service los cifrará antes de almacenarlos.
     */
    public record CreateAccountRequest(

        @NotBlank(message = "El nombre del titular es obligatorio")
        @JsonProperty("holderName")
        String holderName,

        @NotBlank(message = "El número de cuenta es obligatorio")
        @Pattern(regexp = "\\d{10,20}", message = "El número de cuenta debe tener entre 10 y 20 dígitos")
        @JsonProperty("accountNumber")
        String accountNumber,

        @NotBlank(message = "El número de tarjeta es obligatorio")
        @Pattern(regexp = "\\d{16}", message = "El número de tarjeta debe tener 16 dígitos")
        @JsonProperty("cardNumber")
        String cardNumber,

        @JsonProperty("accountType")
        String accountType  // SAVINGS, CHECKING
    ) {}

    // ──────────────────────────────────────────────
    //  RESPONSE: Cuenta creada (sin datos sensibles en claro)
    // ──────────────────────────────────────────────

    /**
     * Respuesta al crear una cuenta.
     *
     * CONCEPTO IMPORTANTE:
     * Los datos sensibles NO se devuelven en claro.
     * Solo se devuelven versiones enmascaradas para confirmar
     * que el sistema los recibió correctamente.
     *
     * maskedAccountNumber: "**********1923"
     * maskedCardNumber:    "411111******1234"
     */
    public record CreateAccountResponse(
        @JsonProperty("accountId")           String accountId,
        @JsonProperty("holderName")          String holderName,
        @JsonProperty("maskedAccountNumber") String maskedAccountNumber,
        @JsonProperty("maskedCardNumber")    String maskedCardNumber,
        @JsonProperty("accountType")         String accountType,
        @JsonProperty("status")              String status,
        @JsonProperty("message")             String message
    ) {}

    // ──────────────────────────────────────────────
    //  RESPONSE: Consulta de cuenta
    // ──────────────────────────────────────────────

    /**
     * Respuesta al consultar una cuenta.
     * Incluye el envelope cifrado para que otro sistema autorizado
     * pueda descifrar si necesita el dato completo.
     */
    public record AccountDetailsResponse(
        @JsonProperty("accountId")           String accountId,
        @JsonProperty("holderName")          String holderName,
        @JsonProperty("maskedAccountNumber") String maskedAccountNumber,
        @JsonProperty("maskedCardNumber")    String maskedCardNumber,
        @JsonProperty("accountType")         String accountType,
        @JsonProperty("status")              String status,
        @JsonProperty("encryptedData")       EncryptedAccountData encryptedData
    ) {}

    /**
     * Datos cifrados de la cuenta (el envelope).
     * Solo sistemas autorizados con K-priv pueden descifrar esto.
     */
    public record EncryptedAccountData(
        @JsonProperty("encryptedAccountNumber") StoredEnvelope encryptedAccountNumber,
        @JsonProperty("encryptedCardNumber")    StoredEnvelope encryptedCardNumber
    ) {}

    /**
     * Envelope almacenado para un campo cifrado.
     * Contiene todo lo necesario para descifrar el dato.
     */
    public record StoredEnvelope(
        @JsonProperty("encryptedCek") String encryptedCek,
        @JsonProperty("ciphertext")   String ciphertext,
        @JsonProperty("iv")           String iv,
        @JsonProperty("authTag")      String authTag,
        @JsonProperty("keyId")        String keyId
    ) {}

    // ──────────────────────────────────────────────
    //  REQUEST: Descifrar y ver el dato completo
    // ──────────────────────────────────────────────

    /**
     * Request para ver un dato en claro (operación privilegiada).
     * En producción requeriría autenticación adicional (MFA, etc.).
     */
    public record RevealRequest(
        @NotBlank(message = "accountId es obligatorio")
        @JsonProperty("accountId")
        String accountId,

        @NotBlank(message = "El campo a revelar es obligatorio")
        @Pattern(regexp = "accountNumber|cardNumber", message = "field debe ser: accountNumber o cardNumber")
        @JsonProperty("field")
        String field        // Qué campo descifrar: "accountNumber" o "cardNumber"
    ) {}

    /**
     * Respuesta al revelar un dato.
     * EDUCATIVO: En producción, el dato descifrado nunca viajaría por HTTP.
     * Se usaría internamente o se mostraría en una sesión segura.
     */
    public record RevealResponse(
        @JsonProperty("accountId")        String accountId,
        @JsonProperty("field")            String field,
        @JsonProperty("plaintext")        String plaintext,
        @JsonProperty("maskedPreview")    String maskedPreview,
        @JsonProperty("integrityOk")      boolean integrityOk,
        @JsonProperty("warning")          String warning
    ) {}

    // ──────────────────────────────────────────────
    //  ERROR
    // ──────────────────────────────────────────────

    public record ErrorResponse(
        @JsonProperty("code")      String code,
        @JsonProperty("message")   String message,
        @JsonProperty("timestamp") String timestamp
    ) {}
}
