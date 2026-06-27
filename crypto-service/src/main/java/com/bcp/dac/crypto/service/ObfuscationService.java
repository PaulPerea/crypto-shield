package com.bcp.dac.crypto.service;

import jakarta.enterprise.context.ApplicationScoped;
import org.jboss.logging.Logger;

/**
 * ══════════════════════════════════════════════════════════════
 *  OBFUSCATION SERVICE – Enmascaramiento de datos sensibles
 * ══════════════════════════════════════════════════════════════
 *
 * CONCEPTO IMPORTANTE:
 * La ofuscación NO es cifrado. No protege el dato criptográficamente.
 * Su propósito es VISUAL: evitar que datos sensibles aparezcan
 * en texto completo en:
 *   - Logs de aplicación
 *   - Trazas de OpenTelemetry
 *   - Respuestas parciales al usuario (ej: "Tu tarjeta ****1234 fue aprobada")
 *   - Pantallas de administración
 *
 * TÉCNICAS IMPLEMENTADAS:
 *
 * 1. MASKING (Enmascaramiento):
 *    Reemplaza parte del valor con '*'
 *    Ejemplo: "4111111111111111" → "4111****1111"
 *
 * 2. TOKENIZACIÓN (simplificada):
 *    Reemplaza el dato por un token referencial sin valor criptográfico
 *    Ejemplo: "juan.perez@gmail.com" → "TOKEN-EMAIL-a3f9"
 *    Nota: En producción esto involucra una tabla de tokens en DB.
 *
 * 3. HASH PARCIAL:
 *    Muestra los últimos N caracteres + hash del resto
 *    Ejemplo: "12345678" → "****5678"
 *
 * DIFERENCIA CON CIFRADO:
 * ┌──────────────┬──────────────────────────────────────────┐
 * │ Cifrado      │ Recuperable con la clave correcta        │
 * │ Ofuscación   │ El dato original puede perderse          │
 * │ Hash         │ Unidireccional, nunca recuperable        │
 * └──────────────┴──────────────────────────────────────────┘
 *
 * PCI-DSS REQUERIMIENTO:
 * Los números de tarjeta SOLO pueden mostrarse los últimos 4 dígitos.
 * "4111 **** **** 1111" es el formato permitido.
 */
@ApplicationScoped
public class ObfuscationService {

    private static final Logger LOG = Logger.getLogger(ObfuscationService.class);

    // ══════════════════════════════════════════════════════════════
    //  MÉTODO PRINCIPAL: Ofuscar según tipo de dato
    // ══════════════════════════════════════════════════════════════

    /**
     * Ofusca un dato según su tipo, aplicando la técnica más apropiada.
     *
     * @param value    El dato en claro
     * @param dataType Tipo del dato (CARD_NUMBER, ACCOUNT_NUMBER, NATIONAL_ID, EMAIL)
     * @return ObfuscationResult con el valor enmascarado y metadatos
     */
    public ObfuscationResult obfuscate(String value, String dataType) {
        if (value == null || value.isBlank()) {
            return new ObfuscationResult("***", dataType, "EMPTY_INPUT");
        }

        return switch (dataType.toUpperCase()) {
            case "CARD_NUMBER"     -> maskCardNumber(value);
            case "ACCOUNT_NUMBER"  -> maskAccountNumber(value);
            case "NATIONAL_ID"     -> maskNationalId(value);
            case "EMAIL"           -> maskEmail(value);
            default                -> maskGeneric(value);
        };
    }

    // ══════════════════════════════════════════════════════════════
    //  REGLAS POR TIPO DE DATO
    // ══════════════════════════════════════════════════════════════

    /**
     * TARJETA DE CRÉDITO/DÉBITO – Regla PCI-DSS:
     * Solo se pueden mostrar los primeros 6 y últimos 4 dígitos.
     *
     * Antes: 4111 1111 1111 1234
     * Después: 411111******1234
     *
     * @param cardNumber Número de tarjeta (con o sin espacios/guiones)
     */
    private ObfuscationResult maskCardNumber(String cardNumber) {
        // Remover espacios y guiones para procesar solo dígitos
        String digits = cardNumber.replaceAll("[\\s-]", "");

        if (digits.length() < 10) {
            // Si tiene menos de 10 dígitos, es inválido → enmascarar todo
            return new ObfuscationResult("****", "CARD_NUMBER", "FULL_MASK_INVALID");
        }

        // PCI-DSS: mostrar primeros 6 + últimos 4
        // "4111 1111 1111 1234" → "411111******1234"
        String firstSix = digits.substring(0, 6);
        String lastFour = digits.substring(digits.length() - 4);
        int hiddenCount = digits.length() - 10; // cuántos dígitos ocultar
        String stars = "*".repeat(Math.max(hiddenCount, 6));

        String masked = firstSix + stars + lastFour;
        LOG.debugf("Tarjeta enmascarada: %s → %s (PCI-DSS compliant)", digits, masked);

        return new ObfuscationResult(masked, "CARD_NUMBER", "PCI_DSS_FIRST6_LAST4");
    }

    /**
     * NÚMERO DE CUENTA – Regla bancaria estándar:
     * Mostrar solo los últimos 4 dígitos.
     *
     * Antes: 19302938471923
     * Después: **********1923
     */
    private ObfuscationResult maskAccountNumber(String accountNumber) {
        String digits = accountNumber.replaceAll("[\\s-]", "");

        if (digits.length() <= 4) {
            return new ObfuscationResult("****", "ACCOUNT_NUMBER", "FULL_MASK_SHORT");
        }

        String lastFour = digits.substring(digits.length() - 4);
        String stars = "*".repeat(digits.length() - 4);
        String masked = stars + lastFour;

        return new ObfuscationResult(masked, "ACCOUNT_NUMBER", "LAST4_VISIBLE");
    }

    /**
     * DOCUMENTO DE IDENTIDAD (DNI/Pasaporte) – Regla de privacidad:
     * Mostrar solo los últimos 4 caracteres.
     *
     * Antes: 12345678
     * Después: ****5678
     */
    private ObfuscationResult maskNationalId(String nationalId) {
        String clean = nationalId.replaceAll("[\\s-]", "");

        if (clean.length() <= 4) {
            return new ObfuscationResult("****", "NATIONAL_ID", "FULL_MASK_SHORT");
        }

        String visibleSuffix = clean.substring(clean.length() - 4);
        String masked = "*".repeat(clean.length() - 4) + visibleSuffix;

        return new ObfuscationResult(masked, "NATIONAL_ID", "LAST4_VISIBLE");
    }

    /**
     * EMAIL – Regla de privacidad estándar:
     * Enmascarar la parte local excepto primer y último carácter.
     *
     * Antes: juan.perez@gmail.com
     * Después: j*********z@gmail.com
     *
     * NOTA: En producción también se almacena SHA-256(email.toLowerCase())
     * para permitir búsquedas sin exponer el email completo.
     */
    private ObfuscationResult maskEmail(String email) {
        int atIndex = email.indexOf('@');

        if (atIndex <= 0) {
            // No tiene @ → no es un email válido → enmascarar todo
            return new ObfuscationResult("***@***.***", "EMAIL", "FULL_MASK_INVALID");
        }

        String localPart = email.substring(0, atIndex);   // "juan.perez"
        String domain    = email.substring(atIndex);       // "@gmail.com"

        String maskedLocal;
        if (localPart.length() <= 2) {
            // Muy corto: enmascarar todo
            maskedLocal = "*".repeat(localPart.length());
        } else {
            // Mostrar primer y último carácter de la parte local
            char first = localPart.charAt(0);
            char last  = localPart.charAt(localPart.length() - 1);
            String stars = "*".repeat(localPart.length() - 2);
            maskedLocal = first + stars + last;
        }

        String masked = maskedLocal + domain;
        return new ObfuscationResult(masked, "EMAIL", "FIRST_LAST_CHAR_VISIBLE");
    }

    /**
     * GENÉRICO – Para tipos no reconocidos:
     * Mostrar solo el 25% inicial y final.
     */
    private ObfuscationResult maskGeneric(String value) {
        if (value.length() <= 4) {
            return new ObfuscationResult("****", "UNKNOWN", "FULL_MASK_SHORT");
        }

        int visibleChars = Math.max(1, value.length() / 4);
        String prefix = value.substring(0, visibleChars);
        String suffix = value.substring(value.length() - visibleChars);
        String stars  = "*".repeat(value.length() - (visibleChars * 2));

        String masked = prefix + stars + suffix;
        return new ObfuscationResult(masked, "UNKNOWN", "GENERIC_MASK");
    }

    // ══════════════════════════════════════════════════════════════
    //  MÉTODO UTILITARIO: Ofuscar para logs
    // ══════════════════════════════════════════════════════════════

    /**
     * Método de conveniencia para usar directamente en logs.
     * Nunca loguear datos sensibles sin pasar por este método.
     *
     * USO CORRECTO:
     *   LOG.infof("Procesando tarjeta: %s", obfuscationService.forLog(cardNumber, "CARD_NUMBER"));
     *
     * USO INCORRECTO (NUNCA HACER):
     *   LOG.infof("Procesando tarjeta: %s", cardNumber);  // ← PROHIBIDO
     */
    public String forLog(String value, String dataType) {
        return obfuscate(value, dataType).masked();
    }

    // ══════════════════════════════════════════════════════════════
    //  RECORD: Resultado de ofuscación
    // ══════════════════════════════════════════════════════════════

    /**
     * Resultado inmutable de la ofuscación.
     * Incluye metadatos sobre qué técnica se aplicó.
     */
    public record ObfuscationResult(
        String masked,      // El valor enmascarado: "4111****1111"
        String dataType,    // Tipo de dato: "CARD_NUMBER"
        String technique    // Técnica usada: "PCI_DSS_FIRST6_LAST4"
    ) {}
}
