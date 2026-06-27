package com.bcp.dac.account.service;

import com.bcp.dac.account.client.CryptoClient;
import com.bcp.dac.account.model.AccountModels.*;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.rest.client.inject.RestClient;
import org.jboss.logging.Logger;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * ══════════════════════════════════════════════════════════════
 *  ACCOUNT SERVICE – Lógica de negocio de cuentas
 * ══════════════════════════════════════════════════════════════
 *
 * RESPONSABILIDAD:
 * Gestionar cuentas bancarias asegurando que los datos sensibles
 * (número de cuenta, número de tarjeta) NUNCA se almacenen en claro.
 *
 * FLUJO AL CREAR UNA CUENTA:
 *  1. Recibe datos en claro (holderName, accountNumber, cardNumber)
 *  2. Llama al Crypto Service para cifrar accountNumber → envelope_1
 *  3. Llama al Crypto Service para cifrar cardNumber    → envelope_2
 *  4. Almacena SOLO los envelopes (datos cifrados)
 *  5. Nunca persiste los datos en claro
 *
 * FLUJO AL CONSULTAR UNA CUENTA:
 *  1. Lee los envelopes cifrados del "almacén" (simulado en memoria)
 *  2. Devuelve versiones enmascaradas sin descifrar
 *  3. Solo revela en claro si se llama explícitamente a /reveal
 *
 * NOTA EDUCATIVA:
 * Usamos un Map en memoria como almacén. En producción sería una DB
 * (PostgreSQL, Cosmos DB) con los campos ciphertext almacenados.
 */
@ApplicationScoped
public class AccountService {

    private static final Logger LOG = Logger.getLogger(AccountService.class);

    @Inject
    @RestClient
    CryptoClient cryptoClient;

    // Almacén en memoria (simula una base de datos)
    // En producción: repositorio JPA/Panache con campos cifrados
    private final Map<String, StoredAccount> accountStore = new ConcurrentHashMap<>();

    // ══════════════════════════════════════════════════════════════
    //  CREAR CUENTA – Cifra y persiste
    // ══════════════════════════════════════════════════════════════

    /**
     * Crea una nueva cuenta cifrando todos los datos sensibles.
     *
     * @param request Datos de la cuenta en claro (vienen por HTTPS)
     * @return Respuesta con datos enmascarados (nunca en claro)
     */
    public CreateAccountResponse createAccount(CreateAccountRequest request) {
        String accountId = UUID.randomUUID().toString();
        LOG.infof("Creando cuenta | accountId=%s | holder=%s", accountId, request.holderName());

        // ── CIFRAR NÚMERO DE CUENTA ────────────────────────────
        LOG.debug("Cifrando número de cuenta...");
        var encryptAccountReq = new CryptoClient.EncryptRequest(
            request.accountNumber(),
            "ACCOUNT_NUMBER",
            "create-account-" + accountId
        );
        var encryptedAccount = cryptoClient.encrypt(encryptAccountReq);
        LOG.debugf("Número de cuenta cifrado | masked=%s", encryptedAccount.maskedPreview());

        // ── CIFRAR NÚMERO DE TARJETA ───────────────────────────
        LOG.debug("Cifrando número de tarjeta...");
        var encryptCardReq = new CryptoClient.EncryptRequest(
            request.cardNumber(),
            "CARD_NUMBER",
            "create-account-card-" + accountId
        );
        var encryptedCard = cryptoClient.encrypt(encryptCardReq);
        LOG.debugf("Número de tarjeta cifrado | masked=%s", encryptedCard.maskedPreview());

        // ── CONSTRUIR ENVELOPES PARA PERSISTIR ─────────────────
        var storedAccountEnvelope = new StoredEnvelope(
            encryptedAccount.encryptedCek(),
            encryptedAccount.ciphertext(),
            encryptedAccount.iv(),
            encryptedAccount.authTag(),
            encryptedAccount.keyId()
        );

        var storedCardEnvelope = new StoredEnvelope(
            encryptedCard.encryptedCek(),
            encryptedCard.ciphertext(),
            encryptedCard.iv(),
            encryptedCard.authTag(),
            encryptedCard.keyId()
        );

        // ── PERSISTIR (simulado en memoria) ────────────────────
        // En producción: accountRepository.save(storedAccount)
        // Los campos ciphertext son columnas VARCHAR en la DB
        StoredAccount storedAccount = new StoredAccount(
            accountId,
            request.holderName(),
            encryptedAccount.maskedPreview(),  // Solo el masked para display rápido
            encryptedCard.maskedPreview(),
            request.accountType() != null ? request.accountType() : "SAVINGS",
            "ACTIVE",
            storedAccountEnvelope,
            storedCardEnvelope
        );
        accountStore.put(accountId, storedAccount);

        LOG.infof("Cuenta creada y persistida con datos cifrados | accountId=%s", accountId);

        // ── RESPUESTA: SIN DATOS EN CLARO ─────────────────────
        return new CreateAccountResponse(
            accountId,
            request.holderName(),
            encryptedAccount.maskedPreview(),
            encryptedCard.maskedPreview(),
            storedAccount.accountType(),
            "ACTIVE",
            "Cuenta creada exitosamente. Los datos sensibles fueron cifrados con AES-256-GCM + RSA-2048-OAEP."
        );
    }

    // ══════════════════════════════════════════════════════════════
    //  CONSULTAR CUENTA – Devuelve datos enmascarados
    // ══════════════════════════════════════════════════════════════

    /**
     * Consulta los detalles de una cuenta.
     * Devuelve datos enmascarados + los envelopes cifrados.
     * No descifra automáticamente.
     */
    public AccountDetailsResponse getAccount(String accountId) {
        LOG.infof("Consultando cuenta | accountId=%s", accountId);

        StoredAccount stored = accountStore.get(accountId);
        if (stored == null) {
            throw new AccountNotFoundException("Cuenta no encontrada: " + accountId);
        }

        // Devolver datos enmascarados + envelopes (sin descifrar)
        return new AccountDetailsResponse(
            stored.accountId(),
            stored.holderName(),
            stored.maskedAccountNumber(),
            stored.maskedCardNumber(),
            stored.accountType(),
            stored.status(),
            new EncryptedAccountData(
                stored.encryptedAccountEnvelope(),
                stored.encryptedCardEnvelope()
            )
        );
    }

    // ══════════════════════════════════════════════════════════════
    //  REVELAR DATO – Descifra un campo específico (operación privilegiada)
    // ══════════════════════════════════════════════════════════════

    /**
     * Descifra y devuelve un campo sensible en claro.
     *
     * IMPORTANTE: Esta operación debe estar protegida por:
     * - Autenticación fuerte (JWT + MFA)
     * - Autorización RBAC (solo roles específicos)
     * - Audit log obligatorio
     * - Rate limiting estricto
     *
     * EDUCATIVO: Aquí la implementamos sin protecciones para simplificar.
     */
    public RevealResponse revealField(RevealRequest request) {
        LOG.infof("OPERACIÓN SENSIBLE: Revelar campo | accountId=%s | field=%s",
            request.accountId(), request.field());

        // Buscar la cuenta
        StoredAccount stored = accountStore.get(request.accountId());
        if (stored == null) {
            throw new AccountNotFoundException("Cuenta no encontrada: " + request.accountId());
        }

        // Seleccionar el envelope correcto según el campo solicitado
        StoredEnvelope envelope = switch (request.field()) {
            case "accountNumber" -> stored.encryptedAccountEnvelope();
            case "cardNumber"    -> stored.encryptedCardEnvelope();
            default -> throw new IllegalArgumentException("Campo no válido: " + request.field());
        };

        // Llamar al Crypto Service para descifrar
        var decryptReq = new CryptoClient.DecryptRequest(
            envelope.encryptedCek(),
            envelope.ciphertext(),
            envelope.iv(),
            envelope.authTag(),
            envelope.keyId(),
            request.field().equals("cardNumber") ? "CARD_NUMBER" : "ACCOUNT_NUMBER"
        );

        var decryptResponse = cryptoClient.decrypt(decryptReq);

        LOG.infof("Campo revelado exitosamente | accountId=%s | field=%s | masked=%s",
            request.accountId(), request.field(), decryptResponse.maskedPreview());

        return new RevealResponse(
            request.accountId(),
            request.field(),
            decryptResponse.plaintext(),
            decryptResponse.maskedPreview(),
            decryptResponse.integrityVerified(),
            "⚠️ EDUCATIVO: En producción, el dato en claro no viajaría por HTTP sin cifrado adicional."
        );
    }

    // ══════════════════════════════════════════════════════════════
    //  LISTADO (simplificado)
    // ══════════════════════════════════════════════════════════════

    public java.util.List<AccountSummary> listAccounts() {
        return accountStore.values().stream()
            .map(a -> new AccountSummary(
                a.accountId(),
                a.holderName(),
                a.maskedAccountNumber(),
                a.maskedCardNumber(),
                a.accountType(),
                a.status()
            ))
            .toList();
    }

    // ══════════════════════════════════════════════════════════════
    //  RECORDS INTERNOS (modelo de persistencia)
    // ══════════════════════════════════════════════════════════════

    /**
     * Cuenta tal como se almacena en la "base de datos".
     * Los campos sensibles son SOLO envelopes cifrados.
     * Los campos maskedX son para display rápido sin descifrar.
     */
    record StoredAccount(
        String accountId,
        String holderName,
        String maskedAccountNumber,     // Para display: "**********1923"
        String maskedCardNumber,        // Para display: "411111******1234"
        String accountType,
        String status,
        StoredEnvelope encryptedAccountEnvelope,  // Dato cifrado completo
        StoredEnvelope encryptedCardEnvelope       // Dato cifrado completo
    ) {}

    /**
     * Resumen de cuenta para listados (sin datos sensibles).
     */
    public record AccountSummary(
        String accountId,
        String holderName,
        String maskedAccountNumber,
        String maskedCardNumber,
        String accountType,
        String status
    ) {}

    // ══════════════════════════════════════════════════════════════
    //  EXCEPCIONES DE DOMINIO
    // ══════════════════════════════════════════════════════════════

    public static class AccountNotFoundException extends RuntimeException {
        public AccountNotFoundException(String message) {
            super(message);
        }
    }
}
