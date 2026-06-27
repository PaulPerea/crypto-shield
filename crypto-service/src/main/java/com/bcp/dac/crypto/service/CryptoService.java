package com.bcp.dac.crypto.service;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.util.Base64;

/**
 * ══════════════════════════════════════════════════════════════
 *  CRYPTO SERVICE – Cifrado y descifrado con Envelope Encryption
 * ══════════════════════════════════════════════════════════════
 *
 * FLUJO COMPLETO DE CIFRADO (Envelope Encryption):
 *
 * CIFRADO:
 *  Dato plano
 *    │
 *    ├──► [1] Generar CEK aleatoria (AES-256, 32 bytes)
 *    │
 *    ├──► [2] Cifrar dato con CEK usando AES-256-GCM
 *    │         → produce: ciphertext + iv + authTag
 *    │
 *    ├──► [3] Cifrar CEK con K-pub RSA usando RSA-OAEP
 *    │         → produce: encryptedCek
 *    │
 *    └──► [4] Empaquetar todo: { encryptedCek, ciphertext, iv, authTag, keyId }
 *
 * DESCIFRADO (solo quien tenga K-priv puede hacerlo):
 *  Envelope { encryptedCek, ciphertext, iv, authTag, keyId }
 *    │
 *    ├──► [1] Descifrar encryptedCek con K-priv RSA → recupera CEK
 *    │
 *    ├──► [2] Descifrar ciphertext con CEK + iv → recupera dato
 *    │
 *    └──► [3] Verificar authTag → garantiza integridad (no hubo tampering)
 *
 * ¿POR QUÉ NO USAR RSA DIRECTAMENTE PARA CIFRAR EL DATO?
 *   RSA-2048 solo puede cifrar ~190 bytes. Los datos reales pueden ser mayores.
 *   Además, RSA es ~1000x más lento que AES. La combinación RSA+AES es óptima.
 *
 * ¿POR QUÉ AES-GCM EN VEZ DE AES-CBC?
 *   GCM (Galois/Counter Mode) incluye autenticación integrada (AEAD).
 *   Detecta si alguien modificó el ciphertext, sin necesidad de HMAC separado.
 *   CBC solo cifra; no detecta modificaciones.
 */
@ApplicationScoped
public class CryptoService {

    private static final Logger LOG = Logger.getLogger(CryptoService.class);

    // ── Constantes de configuración criptográfica ──────────────────

    /** AES con GCM (Galois/Counter Mode): cifrado autenticado (AEAD) */
    private static final String AES_ALGORITHM = "AES/GCM/NoPadding";

    /** Tamaño del IV para GCM: NIST recomienda exactamente 12 bytes (96 bits) */
    private static final int GCM_IV_LENGTH_BYTES = 12;

    /** Tamaño del Authentication Tag GCM: máximo posible = 128 bits = 16 bytes */
    private static final int GCM_TAG_LENGTH_BITS = 128;

    /** Tamaño de la CEK (Content Encryption Key) para AES-256: 32 bytes = 256 bits */
    private static final int AES_KEY_SIZE_BYTES = 32;

    /**
     * RSA-OAEP con SHA-256.
     * OAEP (Optimal Asymmetric Encryption Padding) es más seguro que PKCS#1 v1.5.
     * Protege contra ataques de padding oracle (Bleichenbacher attack).
     */
    private static final String RSA_ALGORITHM = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

    // ── Generador seguro de números aleatorios ─────────────────────
    // SecureRandom es thread-safe y produce aleatoriedad criptográficamente segura.
    // NUNCA usar Math.random() o new Random() para criptografía.
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    // Codificador/decodificador Base64 para serializar bytes a String
    private static final Base64.Encoder B64_ENCODER = Base64.getEncoder();
    private static final Base64.Decoder B64_DECODER = Base64.getDecoder();

    @Inject
    KeyStoreService keyStoreService;

    // ══════════════════════════════════════════════════════════════
    //  CIFRADO COMPLETO (Envelope Encryption)
    // ══════════════════════════════════════════════════════════════

    /**
     * Cifra un dato sensible usando Envelope Encryption.
     *
     * @param plaintext El dato en claro (ej: "4111111111111111")
     * @param keyId     Identificador de la clave RSA a usar
     * @return EnvelopeResult con todos los componentes del envelope
     */
    public EnvelopeResult encrypt(String plaintext, String keyId) {
        LOG.debugf("Iniciando cifrado | keyId=%s | dataLen=%d chars", keyId, plaintext.length());

        try {
            // ── PASO 1: Generar CEK efímera (AES-256) ─────────────
            // CEK = Content Encryption Key
            // "Efímera" = se genera una nueva por cada operación.
            // Si una CEK se compromete, solo UN dato queda expuesto.
            SecretKey cek = generateAesCek();
            LOG.debug("PASO 1: CEK AES-256 generada (efímera, 32 bytes)");

            // ── PASO 2: Generar IV aleatorio para GCM ─────────────
            // IV = Initialization Vector (Vector de Inicialización)
            // NUNCA reutilizar el mismo IV con la misma clave.
            // GCM requiere 12 bytes (96 bits) según NIST SP 800-38D.
            byte[] iv = generateIv();
            LOG.debug("PASO 2: IV generado (12 bytes aleatorios)");

            // ── PASO 3: Cifrar el dato con AES-256-GCM ─────────────
            // GCMParameterSpec especifica el IV y el tamaño del tag de autenticación
            GCMParameterSpec gcmParams = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
            Cipher aesCipher = Cipher.getInstance(AES_ALGORITHM);
            aesCipher.init(Cipher.ENCRYPT_MODE, cek, gcmParams);

            // El ciphertext de GCM incluye el authTag al final.
            // Java's GCM concatena: ciphertext_bytes + authTag_bytes (16 bytes)
            byte[] ciphertextWithTag = aesCipher.doFinal(plaintext.getBytes("UTF-8"));

            // Separar el ciphertext del authTag (el tag siempre está al final)
            int tagOffset = ciphertextWithTag.length - (GCM_TAG_LENGTH_BITS / 8);
            byte[] ciphertext = new byte[tagOffset];
            byte[] authTag    = new byte[GCM_TAG_LENGTH_BITS / 8];
            System.arraycopy(ciphertextWithTag, 0,         ciphertext, 0, tagOffset);
            System.arraycopy(ciphertextWithTag, tagOffset, authTag,    0, authTag.length);

            LOG.debugf("PASO 3: Dato cifrado con AES-256-GCM | ciphertextLen=%d | tagLen=%d",
                ciphertext.length, authTag.length);

            // ── PASO 4: Cifrar la CEK con K-pub RSA (OAEP) ─────────
            // Esto "envuelve" la CEK de forma que solo el dueño de K-priv pueda abrirla.
            // Analogy: Es como poner la llave de la caja fuerte (CEK)
            //          dentro de otro cofre con candado RSA (K-pub).
            PublicKey rsaPublicKey = keyStoreService.getPublicKey(keyId);
            byte[] encryptedCek = rsaEncryptCek(cek.getEncoded(), rsaPublicKey);
            LOG.debugf("PASO 4: CEK cifrada con RSA-2048-OAEP | encryptedCekLen=%d bytes", encryptedCek.length);

            // ── RESULTADO: Armar el envelope ───────────────────────
            EnvelopeResult result = new EnvelopeResult(
                B64_ENCODER.encodeToString(encryptedCek),   // CEK cifrada con RSA
                B64_ENCODER.encodeToString(ciphertext),      // Dato cifrado con AES
                B64_ENCODER.encodeToString(iv),              // IV para descifrar
                B64_ENCODER.encodeToString(authTag),         // Tag de integridad
                keyId                                        // Qué clave RSA usamos
            );

            LOG.info("Cifrado exitoso | keyId=" + keyId);
            return result;

        } catch (Exception e) {
            LOG.errorf("Error en cifrado: %s", e.getMessage());
            throw new CryptoException("Error durante el cifrado del dato", e);
        }
    }

    // ══════════════════════════════════════════════════════════════
    //  DESCIFRADO COMPLETO
    // ══════════════════════════════════════════════════════════════

    /**
     * Descifra un envelope. Proceso inverso al cifrado.
     *
     * @param encryptedCekB64 CEK cifrada con RSA (Base64)
     * @param ciphertextB64   Ciphertext del dato (Base64)
     * @param ivB64           IV usado en el cifrado (Base64)
     * @param authTagB64      Authentication tag GCM (Base64)
     * @param keyId           Qué clave RSA privada usar
     * @return El dato en claro
     */
    public String decrypt(
        String encryptedCekB64,
        String ciphertextB64,
        String ivB64,
        String authTagB64,
        String keyId
    ) {
        LOG.debugf("Iniciando descifrado | keyId=%s", keyId);

        try {
            // ── PASO 1: Decodificar todos los componentes de Base64 ──
            byte[] encryptedCek = B64_DECODER.decode(encryptedCekB64);
            byte[] ciphertext   = B64_DECODER.decode(ciphertextB64);
            byte[] iv           = B64_DECODER.decode(ivB64);
            byte[] authTag      = B64_DECODER.decode(authTagB64);

            // ── PASO 2: Descifrar la CEK con K-priv RSA ─────────────
            // Solo el dueño de K-priv puede hacer esto.
            // En producción: esta operación se haría dentro del Vault
            // (la clave privada NUNCA saldría del Vault).
            PrivateKey rsaPrivateKey = keyStoreService.getPrivateKey(keyId);
            byte[] cekBytes = rsaDecryptCek(encryptedCek, rsaPrivateKey);
            SecretKey cek = new SecretKeySpec(cekBytes, "AES");
            LOG.debug("PASO 2: CEK descifrada con RSA-2048-OAEP exitosamente");

            // ── PASO 3: Descifrar el dato con AES-256-GCM ───────────
            // Reensamblar ciphertext + authTag (GCM los espera juntos)
            byte[] ciphertextWithTag = new byte[ciphertext.length + authTag.length];
            System.arraycopy(ciphertext, 0, ciphertextWithTag, 0,                ciphertext.length);
            System.arraycopy(authTag,    0, ciphertextWithTag, ciphertext.length, authTag.length);

            GCMParameterSpec gcmParams = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
            Cipher aesCipher = Cipher.getInstance(AES_ALGORITHM);
            aesCipher.init(Cipher.DECRYPT_MODE, cek, gcmParams);

            // Si el authTag no coincide (datos modificados), GCM lanza
            // AEADBadTagException automáticamente. ¡Integridad gratuita!
            byte[] plaintextBytes = aesCipher.doFinal(ciphertextWithTag);
            String plaintext = new String(plaintextBytes, "UTF-8");

            LOG.debug("PASO 3: Dato descifrado y authTag verificado exitosamente");
            LOG.infof("Descifrado exitoso | keyId=%s | plaintextLen=%d", keyId, plaintext.length());

            return plaintext;

        } catch (AEADBadTagException e) {
            // Este error específico indica que el ciphertext fue modificado (tampering).
            LOG.errorf("¡ALERTA DE SEGURIDAD! AuthTag inválido: posible tampering | keyId=%s", keyId);
            throw new CryptoException("Fallo de integridad: el dato fue modificado (authTag inválido)", e);
        } catch (Exception e) {
            LOG.errorf("Error en descifrado: %s", e.getMessage());
            throw new CryptoException("Error durante el descifrado del dato", e);
        }
    }

    // ══════════════════════════════════════════════════════════════
    //  MÉTODOS PÚBLICOS DE CONVENIENCIA
    // ══════════════════════════════════════════════════════════════

    /**
     * Devuelve el keyId activo. Delegado al KeyStoreService.
     * Expuesto aquí para que el Resource no tenga que inyectar KeyStoreService.
     */
    public String getActiveKeyIdFromService() {
        return keyStoreService.getActiveKeyId();
    }

    // ══════════════════════════════════════════════════════════════
    //  MÉTODOS PRIVADOS AUXILIARES
    // ══════════════════════════════════════════════════════════════

    /**
     * Genera una CEK AES-256 aleatoria.
     * AES-256 requiere exactamente 32 bytes = 256 bits.
     */
    private SecretKey generateAesCek() throws NoSuchAlgorithmException {
        byte[] keyBytes = new byte[AES_KEY_SIZE_BYTES];
        SECURE_RANDOM.nextBytes(keyBytes);  // Rellena con bytes aleatorios seguros
        return new SecretKeySpec(keyBytes, "AES");
    }

    /**
     * Genera un IV (Initialization Vector) aleatorio de 12 bytes para GCM.
     * REGLA DE ORO: Nunca reusar el mismo IV con la misma clave.
     */
    private byte[] generateIv() {
        byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
        SECURE_RANDOM.nextBytes(iv);
        return iv;
    }

    /**
     * Cifra la CEK con la clave pública RSA usando OAEP.
     * RSA-OAEP es más seguro que RSA-PKCS1v1.5 porque:
     *  - Incluye padding aleatorio → mismo input produce diferente output
     *  - Resistente a ataques de padding oracle
     */
    private byte[] rsaEncryptCek(byte[] cekBytes, PublicKey publicKey) throws Exception {
        Cipher rsaCipher = Cipher.getInstance(RSA_ALGORITHM);
        rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey, SECURE_RANDOM);
        return rsaCipher.doFinal(cekBytes);
    }

    /**
     * Descifra la CEK con la clave privada RSA usando OAEP.
     */
    private byte[] rsaDecryptCek(byte[] encryptedCek, PrivateKey privateKey) throws Exception {
        Cipher rsaCipher = Cipher.getInstance(RSA_ALGORITHM);
        rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
        return rsaCipher.doFinal(encryptedCek);
    }

    // ══════════════════════════════════════════════════════════════
    //  RECORD INTERNO: Resultado del envelope
    // ══════════════════════════════════════════════════════════════

    /**
     * Contiene todos los componentes del envelope cifrado.
     * Java 21 Record: inmutable por diseño.
     */
    public record EnvelopeResult(
        String encryptedCek,    // Base64(RSA_OAEP(CEK))
        String ciphertext,      // Base64(AES_GCM(plaintext))
        String iv,              // Base64(12 bytes random)
        String authTag,         // Base64(16 bytes GCM tag)
        String keyId            // Referencia a qué clave RSA se usó
    ) {}

    // ══════════════════════════════════════════════════════════════
    //  EXCEPCIÓN PERSONALIZADA
    // ══════════════════════════════════════════════════════════════

    /**
     * Excepción de dominio para errores de criptografía.
     * BUENA PRÁCTICA: Usar excepciones de dominio en vez de
     * exponer excepciones de la JCA/JCE al cliente.
     */
    public static class CryptoException extends RuntimeException {
        public CryptoException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
