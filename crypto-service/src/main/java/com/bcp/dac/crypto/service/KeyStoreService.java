package com.bcp.dac.crypto.service;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.annotation.PostConstruct;
import org.jboss.logging.Logger;

import java.security.*;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * ══════════════════════════════════════════════════════════════
 *  KEY STORE SERVICE – Gestión de claves RSA
 * ══════════════════════════════════════════════════════════════
 *
 * PROPÓSITO EDUCATIVO:
 * Este servicio simula lo que en producción haría HashiCorp Vault
 * o Azure Key Vault. Aquí generamos las claves RSA en memoria
 * para que el ejemplo sea autocontenido y ejecutable sin
 * infraestructura externa.
 *
 * EN PRODUCCIÓN:
 * - La clave PRIVADA vive en HashiCorp Vault (Transit Engine)
 * - La clave PÚBLICA se distribuye vía Azure Key Vault
 * - Las claves se rotan cada 12 meses automáticamente
 * - El acceso se controla con AppRole + Kubernetes Auth
 *
 * CONCEPTO RSA:
 * ┌──────────────────────────────────────────────────┐
 * │  K-pub  → Todos pueden cifrar con ella           │
 * │  K-priv → Solo el dueño puede descifrar          │
 * │                                                  │
 * │  Si alguien intercepta el ciphertext,            │
 * │  sin K-priv NO puede descifrar el dato.          │
 * └──────────────────────────────────────────────────┘
 *
 * @ApplicationScoped: Quarkus crea UNA sola instancia (singleton).
 *   Esto es importante para las claves: se generan una vez y se
 *   reutilizan durante toda la vida del servicio.
 */
@ApplicationScoped
public class KeyStoreService {

    private static final Logger LOG = Logger.getLogger(KeyStoreService.class);

    // Tamaño de clave RSA: 2048 bits es el estándar mínimo seguro.
    // En producción se usa 4096 para mayor seguridad (con más latencia).
    private static final int RSA_KEY_SIZE = 2048;

    // Identificador de la versión de clave. En producción, este ID
    // apuntaría a una versión específica en el Vault.
    // Ejemplo real: "akv://keys/rsa-bcp-prod/3"
    private static final String KEY_ID = "rsa-key-v1";

    // Almacén de pares de claves. En producción, SOLO la clave pública
    // estaría en memoria; la privada se solicitaría al Vault en cada operación.
    private final Map<String, KeyPair> keyStore = new ConcurrentHashMap<>();

    /**
     * @PostConstruct: Se ejecuta automáticamente cuando Quarkus
     * inicializa el bean. Aquí generamos las claves RSA.
     *
     * EDUCATIVO: En producción esto sería una llamada al Vault:
     *   vaultClient.getPublicKey("rsa-key-v1")
     *   vaultClient.decrypt("rsa-key-v1", encryptedCek)  // la priv nunca sale del vault
     */
    @PostConstruct
    void initializeKeys() {
        LOG.info("═══════════════════════════════════════════════");
        LOG.info("  Inicializando Key Store (modo educativo)");
        LOG.info("  EN PRODUCCIÓN: Las claves vendrían de Vault");
        LOG.info("═══════════════════════════════════════════════");

        try {
            // Generar par de claves RSA-2048
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            // SecureRandom es el generador seguro de números aleatorios.
            // NUNCA usar java.util.Random para criptografía.
            generator.initialize(RSA_KEY_SIZE, new SecureRandom());

            KeyPair keyPair = generator.generateKeyPair();
            keyStore.put(KEY_ID, keyPair);

            LOG.infof("  Clave RSA generada exitosamente | keyId=%s | bits=%d", KEY_ID, RSA_KEY_SIZE);
            LOG.info("  K-pub alg: " + keyPair.getPublic().getAlgorithm());
            LOG.info("  K-priv alg: " + keyPair.getPrivate().getAlgorithm());
            LOG.info("═══════════════════════════════════════════════");

        } catch (NoSuchAlgorithmException e) {
            // Si RSA no está disponible en la JVM, el servicio no puede arrancar.
            throw new IllegalStateException("RSA no disponible en esta JVM. Verifica el proveedor de seguridad.", e);
        }
    }

    /**
     * Obtiene la clave PÚBLICA para cifrar.
     * La clave pública puede distribuirse libremente.
     *
     * @param keyId Identificador de la clave
     * @return PublicKey RSA
     */
    public PublicKey getPublicKey(String keyId) {
        KeyPair pair = keyStore.get(keyId);
        if (pair == null) {
            throw new IllegalArgumentException("Clave no encontrada: " + keyId +
                ". Claves disponibles: " + keyStore.keySet());
        }
        return pair.getPublic();
    }

    /**
     * Obtiene la clave PRIVADA para descifrar.
     * ¡ACCESO RESTRINGIDO! En producción este método haría
     * una llamada autenticada a HashiCorp Vault.
     *
     * @param keyId Identificador de la clave
     * @return PrivateKey RSA
     */
    public PrivateKey getPrivateKey(String keyId) {
        LOG.debugf("Acceso a clave privada solicitado | keyId=%s [EN PROD: esto sería una llamada al Vault]", keyId);
        KeyPair pair = keyStore.get(keyId);
        if (pair == null) {
            throw new IllegalArgumentException("Clave privada no encontrada: " + keyId);
        }
        return pair.getPrivate();
    }

    /**
     * Devuelve el keyId activo para cifrar nuevos datos.
     * En producción, siempre se cifra con la versión más reciente.
     */
    public String getActiveKeyId() {
        return KEY_ID;
    }
}
