package com.bcp.dac.account.client;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import org.eclipse.microprofile.rest.client.inject.RegisterRestClient;

/**
 * ══════════════════════════════════════════════════════════════
 *  CRYPTO CLIENT – Cliente REST para el Crypto Service
 * ══════════════════════════════════════════════════════════════
 *
 * CONCEPTO: MicroProfile REST Client
 * En vez de usar HttpClient manualmente, Quarkus genera automáticamente
 * el cliente HTTP a partir de esta interfaz. Solo definimos los métodos
 * y Quarkus hace el resto.
 *
 * @RegisterRestClient: Le dice a Quarkus que esta interfaz es un REST client.
 *   configKey="crypto-service" → la URL base se configura en application.properties
 *   como: quarkus.rest-client.crypto-service.url=http://localhost:8081
 */
@RegisterRestClient(configKey = "crypto-service")
@Path("/api/v1/crypto")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public interface CryptoClient {

    /**
     * Llama a POST /api/v1/crypto/encrypt del crypto-service.
     * Cifra un dato sensible y devuelve el envelope.
     */
    @POST
    @Path("/encrypt")
    EncryptResponse encrypt(EncryptRequest request);

    /**
     * Llama a POST /api/v1/crypto/decrypt del crypto-service.
     * Descifra un envelope y devuelve el dato en claro.
     */
    @POST
    @Path("/decrypt")
    DecryptResponse decrypt(DecryptRequest request);

    /**
     * Llama a POST /api/v1/crypto/obfuscate del crypto-service.
     * Ofusca un dato para visualización segura.
     */
    @POST
    @Path("/obfuscate")
    ObfuscateResponse obfuscate(ObfuscateRequest request);

    // ──────────────────────────────────────────────────────────
    //  DTOs internos del cliente (espejo de los del crypto-service)
    //  En un proyecto real, estos estarían en un módulo compartido.
    // ──────────────────────────────────────────────────────────

    record EncryptRequest(
        @JsonProperty("plaintext")   String plaintext,
        @JsonProperty("dataType")    String dataType,
        @JsonProperty("contextInfo") String contextInfo
    ) {}

    record EncryptResponse(
        @JsonProperty("encryptedCek")    String encryptedCek,
        @JsonProperty("ciphertext")      String ciphertext,
        @JsonProperty("iv")              String iv,
        @JsonProperty("authTag")         String authTag,
        @JsonProperty("keyId")           String keyId,
        @JsonProperty("dataType")        String dataType,
        @JsonProperty("maskedPreview")   String maskedPreview
    ) {}

    record DecryptRequest(
        @JsonProperty("encryptedCek") String encryptedCek,
        @JsonProperty("ciphertext")   String ciphertext,
        @JsonProperty("iv")           String iv,
        @JsonProperty("authTag")      String authTag,
        @JsonProperty("keyId")        String keyId,
        @JsonProperty("dataType")     String dataType
    ) {}

    record DecryptResponse(
        @JsonProperty("plaintext")          String plaintext,
        @JsonProperty("maskedPreview")      String maskedPreview,
        @JsonProperty("dataType")           String dataType,
        @JsonProperty("integrityVerified")  boolean integrityVerified
    ) {}

    record ObfuscateRequest(
        @JsonProperty("value")    String value,
        @JsonProperty("dataType") String dataType
    ) {}

    record ObfuscateResponse(
        @JsonProperty("masked")    String masked,
        @JsonProperty("dataType")  String dataType,
        @JsonProperty("technique") String technique
    ) {}
}
