package com.bcp.dac.identity.resource;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.inject.Inject;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.tags.Tag;
import org.eclipse.microprofile.rest.client.inject.RegisterRestClient;
import org.eclipse.microprofile.rest.client.inject.RestClient;
import org.jboss.logging.Logger;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * ══════════════════════════════════════════════════════════════
 *  IDENTITY SERVICE – Gestión de identidad con datos cifrados
 * ══════════════════════════════════════════════════════════════
 *
 * Protege: Documento de Identidad (DNI) + Email
 *
 * ADICIONAL EDUCATIVO – Hash de búsqueda:
 * El email se cifra (para recuperar el valor) Y también se
 * almacena su SHA-256 (para buscar por email sin descifrarlo).
 *
 * ┌──────────────────────────────────────────────────────────┐
 * │  email original: juan@gmail.com                          │
 * │  stored:                                                 │
 * │    emailCiphertext: AES_GCM(juan@gmail.com)             │
 * │    emailSearchHash: SHA256(lowercase(juan@gmail.com))   │
 * │                                                          │
 * │  Para buscar por email:                                  │
 * │    calcular SHA256(input) y comparar con emailSearchHash │
 * │    (nunca se necesita descifrar para buscar)             │
 * └──────────────────────────────────────────────────────────┘
 *
 * RUTAS:
 *  POST /api/v1/identities           → Registrar identidad
 *  GET  /api/v1/identities           → Listar (datos enmascarados)
 *  GET  /api/v1/identities/{id}      → Consultar por ID
 *  POST /api/v1/identities/{id}/reveal → Revelar campo
 */
@Path("/api/v1/identities")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
@Tag(name = "Identity Service", description = "Gestión de identidad con DNI y Email cifrados")
public class IdentityResource {

    private static final Logger LOG = Logger.getLogger(IdentityResource.class);

    @Inject
    @RestClient
    CryptoClientForIdentity cryptoClient;

    // Almacén en memoria
    private final Map<String, StoredIdentity> identityStore = new ConcurrentHashMap<>();

    // ──────────────────────────────────────────────────────────
    //  POST /identities – Registrar identidad
    // ──────────────────────────────────────────────────────────

    @POST
    @Operation(
        summary = "Registrar identidad",
        description = """
            Registra DNI y Email cifrando ambos con AES-256-GCM + RSA-2048-OAEP.
            
            Adicionalmente, el email se hashea con SHA-256 para permitir
            búsquedas sin necesidad de descifrar.
            """
    )
    public Response registerIdentity(@Valid RegisterIdentityRequest request) {
        String identityId = UUID.randomUUID().toString();
        LOG.infof("Registrando identidad | identityId=%s | name=%s", identityId, request.fullName());

        try {
            // ── Cifrar DNI ──────────────────────────────────────
            var encryptDniReq = new CryptoClientForIdentity.EncryptReq(
                request.nationalId(), "NATIONAL_ID", "identity-" + identityId);
            var encryptedDni = cryptoClient.encrypt(encryptDniReq);

            // ── Cifrar Email ────────────────────────────────────
            var encryptEmailReq = new CryptoClientForIdentity.EncryptReq(
                request.email(), "EMAIL", "identity-email-" + identityId);
            var encryptedEmail = cryptoClient.encrypt(encryptEmailReq);

            // ── Hash de búsqueda para email ─────────────────────
            // SHA-256 del email en minúsculas → permite buscar sin descifrar
            String emailSearchHash = sha256(request.email().toLowerCase().trim());

            // ── Ofuscar para respuesta ──────────────────────────
            var maskedDniReq   = new CryptoClientForIdentity.ObfuscateReq(request.nationalId(), "NATIONAL_ID");
            var maskedEmailReq = new CryptoClientForIdentity.ObfuscateReq(request.email(), "EMAIL");
            var maskedDni   = cryptoClient.obfuscate(maskedDniReq);
            var maskedEmail = cryptoClient.obfuscate(maskedEmailReq);

            // ── Persistir (en memoria) ──────────────────────────
            StoredIdentity stored = new StoredIdentity(
                identityId,
                request.fullName(),
                maskedDni.masked(),
                maskedEmail.masked(),
                emailSearchHash,
                new StoredEnvelope(encryptedDni.encryptedCek(), encryptedDni.ciphertext(),
                                   encryptedDni.iv(), encryptedDni.authTag(), encryptedDni.keyId()),
                new StoredEnvelope(encryptedEmail.encryptedCek(), encryptedEmail.ciphertext(),
                                   encryptedEmail.iv(), encryptedEmail.authTag(), encryptedEmail.keyId()),
                "ACTIVE"
            );
            identityStore.put(identityId, stored);

            LOG.infof("Identidad registrada | identityId=%s | maskedDni=%s | maskedEmail=%s",
                identityId, maskedDni.masked(), maskedEmail.masked());

            return Response.status(Response.Status.CREATED).entity(new RegisterResponse(
                identityId, request.fullName(),
                maskedDni.masked(), maskedEmail.masked(), "ACTIVE",
                "emailSearchHash: " + emailSearchHash.substring(0, 8) + "... (SHA-256 para búsquedas)",
                "Identidad registrada. DNI y Email cifrados con AES-256-GCM + RSA-OAEP."
            )).build();

        } catch (Exception e) {
            LOG.errorf("Error al registrar identidad: %s", e.getMessage());
            return Response.serverError()
                .entity(new ErrorResp("IDENTITY_001", "Error al registrar identidad"))
                .build();
        }
    }

    // ──────────────────────────────────────────────────────────
    //  GET /identities – Listar
    // ──────────────────────────────────────────────────────────

    @GET
    @Operation(summary = "Listar identidades (datos enmascarados)")
    public Response listIdentities() {
        var list = identityStore.values().stream()
            .map(i -> new IdentitySummary(i.identityId(), i.fullName(),
                    i.maskedNationalId(), i.maskedEmail(), i.status()))
            .toList();
        return Response.ok(list).build();
    }

    // ──────────────────────────────────────────────────────────
    //  GET /identities/{id} – Consultar
    // ──────────────────────────────────────────────────────────

    @GET
    @Path("/{identityId}")
    @Operation(summary = "Consultar identidad por ID (datos enmascarados)")
    public Response getIdentity(@PathParam("identityId") String identityId) {
        StoredIdentity stored = identityStore.get(identityId);
        if (stored == null) {
            return Response.status(404)
                .entity(new ErrorResp("NOT_FOUND", "Identidad no encontrada: " + identityId))
                .build();
        }
        return Response.ok(new IdentityDetails(
            stored.identityId(), stored.fullName(),
            stored.maskedNationalId(), stored.maskedEmail(),
            stored.emailSearchHash().substring(0, 12) + "...",
            stored.status()
        )).build();
    }

    // ──────────────────────────────────────────────────────────
    //  POST /identities/{id}/reveal – Revelar campo
    // ──────────────────────────────────────────────────────────

    @POST
    @Path("/{identityId}/reveal")
    @Operation(
        summary = "Revelar campo sensible en claro [OPERACIÓN PRIVILEGIADA]",
        description = "Descifra nationalId o email para el identityId dado."
    )
    public Response revealField(
        @PathParam("identityId") String identityId,
        RevealReq request
    ) {
        StoredIdentity stored = identityStore.get(identityId);
        if (stored == null) {
            return Response.status(404)
                .entity(new ErrorResp("NOT_FOUND", "Identidad no encontrada: " + identityId))
                .build();
        }

        StoredEnvelope envelope = switch (request.field()) {
            case "nationalId" -> stored.nationalIdEnvelope();
            case "email"      -> stored.emailEnvelope();
            default -> throw new IllegalArgumentException("field debe ser: nationalId o email");
        };

        String dataType = request.field().equals("email") ? "EMAIL" : "NATIONAL_ID";

        var decryptReq = new CryptoClientForIdentity.DecryptReq(
            envelope.encryptedCek(), envelope.ciphertext(),
            envelope.iv(), envelope.authTag(), envelope.keyId(), dataType);
        var decrypted = cryptoClient.decrypt(decryptReq);

        LOG.warnf("AUDIT-REVEAL | identityId=%s | field=%s | masked=%s",
            identityId, request.field(), decrypted.maskedPreview());

        return Response.ok(new RevealResp(
            identityId, request.field(),
            decrypted.plaintext(), decrypted.maskedPreview(),
            decrypted.integrityVerified(),
            "⚠️ EDUCATIVO: En producción este dato no viajaría por HTTP sin cifrado adicional."
        )).build();
    }

    // ══════════════════════════════════════════════════════════
    //  HASH SHA-256 PARA BÚSQUEDAS
    // ══════════════════════════════════════════════════════════

    private String sha256(String input) {
        try {
            var digest = java.security.MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes("UTF-8"));
            var sb = new StringBuilder();
            for (byte b : hash) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            throw new RuntimeException("Error calculando SHA-256", e);
        }
    }

    // ══════════════════════════════════════════════════════════
    //  CLIENT REST HACIA CRYPTO SERVICE
    // ══════════════════════════════════════════════════════════

    @RegisterRestClient(configKey = "crypto-service")
    @Path("/api/v1/crypto")
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    interface CryptoClientForIdentity {
        @POST @Path("/encrypt")  EncryptResp encrypt(EncryptReq req);
        @POST @Path("/decrypt")  DecryptResp decrypt(DecryptReq req);
        @POST @Path("/obfuscate") ObfuscateResp obfuscate(ObfuscateReq req);

        record EncryptReq(
            @JsonProperty("plaintext")   String plaintext,
            @JsonProperty("dataType")    String dataType,
            @JsonProperty("contextInfo") String contextInfo) {}
        record EncryptResp(
            @JsonProperty("encryptedCek")  String encryptedCek,
            @JsonProperty("ciphertext")    String ciphertext,
            @JsonProperty("iv")            String iv,
            @JsonProperty("authTag")       String authTag,
            @JsonProperty("keyId")         String keyId,
            @JsonProperty("maskedPreview") String maskedPreview) {}
        record DecryptReq(
            @JsonProperty("encryptedCek") String encryptedCek,
            @JsonProperty("ciphertext")   String ciphertext,
            @JsonProperty("iv")           String iv,
            @JsonProperty("authTag")      String authTag,
            @JsonProperty("keyId")        String keyId,
            @JsonProperty("dataType")     String dataType) {}
        record DecryptResp(
            @JsonProperty("plaintext")         String plaintext,
            @JsonProperty("maskedPreview")     String maskedPreview,
            @JsonProperty("integrityVerified") boolean integrityVerified) {}
        record ObfuscateReq(
            @JsonProperty("value")    String value,
            @JsonProperty("dataType") String dataType) {}
        record ObfuscateResp(@JsonProperty("masked") String masked) {}
    }

    // ══════════════════════════════════════════════════════════
    //  RECORDS DE SOLICITUD / RESPUESTA
    // ══════════════════════════════════════════════════════════

    record RegisterIdentityRequest(
        @NotBlank @JsonProperty("fullName")   String fullName,
        @NotBlank @JsonProperty("nationalId") String nationalId,
        @NotBlank @Email @JsonProperty("email") String email
    ) {}

    record RegisterResponse(
        @JsonProperty("identityId")    String identityId,
        @JsonProperty("fullName")      String fullName,
        @JsonProperty("maskedNationalId") String maskedNationalId,
        @JsonProperty("maskedEmail")   String maskedEmail,
        @JsonProperty("status")        String status,
        @JsonProperty("searchHint")    String searchHint,
        @JsonProperty("message")       String message
    ) {}

    record IdentitySummary(
        @JsonProperty("identityId")    String identityId,
        @JsonProperty("fullName")      String fullName,
        @JsonProperty("maskedNationalId") String maskedNationalId,
        @JsonProperty("maskedEmail")   String maskedEmail,
        @JsonProperty("status")        String status
    ) {}

    record IdentityDetails(
        @JsonProperty("identityId")       String identityId,
        @JsonProperty("fullName")         String fullName,
        @JsonProperty("maskedNationalId") String maskedNationalId,
        @JsonProperty("maskedEmail")      String maskedEmail,
        @JsonProperty("emailSearchHashPrefix") String emailSearchHashPrefix,
        @JsonProperty("status")           String status
    ) {}

    record RevealReq(
        @NotBlank @JsonProperty("field") String field
    ) {}

    record RevealResp(
        @JsonProperty("identityId")       String identityId,
        @JsonProperty("field")            String field,
        @JsonProperty("plaintext")        String plaintext,
        @JsonProperty("maskedPreview")    String maskedPreview,
        @JsonProperty("integrityOk")      boolean integrityOk,
        @JsonProperty("warning")          String warning
    ) {}

    record StoredIdentity(
        String identityId, String fullName,
        String maskedNationalId, String maskedEmail,
        String emailSearchHash,
        StoredEnvelope nationalIdEnvelope,
        StoredEnvelope emailEnvelope,
        String status
    ) {}

    record StoredEnvelope(
        String encryptedCek, String ciphertext,
        String iv, String authTag, String keyId
    ) {}

    record ErrorResp(
        @JsonProperty("code")    String code,
        @JsonProperty("message") String message
    ) {}
}
