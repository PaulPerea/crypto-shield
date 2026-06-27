package com.bcp.dac.crypto.resource;

import com.bcp.dac.crypto.model.CryptoModels.*;
import com.bcp.dac.crypto.service.CryptoService;
import com.bcp.dac.crypto.service.CryptoService.EnvelopeResult;
import com.bcp.dac.crypto.service.ObfuscationService;
import jakarta.inject.Inject;
import jakarta.validation.Valid;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.media.Content;
import org.eclipse.microprofile.openapi.annotations.media.Schema;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponse;
import org.eclipse.microprofile.openapi.annotations.tags.Tag;
import org.jboss.logging.Logger;

import java.time.Instant;

/**
 * ══════════════════════════════════════════════════════════════
 *  CRYPTO RESOURCE – Endpoints REST del servicio de cifrado
 * ══════════════════════════════════════════════════════════════
 *
 * RUTAS DISPONIBLES:
 *
 *  POST /api/v1/crypto/encrypt    → Cifra un dato sensible
 *  POST /api/v1/crypto/decrypt    → Descifra un envelope
 *  POST /api/v1/crypto/obfuscate  → Ofusca un dato para logs/visualización
 *  GET  /api/v1/crypto/health     → Estado del servicio
 *
 * BUENAS PRÁCTICAS APLICADAS:
 *  ✔ Versión de API en la URL (/v1/)
 *  ✔ Siempre JSON (consume y produce)
 *  ✔ Validación con @Valid antes de procesar
 *  ✔ Errores estandarizados con ErrorResponse
 *  ✔ Logs sin datos sensibles (se usan masked previews)
 *  ✔ OpenAPI/Swagger con @Operation para documentación automática
 */
@Path("/api/v1/crypto")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
@Tag(name = "Crypto Service", description = "Operaciones de cifrado, descifrado y ofuscación de datos sensibles")
public class CryptoResource {

    private static final Logger LOG = Logger.getLogger(CryptoResource.class);

    @Inject
    CryptoService cryptoService;

    @Inject
    ObfuscationService obfuscationService;

    // ══════════════════════════════════════════════════════════════
    //  POST /encrypt – Cifrar dato sensible
    // ══════════════════════════════════════════════════════════════

    @POST
    @Path("/encrypt")
    @Operation(
        summary = "Cifra un dato sensible",
        description = """
            Aplica Envelope Encryption:
            1. Genera CEK AES-256 efímera
            2. Cifra el dato con AES-256-GCM
            3. Cifra la CEK con RSA-2048-OAEP (K-pub)
            4. Devuelve el envelope con todos los componentes
            
            El dato original NUNCA se loguea. Solo se muestra una versión enmascarada.
            """
    )
    @APIResponse(responseCode = "200", description = "Dato cifrado exitosamente")
    @APIResponse(responseCode = "400", description = "Request inválido")
    @APIResponse(responseCode = "500", description = "Error interno de cifrado")
    public Response encrypt(@Valid EncryptRequest request) {

        // BUENA PRÁCTICA: Nunca loguear el dato en claro.
        // Usamos maskedPreview para identificar la operación en logs.
        String masked = obfuscationService.forLog(request.plaintext(), request.dataType());
        LOG.infof("Solicitud de cifrado | dataType=%s | masked=%s | context=%s",
            request.dataType(), masked, request.contextInfo());

        try {
            // Obtener keyId activo y cifrar
            String keyId = cryptoService.getActiveKeyIdFromService();
            EnvelopeResult envelope = cryptoService.encrypt(request.plaintext(), keyId);

            // Armar respuesta
            EncryptResponse response = new EncryptResponse(
                envelope.encryptedCek(),
                envelope.ciphertext(),
                envelope.iv(),
                envelope.authTag(),
                envelope.keyId(),
                request.dataType(),
                masked              // Vista enmascarada para referencia
            );

            LOG.infof("Cifrado exitoso | dataType=%s | keyId=%s", request.dataType(), keyId);
            return Response.ok(response).build();

        } catch (CryptoService.CryptoException e) {
            LOG.errorf("Error en cifrado | dataType=%s | error=%s", request.dataType(), e.getMessage());
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                .entity(errorResponse("CRYPTO_001", "Error al cifrar el dato"))
                .build();
        }
    }

    // ══════════════════════════════════════════════════════════════
    //  POST /decrypt – Descifrar envelope
    // ══════════════════════════════════════════════════════════════

    @POST
    @Path("/decrypt")
    @Operation(
        summary = "Descifra un envelope",
        description = """
            Proceso inverso al cifrado:
            1. Descifra la CEK con RSA-2048-OAEP (K-priv desde Vault)
            2. Descifra el ciphertext con AES-256-GCM + CEK
            3. Verifica el authTag (integridad: detecta tampering)
            
            Si el authTag no coincide, el descifrado falla con error de integridad.
            Esto indica que el ciphertext fue modificado en tránsito.
            """
    )
    @APIResponse(responseCode = "200", description = "Dato descifrado exitosamente")
    @APIResponse(responseCode = "400", description = "Request inválido o authTag incorrecto")
    @APIResponse(responseCode = "500", description = "Error interno de descifrado")
    public Response decrypt(@Valid DecryptRequest request) {

        LOG.infof("Solicitud de descifrado | keyId=%s | dataType=%s",
            request.keyId(), request.dataType());

        try {
            String plaintext = cryptoService.decrypt(
                request.encryptedCek(),
                request.ciphertext(),
                request.iv(),
                request.authTag(),
                request.keyId()
            );

            // Generar preview enmascarado del dato descifrado
            String dataType = request.dataType() != null ? request.dataType() : "UNKNOWN";
            String masked = obfuscationService.forLog(plaintext, dataType);

            DecryptResponse response = new DecryptResponse(
                plaintext,
                masked,
                dataType,
                true    // integrityVerified: si llegamos aquí, el authTag fue válido
            );

            LOG.infof("Descifrado exitoso | keyId=%s | masked=%s", request.keyId(), masked);
            return Response.ok(response).build();

        } catch (CryptoService.CryptoException e) {
            String code = e.getMessage().contains("integridad") ? "CRYPTO_INTEGRITY_FAIL" : "CRYPTO_002";
            LOG.errorf("Error en descifrado | keyId=%s | error=%s", request.keyId(), e.getMessage());
            return Response.status(Response.Status.BAD_REQUEST)
                .entity(errorResponse(code, e.getMessage()))
                .build();
        }
    }

    // ══════════════════════════════════════════════════════════════
    //  POST /obfuscate – Ofuscar dato para visualización/logs
    // ══════════════════════════════════════════════════════════════

    @POST
    @Path("/obfuscate")
    @Operation(
        summary = "Ofusca un dato para visualización segura",
        description = """
            Aplica enmascaramiento visual según el tipo de dato:
            - CARD_NUMBER   → PCI-DSS: primeros 6 + últimos 4 visibles
            - ACCOUNT_NUMBER → últimos 4 visibles
            - NATIONAL_ID   → últimos 4 visibles
            - EMAIL         → primer y último carácter de la parte local
            
            IMPORTANTE: La ofuscación NO es cifrado. El dato original
            no puede recuperarse desde el valor ofuscado.
            """
    )
    @APIResponse(responseCode = "200", description = "Dato ofuscado exitosamente")
    public Response obfuscate(@Valid ObfuscateRequest request) {

        LOG.debugf("Solicitud de ofuscación | dataType=%s", request.dataType());

        var result = obfuscationService.obfuscate(request.value(), request.dataType());

        ObfuscateResponse response = new ObfuscateResponse(
            result.masked(),
            result.dataType(),
            result.technique()
        );

        return Response.ok(response).build();
    }

    // ══════════════════════════════════════════════════════════════
    //  GET /health – Estado del servicio
    // ══════════════════════════════════════════════════════════════

    @GET
    @Path("/health")
    @Operation(summary = "Estado del Crypto Service")
    public Response health() {
        return Response.ok(java.util.Map.ofEntries(
                java.util.Map.entry("service", "crypto-service"),
                java.util.Map.entry("status", "UP"),
                java.util.Map.entry("version", "1.0.0"),
                java.util.Map.entry("keyId", cryptoService.getActiveKeyIdFromService()),
                java.util.Map.entry("timestamp", Instant.now().toString())
        )).build();
    }

    // ══════════════════════════════════════════════════════════════
    //  MANEJADOR GLOBAL DE ERRORES
    // ══════════════════════════════════════════════════════════════

    /**
     * Construye un ErrorResponse estandarizado.
     * BUENA PRÁCTICA: Nunca exponer stack traces en la respuesta HTTP.
     */
    private ErrorResponse errorResponse(String code, String message) {
        return new ErrorResponse(code, message, Instant.now().toString());
    }
}
