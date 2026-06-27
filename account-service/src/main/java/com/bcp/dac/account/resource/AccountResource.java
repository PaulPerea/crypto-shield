package com.bcp.dac.account.resource;

import com.bcp.dac.account.model.AccountModels.*;
import com.bcp.dac.account.service.AccountService;
import jakarta.inject.Inject;
import jakarta.validation.Valid;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.tags.Tag;
import org.jboss.logging.Logger;

import java.time.Instant;

/**
 * ══════════════════════════════════════════════════════════════
 *  ACCOUNT RESOURCE – Endpoints REST del Account Service
 * ══════════════════════════════════════════════════════════════
 *
 * RUTAS:
 *  POST /api/v1/accounts           → Crear cuenta (datos sensibles se cifran internamente)
 *  GET  /api/v1/accounts           → Listar todas las cuentas (datos enmascarados)
 *  GET  /api/v1/accounts/{id}      → Consultar cuenta por ID (datos enmascarados)
 *  POST /api/v1/accounts/{id}/reveal → Revelar dato en claro (operación privilegiada)
 */
@Path("/api/v1/accounts")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
@Tag(name = "Account Service", description = "Gestión de cuentas con datos sensibles cifrados")
public class AccountResource {

    private static final Logger LOG = Logger.getLogger(AccountResource.class);

    @Inject
    AccountService accountService;

    // ──────────────────────────────────────────────
    //  POST /accounts – Crear cuenta
    // ──────────────────────────────────────────────

    @POST
    @Operation(
        summary = "Crear cuenta bancaria",
        description = """
            Registra una nueva cuenta. Internamente:
            1. Cifra el número de cuenta con AES-256-GCM + RSA-2048-OAEP
            2. Cifra el número de tarjeta con AES-256-GCM + RSA-2048-OAEP
            3. Almacena SOLO los envelopes cifrados (nunca el dato en claro)
            4. Devuelve versiones enmascaradas para confirmación
            """
    )
    public Response createAccount(@Valid CreateAccountRequest request) {
        try {
            LOG.infof("Nueva solicitud de creación de cuenta | holder=%s", request.holderName());
            CreateAccountResponse response = accountService.createAccount(request);
            return Response.status(Response.Status.CREATED).entity(response).build();
        } catch (Exception e) {
            LOG.errorf("Error al crear cuenta: %s", e.getMessage());
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                .entity(new ErrorResponse("ACCOUNT_001", "Error al crear la cuenta", Instant.now().toString()))
                .build();
        }
    }

    // ──────────────────────────────────────────────
    //  GET /accounts – Listar cuentas
    // ──────────────────────────────────────────────

    @GET
    @Operation(
        summary = "Listar todas las cuentas",
        description = "Devuelve un listado con datos enmascarados. Nunca devuelve datos en claro."
    )
    public Response listAccounts() {
        var accounts = accountService.listAccounts();
        LOG.infof("Listando cuentas | total=%d", accounts.size());
        return Response.ok(accounts).build();
    }

    // ──────────────────────────────────────────────
    //  GET /accounts/{id} – Consultar cuenta
    // ──────────────────────────────────────────────

    @GET
    @Path("/{accountId}")
    @Operation(
        summary = "Consultar cuenta por ID",
        description = """
            Devuelve los detalles de una cuenta con:
            - Datos enmascarados (maskedAccountNumber, maskedCardNumber)
            - Los envelopes cifrados completos (para uso por sistemas autorizados)
            
            Los datos en claro NO se devuelven en este endpoint.
            """
    )
    public Response getAccount(@PathParam("accountId") String accountId) {
        try {
            AccountDetailsResponse response = accountService.getAccount(accountId);
            return Response.ok(response).build();
        } catch (AccountService.AccountNotFoundException e) {
            return Response.status(Response.Status.NOT_FOUND)
                .entity(new ErrorResponse("ACCOUNT_NOT_FOUND", e.getMessage(), Instant.now().toString()))
                .build();
        }
    }

    // ──────────────────────────────────────────────
    //  POST /accounts/{id}/reveal – Revelar dato en claro
    // ──────────────────────────────────────────────

    @POST
    @Path("/{accountId}/reveal")
    @Operation(
        summary = "Revelar un campo sensible en claro [OPERACIÓN PRIVILEGIADA]",
        description = """
            Descifra y devuelve un campo específico en claro.
            
            ⚠️ EDUCATIVO: En producción esta operación requeriría:
            - Autenticación con JWT + MFA
            - Rol específico (ej: ROLE_DATA_REVEAL)
            - Audit log obligatorio
            - Rate limiting estricto (máximo 3 intentos por minuto)
            - Que el dato descifrado NO viaje por HTTP (se mostraría en sesión segura)
            
            Campos disponibles: accountNumber, cardNumber
            """
    )
    public Response revealField(
        @PathParam("accountId") String accountId,
        @Valid RevealRequest request
    ) {
        try {
            // Inyectar el accountId del path en el request
            var requestWithId = new RevealRequest(accountId, request.field());
            LOG.warnf("AUDIT: Solicitud de reveal | accountId=%s | field=%s", accountId, request.field());
            RevealResponse response = accountService.revealField(requestWithId);
            return Response.ok(response).build();
        } catch (AccountService.AccountNotFoundException e) {
            return Response.status(Response.Status.NOT_FOUND)
                .entity(new ErrorResponse("ACCOUNT_NOT_FOUND", e.getMessage(), Instant.now().toString()))
                .build();
        } catch (Exception e) {
            LOG.errorf("Error al revelar campo | accountId=%s | error=%s", accountId, e.getMessage());
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                .entity(new ErrorResponse("REVEAL_ERROR", "Error al descifrar el campo", Instant.now().toString()))
                .build();
        }
    }
}
