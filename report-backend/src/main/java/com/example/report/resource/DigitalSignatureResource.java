package com.example.report.resource;

import com.example.report.entity.ReportPurchase.ReportType;
import com.example.report.service.DomainDataService;
import com.example.report.service.DigitalSignatureService;
import com.example.report.service.PdfGenerationService;

import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.media.Content;
import org.eclipse.microprofile.openapi.annotations.media.Schema;
import org.eclipse.microprofile.openapi.annotations.parameters.Parameter;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponse;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponses;
import org.eclipse.microprofile.openapi.annotations.tags.Tag;

import java.util.Map;
import java.util.HashMap;
import java.util.logging.Logger;

@Path("/api/v1/signature")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
@Tag(name = "Digital Signature", description = "Servicios de firma digital para reportes PDF")
public class DigitalSignatureResource {
    
    private static final Logger LOGGER = Logger.getLogger(DigitalSignatureResource.class.getName());
    
    @Inject
    PdfGenerationService pdfGenerationService;
    
    @Inject
    DomainDataService domainDataService;
    
    @Inject
    DigitalSignatureService digitalSignatureService;
    
    @POST
    @Path("/sign-report")
    @Operation(
        summary = "Generar reporte PDF con firma digital",
        description = "Genera un reporte de seguridad y lo firma digitalmente usando DSS"
    )
    @APIResponses({
        @APIResponse(
            responseCode = "200",
            description = "Reporte firmado digitalmente generado exitosamente",
            content = @Content(mediaType = MediaType.APPLICATION_OCTET_STREAM)
        ),
        @APIResponse(responseCode = "400", description = "Parámetros inválidos"),
        @APIResponse(responseCode = "500", description = "Error interno del servidor")
    })
    @Produces(MediaType.APPLICATION_OCTET_STREAM)
    public Response generateSignedReport(
            @Parameter(description = "Dominio para análisis", required = true)
            @QueryParam("domain") String domain,
            @Parameter(description = "Tipo de reporte", required = false)
            @QueryParam("reportType") @DefaultValue("BASIC") String reportTypeStr) {
        
        try {
            if (domain == null || domain.trim().isEmpty()) {
                return Response.status(Response.Status.BAD_REQUEST)
                    .entity("Domain parameter is required")
                    .build();
            }
            
            LOGGER.info("Generating signed report for domain: " + domain);
            
            // Parse report type
            ReportType reportType;
            try {
                reportType = ReportType.valueOf(reportTypeStr.toUpperCase());
            } catch (IllegalArgumentException e) {
                reportType = ReportType.BASIC;
            }
            
            // Get domain data
            DomainDataService.DomainRiskData domainData = domainDataService.getDomainRiskData(domain);
            
            // Generate signed PDF report
            byte[] signedPdfBytes = pdfGenerationService.generateSignedPdfReport(domainData, reportType);
            
            // Return the signed PDF
            String filename = "signed-report-" + domain + "-" + System.currentTimeMillis() + ".pdf";
            
            return Response.ok(signedPdfBytes, MediaType.APPLICATION_OCTET_STREAM)
                    .header("Content-Disposition", "attachment; filename=\"" + filename + "\"")
                    .header("Content-Length", signedPdfBytes.length)
                    .build();
                    
        } catch (Exception e) {
            LOGGER.severe("Failed to generate signed report: " + e.getMessage());
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity("Failed to generate signed report: " + e.getMessage())
                    .build();
        }
    }
    
    @POST
    @Path("/validate")
    @Operation(
        summary = "Validar firma digital de un PDF",
        description = "Valida la integridad y autenticidad de la firma digital de un reporte PDF"
    )
    @APIResponses({
        @APIResponse(
            responseCode = "200",
            description = "Resultado de validación de firma",
            content = @Content(schema = @Schema(implementation = Map.class))
        ),
        @APIResponse(responseCode = "400", description = "Archivo PDF inválido"),
        @APIResponse(responseCode = "500", description = "Error interno del servidor")
    })
    @Consumes(MediaType.APPLICATION_OCTET_STREAM)
    public Response validateSignature(byte[] pdfContent) {
        try {
            if (pdfContent == null || pdfContent.length == 0) {
                return Response.status(Response.Status.BAD_REQUEST)
                    .entity(createErrorResponse("PDF content is required"))
                    .build();
            }
            
            LOGGER.info("Validating PDF signature for " + pdfContent.length + " bytes");
            
            // Validate signature
            boolean isValid = digitalSignatureService.validateSignature(pdfContent);
            
            Map<String, Object> result = new HashMap<>();
            result.put("valid", isValid);
            result.put("message", isValid ? "Signature is valid" : "Signature is invalid or missing");
            result.put("timestamp", System.currentTimeMillis());
            result.put("fileSize", pdfContent.length);
            
            return Response.ok(result).build();
            
        } catch (Exception e) {
            LOGGER.severe("Failed to validate signature: " + e.getMessage());
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(createErrorResponse("Failed to validate signature: " + e.getMessage()))
                    .build();
        }
    }
    
    @GET
    @Path("/info")
    @Operation(
        summary = "Información del servicio de firma digital",
        description = "Obtiene información sobre el servicio de firma digital configurado"
    )
    @APIResponses({
        @APIResponse(
            responseCode = "200",
            description = "Información del servicio",
            content = @Content(schema = @Schema(implementation = Map.class))
        )
    })
    public Response getSignatureServiceInfo() {
        Map<String, Object> info = new HashMap<>();
        info.put("service", "Tsunami Digital Signature Service");
        info.put("version", "1.0.0");
        info.put("provider", "DSS (Digital Signature Services) by European Commission");
        info.put("dssVersion", "6.0");
        info.put("supportedFormats", new String[]{"PDF (PAdES)"});
        info.put("signatureLevel", "PAdES-BASELINE-T");
        info.put("digestAlgorithm", "SHA256");
        info.put("signatureAlgorithm", "RSA");
        info.put("timestampEnabled", true);
        info.put("mode", "development");
        info.put("certificateType", "self-signed");
        
        return Response.ok(info).build();
    }
    
    private Map<String, Object> createErrorResponse(String message) {
        Map<String, Object> error = new HashMap<>();
        error.put("error", true);
        error.put("message", message);
        error.put("timestamp", System.currentTimeMillis());
        return error;
    }
}