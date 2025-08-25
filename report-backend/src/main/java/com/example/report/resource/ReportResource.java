package com.example.report.resource;

import com.example.report.dto.ReportRequest;
import com.example.report.dto.ReportResponse;
import com.example.report.service.ReportService;
import com.example.report.service.DomainDataService;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.media.Content;
import org.eclipse.microprofile.openapi.annotations.media.Schema;
import org.eclipse.microprofile.openapi.annotations.parameters.Parameter;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponse;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponses;
import org.eclipse.microprofile.openapi.annotations.tags.Tag;
import jakarta.inject.Inject;
import jakarta.validation.Valid;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.List;
import java.util.logging.Logger;

@Path("/api/v1/reports")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
@Tag(name = "Reports", description = "Generación y gestión de reportes de seguridad")
public class ReportResource {
    
    private static final Logger LOGGER = Logger.getLogger(ReportResource.class.getName());
    
    @Inject
    ReportService reportService;
    
    @Inject
    DomainDataService domainDataService;
    
    @POST
    public Response generateReport(@Valid ReportRequest request) {
        try {
            LOGGER.info("Generating report for domain: " + request.domain + 
                       " client: " + request.clientId + 
                       " type: " + request.reportType);
            
            ReportResponse response = reportService.generateReport(request);
            return Response.status(Response.Status.CREATED).entity(response).build();
            
        } catch (IllegalArgumentException e) {
            LOGGER.warning("Invalid request: " + e.getMessage());
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(new ErrorResponse("Invalid request", e.getMessage()))
                    .build();
        } catch (IllegalStateException e) {
            LOGGER.warning("Business rule violation: " + e.getMessage());
            return Response.status(Response.Status.CONFLICT)
                    .entity(new ErrorResponse("Business rule violation", e.getMessage()))
                    .build();
        } catch (Exception e) {
            LOGGER.severe("Failed to generate report: " + e.getMessage());
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(new ErrorResponse("Internal error", "Failed to generate report"))
                    .build();
        }
    }
    
    @GET
    @Path("/{reportId}")
    public Response getReportStatus(@PathParam("reportId") String reportId) {
        try {
            ReportResponse response = reportService.getReportStatus(reportId);
            return Response.ok(response).build();
            
        } catch (IllegalArgumentException e) {
            return Response.status(Response.Status.NOT_FOUND)
                    .entity(new ErrorResponse("Not found", e.getMessage()))
                    .build();
        } catch (Exception e) {
            LOGGER.severe("Failed to get report status: " + e.getMessage());
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(new ErrorResponse("Internal error", "Failed to get report status"))
                    .build();
        }
    }
    
    @GET
    @Path("/{reportId}/download")
    @Produces("application/pdf")
    public Response downloadReport(
            @PathParam("reportId") String reportId,
            @HeaderParam("X-Client-ID") String clientId) {
        
        if (clientId == null || clientId.trim().isEmpty()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(new ErrorResponse("Missing header", "X-Client-ID header is required"))
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }
        
        try {
            byte[] pdfData = reportService.downloadReport(reportId, clientId);
            
            return Response.ok(pdfData)
                    .header("Content-Disposition", "attachment; filename=report_" + reportId + ".pdf")
                    .header("Content-Type", "application/pdf")
                    .build();
                    
        } catch (IllegalArgumentException e) {
            return Response.status(Response.Status.NOT_FOUND)
                    .entity(new ErrorResponse("Not found", e.getMessage()))
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        } catch (IllegalStateException e) {
            return Response.status(Response.Status.CONFLICT)
                    .entity(new ErrorResponse("Not available", e.getMessage()))
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        } catch (Exception e) {
            LOGGER.severe("Failed to download report: " + e.getMessage());
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(new ErrorResponse("Internal error", "Failed to download report"))
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }
    }
    
    @GET
    @Path("/client/{clientId}")
    public Response getClientReports(
            @PathParam("clientId") String clientId,
            @QueryParam("page") @DefaultValue("0") int page,
            @QueryParam("size") @DefaultValue("20") int size) {
        
        try {
            List<ReportResponse> reports = reportService.getClientReports(clientId, page, size);
            return Response.ok(reports).build();
            
        } catch (IllegalArgumentException e) {
            return Response.status(Response.Status.NOT_FOUND)
                    .entity(new ErrorResponse("Not found", e.getMessage()))
                    .build();
        } catch (Exception e) {
            LOGGER.severe("Failed to get client reports: " + e.getMessage());
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(new ErrorResponse("Internal error", "Failed to get client reports"))
                    .build();
        }
    }
    
    @GET
    @Path("/graph/analysis")
    public Response getGraphAnalysis() {
        try {
            LOGGER.info("Generating graph analysis report");
            
            DomainDataService.GraphAnalysisData analysis = domainDataService.getGraphAnalysisData();
            return Response.ok(analysis).build();
            
        } catch (Exception e) {
            LOGGER.severe("Failed to generate graph analysis: " + e.getMessage());
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(new ErrorResponse("Internal error", "Failed to generate graph analysis"))
                    .build();
        }
    }
    
    @GET
    @Path("/domain/{domain}/analysis")
    @Operation(
        summary = "Análisis de dominio específico",
        description = "Obtiene análisis detallado de riesgos y tecnologías para un dominio específico"
    )
    @APIResponses({
        @APIResponse(
            responseCode = "200",
            description = "Análisis obtenido exitosamente",
            content = @Content(
                mediaType = MediaType.APPLICATION_JSON,
                schema = @Schema(implementation = Object.class)
            )
        ),
        @APIResponse(
            responseCode = "500",
            description = "Error interno del servidor",
            content = @Content(mediaType = MediaType.APPLICATION_JSON)
        )
    })
    public Response getDomainAnalysis(
        @Parameter(description = "Nombre del dominio a analizar", required = true)
        @PathParam("domain") String domain) {
        try {
            LOGGER.info("Generating domain analysis for: " + domain);
            
            DomainDataService.DomainRiskData analysis = domainDataService.getDomainRiskData(domain);
            return Response.ok(analysis).build();
            
        } catch (Exception e) {
            LOGGER.severe("Failed to generate domain analysis: " + e.getMessage());
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(new ErrorResponse("Internal error", "Failed to generate domain analysis"))
                    .build();
        }
    }
    
    // Error response class
    public static class ErrorResponse {
        public String error;
        public String message;
        
        public ErrorResponse(String error, String message) {
            this.error = error;
            this.message = message;
        }
    }
}