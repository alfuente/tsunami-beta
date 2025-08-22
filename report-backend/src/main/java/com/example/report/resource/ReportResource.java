package com.example.report.resource;

import com.example.report.dto.ReportRequest;
import com.example.report.dto.ReportResponse;
import com.example.report.service.ReportService;
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
public class ReportResource {
    
    private static final Logger LOGGER = Logger.getLogger(ReportResource.class.getName());
    
    @Inject
    ReportService reportService;
    
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