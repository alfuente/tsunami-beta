package com.example.report.resource;

import com.example.report.dto.ClientSummary;
import com.example.report.entity.Client;
import com.example.report.entity.ReportPurchase;
import jakarta.transaction.Transactional;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;
import java.util.logging.Logger;

@Path("/api/v1/clients")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class ClientResource {
    
    private static final Logger LOGGER = Logger.getLogger(ClientResource.class.getName());
    
    @GET
    @Path("/{clientId}")
    public Response getClient(@PathParam("clientId") String clientId) {
        Client client = Client.findByClientId(clientId);
        if (client == null) {
            return Response.status(Response.Status.NOT_FOUND)
                    .entity(new ErrorResponse("Not found", "Client not found: " + clientId))
                    .build();
        }
        
        ClientSummary summary = ClientSummary.fromEntity(client);
        return Response.ok(summary).build();
    }
    
    @POST
    @Transactional
    public Response createClient(CreateClientRequest request) {
        try {
            // Check if client already exists
            if (Client.findByEmail(request.email) != null) {
                return Response.status(Response.Status.CONFLICT)
                        .entity(new ErrorResponse("Conflict", "Client with email already exists"))
                        .build();
            }
            
            Client client = new Client();
            client.clientId = UUID.randomUUID().toString();
            client.name = request.name;
            client.email = request.email;
            client.organization = request.organization;
            client.contactPhone = request.contactPhone;
            client.status = Client.ClientStatus.ACTIVE;
            
            client.persist();
            
            LOGGER.info("Created new client: " + client.clientId + " (" + client.email + ")");
            
            ClientSummary summary = ClientSummary.fromEntity(client);
            return Response.status(Response.Status.CREATED).entity(summary).build();
            
        } catch (Exception e) {
            LOGGER.severe("Failed to create client: " + e.getMessage());
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(new ErrorResponse("Internal error", "Failed to create client"))
                    .build();
        }
    }
    
    @POST
    @Path("/{clientId}/purchases")
    @Transactional
    public Response addReportPurchase(@PathParam("clientId") String clientId, PurchaseRequest request) {
        try {
            Client client = Client.findByClientId(clientId);
            if (client == null) {
                return Response.status(Response.Status.NOT_FOUND)
                        .entity(new ErrorResponse("Not found", "Client not found: " + clientId))
                        .build();
            }
            
            ReportPurchase purchase = new ReportPurchase();
            purchase.client = client;
            purchase.reportType = request.reportType;
            purchase.quantity = request.quantity;
            purchase.unitPrice = request.unitPrice;
            purchase.totalAmount = request.unitPrice.multiply(BigDecimal.valueOf(request.quantity));
            purchase.paymentReference = request.paymentReference;
            purchase.paymentStatus = ReportPurchase.PaymentStatus.COMPLETED; // Assume payment is completed
            purchase.expirationDate = request.expirationDate;
            purchase.notes = request.notes;
            
            purchase.persist();
            
            LOGGER.info("Added purchase for client " + clientId + ": " + 
                       request.quantity + " " + request.reportType + " reports");
            
            return Response.status(Response.Status.CREATED).entity(purchase).build();
            
        } catch (Exception e) {
            LOGGER.severe("Failed to add purchase: " + e.getMessage());
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(new ErrorResponse("Internal error", "Failed to add purchase"))
                    .build();
        }
    }
    
    @GET
    @Path("/{clientId}/purchases")
    public Response getClientPurchases(@PathParam("clientId") String clientId) {
        Client client = Client.findByClientId(clientId);
        if (client == null) {
            return Response.status(Response.Status.NOT_FOUND)
                    .entity(new ErrorResponse("Not found", "Client not found: " + clientId))
                    .build();
        }
        
        List<ReportPurchase> purchases = ReportPurchase.find("client.clientId = ?1 order by purchaseDate desc", clientId).list();
        return Response.ok(purchases).build();
    }
    
    @GET
    public Response getAllClients(@QueryParam("page") @DefaultValue("0") int page,
                                  @QueryParam("size") @DefaultValue("20") int size) {
        List<Client> clients = Client.find("order by createdAt desc").page(page, size).list();
        List<ClientSummary> summaries = clients.stream()
                .map(ClientSummary::fromEntity)
                .toList();
        return Response.ok(summaries).build();
    }
    
    // Request DTOs
    public static class CreateClientRequest {
        public String name;
        public String email;
        public String organization;
        public String contactPhone;
    }
    
    public static class PurchaseRequest {
        public ReportPurchase.ReportType reportType;
        public Integer quantity;
        public BigDecimal unitPrice;
        public String paymentReference;
        public LocalDateTime expirationDate;
        public String notes;
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