package com.example.risk.resource;

import com.example.risk.dto.CalculationResponse;
import com.example.risk.service.RiskCalculator;
import com.example.risk.service.RiskPropagationService;

import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.parameters.Parameter;
import org.eclipse.microprofile.openapi.annotations.tags.Tag;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

@Path("/api/v1/calculations")
@Tag(name = "Risk Calculations", description = "APIs for triggering risk calculations")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class RiskCalculationResource {

    @Inject
    RiskCalculator riskCalculator;

    @Inject
    RiskPropagationService riskPropagationService;

    @POST
    @Path("/domain/{fqdn}")
    @Operation(summary = "Calculate risk for a domain", 
               description = "Triggers risk calculation for a specific domain")
    public Response calculateDomainRisk(
            @Parameter(description = "Fully qualified domain name")
            @PathParam("fqdn") String fqdn,
            @Parameter(description = "Propagate calculation to dependent nodes")
            @QueryParam("propagate") @DefaultValue("false") boolean propagate) {
        
        try {
            String calculationId = UUID.randomUUID().toString();
            
            if (propagate) {
                // Asynchronous calculation with propagation
                CompletableFuture<Integer> future = riskPropagationService.propagateRiskAsync(fqdn, "domain");
                
                future.thenAccept(nodesProcessed -> {
                    // Log completion or store in database for status tracking
                    System.out.println("Risk calculation completed for " + fqdn + ". Nodes processed: " + nodesProcessed);
                }).exceptionally(throwable -> {
                    // Log error
                    System.err.println("Risk calculation failed for " + fqdn + ": " + throwable.getMessage());
                    return null;
                });
                
                return Response.accepted(CalculationResponse.success(calculationId, "domain_with_propagation", fqdn, null))
                        .build();
            } else {
                // Synchronous calculation for single domain
                double riskScore = riskCalculator.calculateCompleteRiskScore(fqdn, "domain");
                
                return Response.ok(CalculationResponse.success(calculationId, "domain", fqdn, 1))
                        .header("X-Risk-Score", riskScore)
                        .build();
            }
        } catch (Exception e) {
            String calculationId = UUID.randomUUID().toString();
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(CalculationResponse.error(calculationId, "domain", fqdn, e.getMessage()))
                    .build();
        }
    }

    @POST
    @Path("/domain-tree/{rootFqdn}")
    @Operation(summary = "Calculate risk for domain tree", 
               description = "Triggers risk calculation for a domain and all its subdomains")
    public Response calculateDomainTreeRisk(
            @Parameter(description = "Root domain FQDN")
            @PathParam("rootFqdn") String rootFqdn) {
        
        try {
            String calculationId = UUID.randomUUID().toString();
            
            // This runs synchronously but could be made async for large trees
            int nodesProcessed = riskCalculator.recalcForDomainTree(rootFqdn);
            
            return Response.ok(CalculationResponse.success(calculationId, "domain_tree", rootFqdn, nodesProcessed))
                    .build();
                    
        } catch (Exception e) {
            String calculationId = UUID.randomUUID().toString();
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(CalculationResponse.error(calculationId, "domain_tree", rootFqdn, e.getMessage()))
                    .build();
        }
    }

    @POST
    @Path("/provider/{providerId}")
    @Operation(summary = "Calculate risk for a provider", 
               description = "Triggers risk calculation for a specific provider")
    public Response calculateProviderRisk(
            @Parameter(description = "Provider identifier")
            @PathParam("providerId") String providerId,
            @Parameter(description = "Propagate calculation to dependent nodes")
            @QueryParam("propagate") @DefaultValue("false") boolean propagate) {
        
        try {
            String calculationId = UUID.randomUUID().toString();
            
            if (propagate) {
                CompletableFuture<Integer> future = riskPropagationService.propagateRiskAsync(providerId, "provider");
                
                future.thenAccept(nodesProcessed -> {
                    System.out.println("Risk calculation completed for provider " + providerId + ". Nodes processed: " + nodesProcessed);
                }).exceptionally(throwable -> {
                    System.err.println("Risk calculation failed for provider " + providerId + ": " + throwable.getMessage());
                    return null;
                });
                
                return Response.accepted(CalculationResponse.success(calculationId, "provider_with_propagation", providerId, null))
                        .build();
            } else {
                int nodesProcessed = riskCalculator.recalcForProvider(providerId);
                
                return Response.ok(CalculationResponse.success(calculationId, "provider", providerId, nodesProcessed))
                        .build();
            }
        } catch (Exception e) {
            String calculationId = UUID.randomUUID().toString();
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(CalculationResponse.error(calculationId, "provider", providerId, e.getMessage()))
                    .build();
        }
    }

    @POST
    @Path("/service/{serviceId}")
    @Operation(summary = "Calculate risk for a service", 
               description = "Triggers risk calculation for a specific service")
    public Response calculateServiceRisk(
            @Parameter(description = "Service identifier")
            @PathParam("serviceId") String serviceId,
            @Parameter(description = "Propagate calculation to dependent nodes")
            @QueryParam("propagate") @DefaultValue("false") boolean propagate) {
        
        try {
            String calculationId = UUID.randomUUID().toString();
            
            if (propagate) {
                CompletableFuture<Integer> future = riskPropagationService.propagateRiskAsync(serviceId, "service");
                
                future.thenAccept(nodesProcessed -> {
                    System.out.println("Risk calculation completed for service " + serviceId + ". Nodes processed: " + nodesProcessed);
                }).exceptionally(throwable -> {
                    System.err.println("Risk calculation failed for service " + serviceId + ": " + throwable.getMessage());
                    return null;
                });
                
                return Response.accepted(CalculationResponse.success(calculationId, "service_with_propagation", serviceId, null))
                        .build();
            } else {
                int nodesProcessed = riskCalculator.recalcForService(serviceId);
                
                return Response.ok(CalculationResponse.success(calculationId, "service", serviceId, nodesProcessed))
                        .build();
            }
        } catch (Exception e) {
            String calculationId = UUID.randomUUID().toString();
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(CalculationResponse.error(calculationId, "service", serviceId, e.getMessage()))
                    .build();
        }
    }

    @POST
    @Path("/organization/{organizationId}")
    @Operation(summary = "Calculate risk for an organization", 
               description = "Triggers risk calculation for a specific organization")
    public Response calculateOrganizationRisk(
            @Parameter(description = "Organization identifier")
            @PathParam("organizationId") String organizationId) {
        
        try {
            String calculationId = UUID.randomUUID().toString();
            
            int nodesProcessed = riskCalculator.recalcForOrganization(organizationId);
            
            return Response.ok(CalculationResponse.success(calculationId, "organization", organizationId, nodesProcessed))
                    .build();
                    
        } catch (Exception e) {
            String calculationId = UUID.randomUUID().toString();
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(CalculationResponse.error(calculationId, "organization", organizationId, e.getMessage()))
                    .build();
        }
    }

    @POST
    @Path("/incident/{incidentId}")
    @Operation(summary = "Propagate risk for incident", 
               description = "Triggers risk propagation for nodes affected by an incident")
    public Response propagateRiskForIncident(
            @Parameter(description = "Incident identifier")
            @PathParam("incidentId") String incidentId) {
        
        try {
            String calculationId = UUID.randomUUID().toString();
            
            int nodesProcessed = riskPropagationService.propagateRiskForIncident(incidentId);
            
            return Response.ok(CalculationResponse.success(calculationId, "incident_propagation", incidentId, nodesProcessed))
                    .build();
                    
        } catch (Exception e) {
            String calculationId = UUID.randomUUID().toString();
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(CalculationResponse.error(calculationId, "incident_propagation", incidentId, e.getMessage()))
                    .build();
        }
    }

    @POST
    @Path("/bulk")
    @Operation(summary = "Bulk risk recalculation", 
               description = "Triggers bulk risk recalculation for all outdated nodes")
    public Response bulkRiskRecalculation() {
        
        try {
            String calculationId = UUID.randomUUID().toString();
            
            // This could take a while, so we run it asynchronously
            CompletableFuture.supplyAsync(() -> {
                return riskPropagationService.bulkRiskRecalculation();
            }).thenAccept(nodesProcessed -> {
                System.out.println("Bulk risk calculation completed. Nodes processed: " + nodesProcessed);
            }).exceptionally(throwable -> {
                System.err.println("Bulk risk calculation failed: " + throwable.getMessage());
                return null;
            });
            
            return Response.accepted(CalculationResponse.success(calculationId, "bulk_recalculation", "all", null))
                    .build();
                    
        } catch (Exception e) {
            String calculationId = UUID.randomUUID().toString();
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(CalculationResponse.error(calculationId, "bulk_recalculation", "all", e.getMessage()))
                    .build();
        }
    }

    @GET
    @Path("/status/{calculationId}")
    @Operation(summary = "Get calculation status", 
               description = "Retrieves the status of a risk calculation (placeholder - would need proper status tracking)")
    public Response getCalculationStatus(
            @Parameter(description = "Calculation identifier")
            @PathParam("calculationId") String calculationId) {
        
        // This is a placeholder - in a real implementation you would store calculation status in database
        return Response.ok(Map.of(
            "calculation_id", calculationId,
            "status", "COMPLETED",
            "message", "Status tracking not implemented - this is a placeholder endpoint"
        )).build();
    }

    @POST
    @Path("/validate")
    @Operation(summary = "Validate risk calculations", 
               description = "Runs validation checks on risk calculations and returns results")
    public Response validateRiskCalculations() {
        
        try {
            // This would use the RiskValidationService
            return Response.ok(Map.of(
                "validation_status", "COMPLETED",
                "message", "Risk validation not implemented in this endpoint - use the existing ProvisionResource for validation"
            )).build();
            
        } catch (Exception e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(Map.of("error", "Failed to run validation", "message", e.getMessage()))
                    .build();
        }
    }
}