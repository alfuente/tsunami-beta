package com.example.risk.resource;

import com.example.risk.dto.RiskScoreResponse;
import com.example.risk.service.RiskCalculator;
import com.example.risk.service.BaseScoreCalculator;
import com.example.risk.service.ThirdPartyScoreCalculator;
import com.example.risk.service.IncidentImpactCalculator;
import com.example.risk.service.ContextBoostCalculator;
import com.example.risk.service.RiskPropagationService;
import org.neo4j.driver.Driver;
import org.neo4j.driver.Session;
import org.neo4j.driver.Result;
import org.neo4j.driver.Record;

import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.parameters.Parameter;
import org.eclipse.microprofile.openapi.annotations.tags.Tag;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.ArrayList;

@Path("/api/v1/risk")
@Tag(name = "Risk Scoring", description = "APIs for querying risk scores and related information")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class RiskScoringResource {

    @Inject
    Driver driver;

    @Inject
    RiskCalculator riskCalculator;

    @Inject
    BaseScoreCalculator baseScoreCalculator;

    @Inject
    ThirdPartyScoreCalculator thirdPartyScoreCalculator;

    @Inject
    IncidentImpactCalculator incidentImpactCalculator;

    @Inject
    ContextBoostCalculator contextBoostCalculator;

    @Inject
    RiskPropagationService riskPropagationService;

    @GET
    @Path("/score/{nodeType}/{nodeId}")
    @Operation(summary = "Get risk score for a specific node", 
               description = "Retrieves the current risk score and breakdown for a given node")
    public Response getRiskScore(
            @Parameter(description = "Type of node (domain, provider, service, organization)")
            @PathParam("nodeType") String nodeType,
            @Parameter(description = "Node identifier (FQDN for domains, ID for others)")
            @PathParam("nodeId") String nodeId,
            @Parameter(description = "Include detailed score breakdown")
            @QueryParam("includeBreakdown") @DefaultValue("false") boolean includeBreakdown) {
        
        try {
            String query = buildRiskScoreQuery(nodeType);
            
            try (Session session = driver.session()) {
                Result result = session.run(query, Map.of("nodeId", nodeId));
                
                if (!result.hasNext()) {
                    return Response.status(Response.Status.NOT_FOUND)
                            .entity(Map.of("error", "Node not found", "nodeId", nodeId, "nodeType", nodeType))
                            .build();
                }
                
                Record record = result.next();
                RiskScoreResponse response = new RiskScoreResponse(
                    nodeId,
                    nodeType,
                    record.get("risk_score").asDouble(0.0),
                    record.get("risk_tier").asString("Unknown"),
                    record.get("last_calculated").asLocalDateTime(null)
                );
                
                if (includeBreakdown) {
                    Map<String, Object> domainData = riskCalculator.fetchDomainData(nodeId);
                    
                    double baseScore = baseScoreCalculator.calculateBaseScore(domainData);
                    double thirdPartyScore = thirdPartyScoreCalculator.calculateThirdPartyScore(nodeId, nodeType);
                    double incidentImpact = incidentImpactCalculator.calculateIncidentImpact(nodeId, nodeType);
                    double contextBoost = contextBoostCalculator.calculateContextBoost(nodeId, nodeType);
                    
                    response.setScoreBreakdown(new RiskScoreResponse.ScoreBreakdown(
                        baseScore, thirdPartyScore, incidentImpact, contextBoost
                    ));
                }
                
                return Response.ok(response).build();
            }
        } catch (Exception e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(Map.of("error", "Failed to retrieve risk score", "message", e.getMessage()))
                    .build();
        }
    }

    @GET
    @Path("/high-risk")
    @Operation(summary = "Get high-risk nodes", 
               description = "Retrieves all nodes with risk score above specified threshold")
    public Response getHighRiskNodes(
            @Parameter(description = "Minimum risk score threshold")
            @QueryParam("threshold") @DefaultValue("70.0") double threshold,
            @Parameter(description = "Maximum number of results")
            @QueryParam("limit") @DefaultValue("100") int limit) {
        
        try {
            List<Map<String, Object>> highRiskNodes = riskPropagationService.getHighRiskNodes(threshold);
            
            if (highRiskNodes.size() > limit) {
                highRiskNodes = highRiskNodes.subList(0, limit);
            }
            
            return Response.ok(Map.of(
                "high_risk_nodes", highRiskNodes,
                "threshold", threshold,
                "total_count", highRiskNodes.size()
            )).build();
            
        } catch (Exception e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(Map.of("error", "Failed to retrieve high-risk nodes", "message", e.getMessage()))
                    .build();
        }
    }

    @GET
    @Path("/metrics")
    @Operation(summary = "Get risk calculation metrics", 
               description = "Retrieves overall metrics about risk calculations across the system")
    public Response getRiskMetrics() {
        try {
            Map<String, Object> metrics = riskPropagationService.getRiskPropagationMetrics();
            return Response.ok(metrics).build();
        } catch (Exception e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(Map.of("error", "Failed to retrieve risk metrics", "message", e.getMessage()))
                    .build();
        }
    }

    @GET
    @Path("/scores/bulk")
    @Operation(summary = "Get risk scores for multiple nodes", 
               description = "Retrieves risk scores for multiple nodes in a single request")
    public Response getBulkRiskScores(
            @Parameter(description = "Node type filter (optional)")
            @QueryParam("nodeType") String nodeType,
            @Parameter(description = "Risk tier filter (optional)")
            @QueryParam("riskTier") String riskTier,
            @Parameter(description = "Maximum number of results")
            @QueryParam("limit") @DefaultValue("50") int limit) {
        
        try {
            String query = buildBulkRiskScoreQuery(nodeType, riskTier, limit);
            
            try (Session session = driver.session()) {
                Result result = session.run(query);
                List<RiskScoreResponse> responses = new ArrayList<>();
                
                while (result.hasNext()) {
                    Record record = result.next();
                    String nodeId = getNodeId(record);
                    String type = record.get("nodeType").asString();
                    
                    responses.add(new RiskScoreResponse(
                        nodeId,
                        type,
                        record.get("risk_score").asDouble(0.0),
                        record.get("risk_tier").asString("Unknown"),
                        record.get("last_calculated").asLocalDateTime(null)
                    ));
                }
                
                return Response.ok(Map.of(
                    "risk_scores", responses,
                    "total_count", responses.size(),
                    "filters", Map.of(
                        "node_type", nodeType != null ? nodeType : "all",
                        "risk_tier", riskTier != null ? riskTier : "all"
                    )
                )).build();
            }
        } catch (Exception e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(Map.of("error", "Failed to retrieve bulk risk scores", "message", e.getMessage()))
                    .build();
        }
    }

    private String buildRiskScoreQuery(String nodeType) {
        String nodeLabel = nodeType.substring(0, 1).toUpperCase() + nodeType.substring(1).toLowerCase();
        String idField = getIdField(nodeType);
        
        // For domains, also check subdomain nodes
        if ("domain".equalsIgnoreCase(nodeType)) {
            return """
                OPTIONAL MATCH (d:Domain {fqdn: $nodeId})
                OPTIONAL MATCH (s:Subdomain {fqdn: $nodeId})
                WITH CASE WHEN d IS NOT NULL THEN d ELSE s END as n
                WHERE n IS NOT NULL
                RETURN 
                    n.risk_score as risk_score,
                    n.risk_tier as risk_tier,
                    n.last_calculated as last_calculated
                """;
        }
        
        return String.format("""
            MATCH (n:%s {%s: $nodeId})
            RETURN 
                n.risk_score as risk_score,
                n.risk_tier as risk_tier,
                n.last_calculated as last_calculated
            """, nodeLabel, idField);
    }

    private String buildBulkRiskScoreQuery(String nodeType, String riskTier, int limit) {
        StringBuilder query = new StringBuilder("MATCH (n) WHERE ");
        
        if (nodeType != null && !nodeType.isEmpty()) {
            String nodeLabel = nodeType.substring(0, 1).toUpperCase() + nodeType.substring(1).toLowerCase();
            query.append("n:").append(nodeLabel);
        } else {
            query.append("(n:Domain OR n:Provider OR n:Service OR n:Organization)");
        }
        
        if (riskTier != null && !riskTier.isEmpty()) {
            query.append(" AND n.risk_tier = '").append(riskTier).append("'");
        }
        
        query.append("""
             RETURN 
                labels(n)[0] as nodeType,
                CASE 
                    WHEN n:Domain THEN n.fqdn
                    ELSE n.id
                END as nodeId,
                n.risk_score as risk_score,
                n.risk_tier as risk_tier,
                n.last_calculated as last_calculated
            ORDER BY n.risk_score DESC
            """).append("LIMIT ").append(limit);
        
        return query.toString();
    }

    private String getIdField(String nodeType) {
        switch (nodeType.toLowerCase()) {
            case "domain":
                return "fqdn";
            case "organization":
            case "provider":
            case "service":
                return "id";
            default:
                return "id";
        }
    }

    private String getNodeId(Record record) {
        try {
            return record.get("nodeId").asString();
        } catch (Exception e) {
            String nodeType = record.get("nodeType").asString();
            if ("Domain".equals(nodeType)) {
                return record.get("fqdn").asString("");
            } else {
                return record.get("id").asString("");
            }
        }
    }
}