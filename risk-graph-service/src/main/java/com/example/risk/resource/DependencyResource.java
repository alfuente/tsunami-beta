package com.example.risk.resource;

import com.example.risk.dto.DependencyResponse;
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

import java.util.List;
import java.util.Map;
import java.util.ArrayList;

@Path("/api/v1/dependencies")
@Tag(name = "Dependencies", description = "APIs for querying node dependencies and relationships")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class DependencyResource {

    @Inject
    Driver driver;

    @GET
    @Path("/{nodeType}/{nodeId}")
    @Operation(summary = "Get dependencies for a specific node", 
               description = "Retrieves all dependencies and dependents for a given node")
    public Response getDependencies(
            @Parameter(description = "Type of node (domain, provider, service, organization)")
            @PathParam("nodeType") String nodeType,
            @Parameter(description = "Node identifier (FQDN for domains, ID for others)")
            @PathParam("nodeId") String nodeId,
            @Parameter(description = "Include dependency summary statistics")
            @QueryParam("includeSummary") @DefaultValue("true") boolean includeSummary) {
        
        try {
            DependencyResponse response = new DependencyResponse(nodeId, nodeType);
            
            // Get dependencies (outgoing relationships)
            List<DependencyResponse.Dependency> dependencies = getDependenciesForNode(nodeId, nodeType);
            response.setDependencies(dependencies);
            
            // Get dependents (incoming relationships)
            List<DependencyResponse.Dependency> dependents = getDependentsForNode(nodeId, nodeType);
            response.setDependents(dependents);
            
            if (includeSummary) {
                DependencyResponse.DependencySummary summary = calculateDependencySummary(dependencies, dependents);
                response.setSummary(summary);
            }
            
            return Response.ok(response).build();
            
        } catch (Exception e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(Map.of("error", "Failed to retrieve dependencies", "message", e.getMessage()))
                    .build();
        }
    }

    @GET
    @Path("/graph/{nodeType}/{nodeId}")
    @Operation(summary = "Get dependency graph for a node", 
               description = "Retrieves the full dependency graph with specified depth")
    public Response getDependencyGraph(
            @Parameter(description = "Type of node (domain, provider, service, organization)")
            @PathParam("nodeType") String nodeType,
            @Parameter(description = "Node identifier (FQDN for domains, ID for others)")
            @PathParam("nodeId") String nodeId,
            @Parameter(description = "Maximum depth for dependency traversal")
            @QueryParam("depth") @DefaultValue("2") int depth,
            @Parameter(description = "Include risk scores in graph")
            @QueryParam("includeRisk") @DefaultValue("true") boolean includeRisk) {
        
        try {
            String query = buildDependencyGraphQuery(nodeType, depth, includeRisk);
            
            try (Session session = driver.session()) {
                Result result = session.run(query, Map.of("nodeId", nodeId, "depth", depth));
                
                List<Map<String, Object>> graphNodes = new ArrayList<>();
                List<Map<String, Object>> graphEdges = new ArrayList<>();
                
                while (result.hasNext()) {
                    Record record = result.next();
                    
                    // Extract nodes and relationships from the path
                    org.neo4j.driver.types.Path path = record.get("path").asPath();
                    
                    path.nodes().forEach(node -> {
                        Map<String, Object> nodeData = node.asMap();
                        nodeData.put("labels", node.labels());
                        graphNodes.add(nodeData);
                    });
                    
                    path.relationships().forEach(rel -> {
                        Map<String, Object> edgeData = rel.asMap();
                        edgeData.put("type", rel.type());
                        edgeData.put("startNodeId", rel.startNodeId());
                        edgeData.put("endNodeId", rel.endNodeId());
                        graphEdges.add(edgeData);
                    });
                }
                
                return Response.ok(Map.of(
                    "target_node", Map.of("id", nodeId, "type", nodeType),
                    "graph", Map.of(
                        "nodes", graphNodes,
                        "edges", graphEdges
                    ),
                    "metadata", Map.of(
                        "depth", depth,
                        "include_risk", includeRisk,
                        "node_count", graphNodes.size(),
                        "edge_count", graphEdges.size()
                    )
                )).build();
            }
        } catch (Exception e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(Map.of("error", "Failed to retrieve dependency graph", "message", e.getMessage()))
                    .build();
        }
    }

    @GET
    @Path("/circular")
    @Operation(summary = "Detect circular dependencies", 
               description = "Finds all circular dependencies in the system")
    public Response getCircularDependencies(
            @Parameter(description = "Maximum depth for circular dependency detection")
            @QueryParam("maxDepth") @DefaultValue("5") int maxDepth) {
        
        try {
            String query = """
                MATCH path = (n)-[:DEPENDS_ON*2..%d]->(n)
                WHERE n:Domain OR n:Provider OR n:Service
                RETURN 
                    labels(n)[0] as nodeType,
                    CASE 
                        WHEN n:Domain THEN n.fqdn
                        ELSE n.id
                    END as nodeId,
                    length(path) as pathLength,
                    [node in nodes(path) | 
                        CASE 
                            WHEN node:Domain THEN node.fqdn
                            ELSE node.id
                        END
                    ] as dependencyChain
                ORDER BY pathLength
                """.formatted(maxDepth);
            
            try (Session session = driver.session()) {
                Result result = session.run(query);
                List<Map<String, Object>> circularDependencies = new ArrayList<>();
                
                while (result.hasNext()) {
                    Record record = result.next();
                    circularDependencies.add(Map.of(
                        "node_id", record.get("nodeId").asString(),
                        "node_type", record.get("nodeType").asString(),
                        "path_length", record.get("pathLength").asInt(),
                        "dependency_chain", record.get("dependencyChain").asList()
                    ));
                }
                
                return Response.ok(Map.of(
                    "circular_dependencies", circularDependencies,
                    "total_count", circularDependencies.size(),
                    "max_depth", maxDepth
                )).build();
            }
        } catch (Exception e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(Map.of("error", "Failed to detect circular dependencies", "message", e.getMessage()))
                    .build();
        }
    }

    private List<DependencyResponse.Dependency> getDependenciesForNode(String nodeId, String nodeType) {
        String query = buildDependencyQuery(nodeType, false); // false = get dependencies (outgoing)
        
        try (Session session = driver.session()) {
            Result result = session.run(query, Map.of("nodeId", nodeId));
            List<DependencyResponse.Dependency> dependencies = new ArrayList<>();
            
            while (result.hasNext()) {
                Record record = result.next();
                dependencies.add(new DependencyResponse.Dependency(
                    record.get("targetId").asString(),
                    record.get("targetType").asString(),
                    record.get("dependencyType").asString("Unknown"),
                    record.get("riskScore").asDouble(0.0),
                    record.get("riskTier").asString("Unknown")
                ));
            }
            
            return dependencies;
        }
    }

    private List<DependencyResponse.Dependency> getDependentsForNode(String nodeId, String nodeType) {
        String query = buildDependencyQuery(nodeType, true); // true = get dependents (incoming)
        
        try (Session session = driver.session()) {
            Result result = session.run(query, Map.of("nodeId", nodeId));
            List<DependencyResponse.Dependency> dependents = new ArrayList<>();
            
            while (result.hasNext()) {
                Record record = result.next();
                dependents.add(new DependencyResponse.Dependency(
                    record.get("targetId").asString(),
                    record.get("targetType").asString(),
                    record.get("dependencyType").asString("Unknown"),
                    record.get("riskScore").asDouble(0.0),
                    record.get("riskTier").asString("Unknown")
                ));
            }
            
            return dependents;
        }
    }

    private String buildDependencyQuery(String nodeType, boolean getDependents) {
        String nodeLabel = nodeType.substring(0, 1).toUpperCase() + nodeType.substring(1).toLowerCase();
        String idField = getIdField(nodeType);
        String relationPattern = getDependents ? 
            "(n)-[r:DEPENDS_ON]->(target)" : 
            "(target)-[r:DEPENDS_ON]->(n)";
        
        return String.format("""
            MATCH (n:%s {%s: $nodeId})
            MATCH %s
            WHERE CASE 
                WHEN target:Domain THEN target.fqdn IS NOT NULL
                ELSE target.id IS NOT NULL
            END
            RETURN 
                CASE 
                    WHEN target:Domain THEN target.fqdn
                    ELSE coalesce(target.id, target.name, 'unknown-' + id(target))
                END as targetId,
                labels(target)[0] as targetType,
                coalesce(r.dependency_type, 'Unknown') as dependencyType,
                coalesce(target.risk_score, 0.0) as riskScore,
                coalesce(target.risk_tier, 'Unknown') as riskTier
            """, nodeLabel, idField, relationPattern);
    }

    private String buildDependencyGraphQuery(String nodeType, int depth, boolean includeRisk) {
        String nodeLabel = nodeType.substring(0, 1).toUpperCase() + nodeType.substring(1).toLowerCase();
        String idField = getIdField(nodeType);
        
        String riskFields = includeRisk ? ", node.risk_score, node.risk_tier" : "";
        
        return String.format("""
            MATCH path = (n:%s {%s: $nodeId})-[:DEPENDS_ON*0..%d]-(node)
            RETURN path %s
            """, nodeLabel, idField, depth, riskFields);
    }

    private DependencyResponse.DependencySummary calculateDependencySummary(
            List<DependencyResponse.Dependency> dependencies, 
            List<DependencyResponse.Dependency> dependents) {
        
        int criticalDeps = (int) dependencies.stream()
            .filter(dep -> "Critical".equals(dep.getDependencyType()))
            .count();
        
        int highRiskDeps = (int) dependencies.stream()
            .filter(dep -> dep.getRiskScore() != null && dep.getRiskScore() >= 70.0)
            .count();
        
        double avgRisk = dependencies.stream()
            .filter(dep -> dep.getRiskScore() != null)
            .mapToDouble(DependencyResponse.Dependency::getRiskScore)
            .average()
            .orElse(0.0);
        
        return new DependencyResponse.DependencySummary(
            dependencies.size(),
            dependents.size(),
            criticalDeps,
            highRiskDeps,
            avgRisk
        );
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
}