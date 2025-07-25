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

    @GET
    @Path("/domain/{fqdn}/providers-services")
    @Operation(summary = "Get services and providers for a domain", 
               description = "Retrieves all services and providers associated with a domain through subdomains, DNS, MX records and dependencies")
    public Response getDomainProvidersAndServices(
            @Parameter(description = "Fully qualified domain name")
            @PathParam("fqdn") String fqdn,
            @Parameter(description = "Include risk analysis for each provider/service")
            @QueryParam("includeRisk") @DefaultValue("true") boolean includeRisk,
            @Parameter(description = "Include dependency paths showing how services are connected")
            @QueryParam("includePaths") @DefaultValue("false") boolean includePaths) {
        
        try {
            Map<String, Object> result = getDomainProvidersServicesData(fqdn, includeRisk, includePaths);
            return Response.ok(result).build();
            
        } catch (Exception e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(Map.of("error", "Failed to retrieve domain providers and services", "message", e.getMessage()))
                    .build();
        }
    }

    private Map<String, Object> getDomainProvidersServicesData(String fqdn, boolean includeRisk, boolean includePaths) {
        String query = """
            // Try to match as Domain first, then as Subdomain
            OPTIONAL MATCH (d:Domain {fqdn: $fqdn})
            OPTIONAL MATCH (sub:Subdomain {fqdn: $fqdn})
            
            // Use either domain or subdomain as the base node
            WITH CASE WHEN d IS NOT NULL THEN d ELSE sub END as baseNode,
                 CASE WHEN d IS NOT NULL THEN 'Domain' ELSE 'Subdomain' END as nodeType
            
            WHERE baseNode IS NOT NULL
            
            // Get providers through USES_SERVICE relationship (works for both Domain and Subdomain)
            OPTIONAL MATCH (baseNode)-[:USES_SERVICE]->(p:Provider)
            
            // Get providers through RUNS relationship (works for both Domain and Subdomain) 
            OPTIONAL MATCH (baseNode)-[:RUNS]->(rp:Provider)
            
            // Get services through RUNS relationship (works for both Domain and Subdomain)
            OPTIONAL MATCH (baseNode)-[:RUNS]->(s:Service)
            
            // If it's a Domain, get providers through subdomains
            OPTIONAL MATCH (baseNode)-[:HAS_SUBDOMAIN]->(childSub:Subdomain)-[:USES_SERVICE]->(subProv:Provider)
            OPTIONAL MATCH (baseNode)-[:HAS_SUBDOMAIN]->(childSub2:Subdomain)-[:RUNS]->(subProv2:Provider)
            WHERE nodeType = 'Domain'
            
            // If it's a Domain, get services through subdomains
            OPTIONAL MATCH (baseNode)-[:HAS_SUBDOMAIN]->(childSub3:Subdomain)-[:RUNS]->(subSvc:Service)
            WHERE nodeType = 'Domain'
            
            RETURN 
                baseNode.fqdn as domain,
                nodeType as node_type,
                CASE WHEN nodeType = 'Subdomain' THEN baseNode.base_domain ELSE null END as base_domain,
                collect(DISTINCT {
                    id: p.id,
                    name: p.name,
                    type: 'provider',
                    risk_score: CASE WHEN $includeRisk THEN coalesce(p.risk_score, 0.0) ELSE null END,
                    risk_tier: CASE WHEN $includeRisk THEN coalesce(p.risk_tier, 'Unknown') ELSE null END,
                    source: 'uses_service',
                    service_type: coalesce(p.type, 'unknown'),
                    confidence: coalesce(p.confidence, 0.8),
                    subdomain: CASE WHEN nodeType = 'Subdomain' THEN baseNode.fqdn ELSE null END
                }) + 
                collect(DISTINCT {
                    id: rp.id,
                    name: rp.name,
                    type: 'provider',
                    risk_score: CASE WHEN $includeRisk THEN coalesce(rp.risk_score, 0.0) ELSE null END,
                    risk_tier: CASE WHEN $includeRisk THEN coalesce(rp.risk_tier, 'Unknown') ELSE null END,
                    source: 'runs_service',
                    service_type: coalesce(rp.type, 'unknown'),
                    confidence: coalesce(rp.confidence, 0.8),
                    subdomain: CASE WHEN nodeType = 'Subdomain' THEN baseNode.fqdn ELSE null END
                }) +
                collect(DISTINCT {
                    id: subProv.id,
                    name: subProv.name,
                    type: 'provider',
                    risk_score: CASE WHEN $includeRisk THEN coalesce(subProv.risk_score, 0.0) ELSE null END,
                    risk_tier: CASE WHEN $includeRisk THEN coalesce(subProv.risk_tier, 'Unknown') ELSE null END,
                    source: 'subdomain_provider',
                    service_type: coalesce(subProv.type, 'unknown'),
                    confidence: coalesce(subProv.confidence, 0.8),
                    subdomain: childSub.fqdn
                }) +
                collect(DISTINCT {
                    id: subProv2.id,
                    name: subProv2.name,
                    type: 'provider',
                    risk_score: CASE WHEN $includeRisk THEN coalesce(subProv2.risk_score, 0.0) ELSE null END,
                    risk_tier: CASE WHEN $includeRisk THEN coalesce(subProv2.risk_tier, 'Unknown') ELSE null END,
                    source: 'subdomain_provider',
                    service_type: coalesce(subProv2.type, 'unknown'),
                    confidence: coalesce(subProv2.confidence, 0.8),
                    subdomain: childSub2.fqdn
                }) as allProviders,
                
                collect(DISTINCT {
                    id: s.id,
                    name: s.name,
                    type: 'service',
                    risk_score: CASE WHEN $includeRisk THEN coalesce(s.risk_score, 0.0) ELSE null END,
                    risk_tier: CASE WHEN $includeRisk THEN coalesce(s.risk_tier, 'Unknown') ELSE null END,
                    source: 'runs_service',
                    service_type: coalesce(s.type, 'unknown'),
                    confidence: coalesce(s.confidence, 0.8),
                    subdomain: CASE WHEN nodeType = 'Subdomain' THEN baseNode.fqdn ELSE null END
                }) +
                collect(DISTINCT {
                    id: subSvc.id,
                    name: subSvc.name,
                    type: 'service',
                    risk_score: CASE WHEN $includeRisk THEN coalesce(subSvc.risk_score, 0.0) ELSE null END,
                    risk_tier: CASE WHEN $includeRisk THEN coalesce(subSvc.risk_tier, 'Unknown') ELSE null END,
                    source: 'subdomain_service',
                    service_type: coalesce(subSvc.type, 'unknown'),
                    confidence: coalesce(subSvc.confidence, 0.8),
                    subdomain: childSub3.fqdn
                }) as allServices
            """;
        
        try (Session session = driver.session()) {
            Result result = session.run(query, Map.of("fqdn", fqdn, "includeRisk", includeRisk));
            
            if (!result.hasNext()) {
                return Map.of(
                    "domain", fqdn,
                    "providers", List.of(),
                    "services", List.of(),
                    "summary", Map.of(
                        "total_providers", 0,
                        "total_services", 0,
                        "error", "Domain not found"
                    )
                );
            }
            
            Record record = result.next();
            
            // Get providers and services from the new query structure
            List<Map<String, Object>> allProviders = new ArrayList<>();
            List<Map<String, Object>> allServices = new ArrayList<>();
            
            // Filter out null entries 
            addNonNullItems(allProviders, record.get("allProviders").asList());
            addNonNullItems(allServices, record.get("allServices").asList());
            
            // Remove duplicates based on ID
            List<Map<String, Object>> uniqueProviders = removeDuplicatesById(allProviders);
            List<Map<String, Object>> uniqueServices = removeDuplicatesById(allServices);
            
            // Calculate risk statistics
            Map<String, Object> riskSummary = calculateRiskSummary(uniqueProviders, uniqueServices, includeRisk);
            
            // Get dependency paths if requested
            Map<String, Object> paths = includePaths ? getDependencyPaths(fqdn) : Map.of();
            
            Map<String, Object> response = new java.util.HashMap<>();
            response.put("domain", fqdn);
            response.put("node_type", record.get("node_type").asString());
            if (!record.get("base_domain").isNull()) {
                response.put("base_domain", record.get("base_domain").asString());
            }
            response.put("providers", uniqueProviders);
            response.put("services", uniqueServices);
            response.put("summary", Map.of(
                "total_providers", uniqueProviders.size(),
                "total_services", uniqueServices.size(),
                "risk_analysis", riskSummary
            ));
            
            if (includePaths) {
                Map<String, Object> responseWithPaths = new java.util.HashMap<>(response);
                responseWithPaths.put("dependency_paths", paths);
                return responseWithPaths;
            }
            
            return response;
        }
    }
    
    private void addNonNullItems(List<Map<String, Object>> target, List<Object> source) {
        for (Object item : source) {
            if (item instanceof Map) {
                @SuppressWarnings("unchecked")
                Map<String, Object> itemMap = (Map<String, Object>) item;
                if (itemMap.get("id") != null && !"".equals(itemMap.get("id"))) {
                    target.add(itemMap);
                }
            }
        }
    }
    
    private List<Map<String, Object>> removeDuplicatesById(List<Map<String, Object>> items) {
        Map<String, Map<String, Object>> uniqueItems = new java.util.LinkedHashMap<>();
        
        for (Map<String, Object> item : items) {
            String id = (String) item.get("id");
            if (id != null && !uniqueItems.containsKey(id)) {
                uniqueItems.put(id, item);
            }
        }
        
        return new ArrayList<>(uniqueItems.values());
    }
    
    private Map<String, Object> calculateRiskSummary(List<Map<String, Object>> providers, 
                                                   List<Map<String, Object>> services, 
                                                   boolean includeRisk) {
        if (!includeRisk) {
            return Map.of("risk_analysis_disabled", true);
        }
        
        // Calculate risk statistics for providers
        List<Double> providerRisks = providers.stream()
            .map(p -> (Double) p.get("risk_score"))
            .filter(score -> score != null && score > 0)
            .toList();
        
        // Calculate risk statistics for services  
        List<Double> serviceRisks = services.stream()
            .map(s -> (Double) s.get("risk_score"))
            .filter(score -> score != null && score > 0)
            .toList();
        
        double avgProviderRisk = providerRisks.stream().mapToDouble(Double::doubleValue).average().orElse(0.0);
        double avgServiceRisk = serviceRisks.stream().mapToDouble(Double::doubleValue).average().orElse(0.0);
        
        long highRiskProviders = providerRisks.stream().filter(risk -> risk >= 7.0).count();
        long highRiskServices = serviceRisks.stream().filter(risk -> risk >= 7.0).count();
        
        return Map.of(
            "average_provider_risk", Math.round(avgProviderRisk * 100.0) / 100.0,
            "average_service_risk", Math.round(avgServiceRisk * 100.0) / 100.0,
            "high_risk_providers", highRiskProviders,
            "high_risk_services", highRiskServices,
            "total_dependencies", providers.size() + services.size(),
            "risk_distribution", Map.of(
                "low_risk", providerRisks.stream().filter(r -> r < 4.0).count() + serviceRisks.stream().filter(r -> r < 4.0).count(),
                "medium_risk", providerRisks.stream().filter(r -> r >= 4.0 && r < 7.0).count() + serviceRisks.stream().filter(r -> r >= 4.0 && r < 7.0).count(),
                "high_risk", highRiskProviders + highRiskServices
            )
        );
    }
    
    private Map<String, Object> getDependencyPaths(String fqdn) {
        String pathQuery = """
            MATCH (d:Domain {fqdn: $fqdn})
            MATCH path = (d)-[:DEPENDS_ON*1..3]->(target)
            WHERE target:Provider OR target:Service
            RETURN 
                target.id as targetId,
                target.name as targetName,
                labels(target)[0] as targetType,
                [node in nodes(path) | 
                    CASE 
                        WHEN node:Domain THEN node.fqdn
                        WHEN node:Subdomain THEN node.fqdn  
                        ELSE node.name
                    END
                ] as dependencyPath,
                length(path) as pathLength
            ORDER BY pathLength, targetName
            """;
            
        try (Session session = driver.session()) {
            Result result = session.run(pathQuery, Map.of("fqdn", fqdn));
            List<Map<String, Object>> paths = new ArrayList<>();
            
            while (result.hasNext()) {
                Record record = result.next();
                paths.add(Map.of(
                    "target_id", record.get("targetId").asString(),
                    "target_name", record.get("targetName").asString(),
                    "target_type", record.get("targetType").asString(),
                    "path", record.get("dependencyPath").asList(),
                    "path_length", record.get("pathLength").asInt()
                ));
            }
            
            return Map.of(
                "paths", paths,
                "total_paths", paths.size()
            );
        }
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