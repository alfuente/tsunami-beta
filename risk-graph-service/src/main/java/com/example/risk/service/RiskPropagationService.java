package com.example.risk.service;

import org.neo4j.driver.Driver;
import org.neo4j.driver.Session;
import org.neo4j.driver.Result;
import org.neo4j.driver.Record;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.util.*;
import java.util.concurrent.CompletableFuture;

@ApplicationScoped
public class RiskPropagationService {
    
    @Inject
    Driver driver;
    
    @Inject
    RiskCalculator riskCalculator;
    
    private static final int BATCH_SIZE = 100;
    private static final int MAX_PROPAGATION_DEPTH = 3;
    
    public int propagateRiskForIncident(String incidentId) {
        String query = """
            MATCH (i:Incident {id: $incidentId})-[:AFFECTS]->(node)
            RETURN 
                node,
                labels(node)[0] as nodeType,
                CASE 
                    WHEN node:Domain THEN node.fqdn
                    ELSE node.id
                END as nodeId
        """;
        
        try (Session session = driver.session()) {
            Result result = session.run(query, Map.of("incidentId", incidentId));
            Set<String> affectedNodes = new HashSet<>();
            
            while (result.hasNext()) {
                Record record = result.next();
                String nodeType = record.get("nodeType").asString();
                String nodeId = record.get("nodeId").asString();
                
                propagateRiskFromNode(nodeId, nodeType, 0, affectedNodes);
            }
            
            return affectedNodes.size();
        }
    }
    
    private void propagateRiskFromNode(String nodeId, String nodeType, int depth, Set<String> visited) {
        if (depth >= MAX_PROPAGATION_DEPTH || visited.contains(nodeId)) {
            return;
        }
        
        visited.add(nodeId);
        
        riskCalculator.calculateCompleteRiskScore(nodeId, nodeType);
        
        String dependentQuery = buildDependentNodesQuery(nodeType);
        try (Session session = driver.session()) {
            Result result = session.run(dependentQuery, Map.of("nodeId", nodeId));
            
            while (result.hasNext()) {
                Record record = result.next();
                String dependentId = record.get("dependentId").asString();
                String dependentType = record.get("dependentType").asString();
                
                propagateRiskFromNode(dependentId, dependentType, depth + 1, visited);
            }
        }
    }
    
    public int propagateRiskForDomainTree(String rootFqdn) {
        return riskCalculator.recalcForDomainTree(rootFqdn);
    }
    
    public CompletableFuture<Integer> propagateRiskAsync(String nodeId, String nodeType) {
        return CompletableFuture.supplyAsync(() -> {
            Set<String> visited = new HashSet<>();
            propagateRiskFromNode(nodeId, nodeType, 0, visited);
            return visited.size();
        });
    }
    
    public int bulkRiskRecalculation() {
        int totalUpdated = 0;
        
        totalUpdated += bulkUpdateDomains();
        totalUpdated += bulkUpdateProviders();
        totalUpdated += bulkUpdateServices();
        totalUpdated += bulkUpdateOrganizations();
        
        return totalUpdated;
    }
    
    private int bulkUpdateDomains() {
        String query = """
            MATCH (d:Domain)
            WHERE d.last_calculated IS NULL 
               OR d.last_calculated < datetime() - duration('P1D')
            RETURN d.fqdn as fqdn
            ORDER BY d.business_criticality DESC
            LIMIT $batchSize
        """;
        
        try (Session session = driver.session()) {
            Result result = session.run(query, Map.of("batchSize", BATCH_SIZE));
            int count = 0;
            
            while (result.hasNext()) {
                Record record = result.next();
                String fqdn = record.get("fqdn").asString();
                
                double riskScore = riskCalculator.calculateCompleteRiskScore(fqdn, "domain");
                updateNodeRiskScore(fqdn, "Domain", "fqdn", riskScore);
                count++;
            }
            
            return count;
        }
    }
    
    private int bulkUpdateProviders() {
        String query = """
            MATCH (p:Provider)
            WHERE p.last_calculated IS NULL 
               OR p.last_calculated < datetime() - duration('P1D')
            RETURN p.id as id
            ORDER BY p.criticality_score DESC
            LIMIT $batchSize
        """;
        
        try (Session session = driver.session()) {
            Result result = session.run(query, Map.of("batchSize", BATCH_SIZE));
            int count = 0;
            
            while (result.hasNext()) {
                Record record = result.next();
                String id = record.get("id").asString();
                
                double riskScore = riskCalculator.calculateCompleteRiskScore(id, "provider");
                updateNodeRiskScore(id, "Provider", "id", riskScore);
                count++;
            }
            
            return count;
        }
    }
    
    private int bulkUpdateServices() {
        String query = """
            MATCH (s:Service)
            WHERE s.last_calculated IS NULL 
               OR s.last_calculated < datetime() - duration('P1D')
            RETURN s.id as id
            ORDER BY s.criticality_score DESC
            LIMIT $batchSize
        """;
        
        try (Session session = driver.session()) {
            Result result = session.run(query, Map.of("batchSize", BATCH_SIZE));
            int count = 0;
            
            while (result.hasNext()) {
                Record record = result.next();
                String id = record.get("id").asString();
                
                double riskScore = riskCalculator.calculateCompleteRiskScore(id, "service");
                updateNodeRiskScore(id, "Service", "id", riskScore);
                count++;
            }
            
            return count;
        }
    }
    
    private int bulkUpdateOrganizations() {
        String query = """
            MATCH (o:Organization)
            WHERE o.last_calculated IS NULL 
               OR o.last_calculated < datetime() - duration('P1D')
            RETURN o.id as id
            LIMIT $batchSize
        """;
        
        try (Session session = driver.session()) {
            Result result = session.run(query, Map.of("batchSize", BATCH_SIZE));
            int count = 0;
            
            while (result.hasNext()) {
                Record record = result.next();
                String id = record.get("id").asString();
                
                riskCalculator.recalcForOrganization(id);
                count++;
            }
            
            return count;
        }
    }
    
    private void updateNodeRiskScore(String nodeId, String nodeLabel, String idField, double riskScore) {
        String query = String.format("""
            MATCH (n:%s {%s: $nodeId})
            SET n.risk_score = $riskScore,
                n.risk_tier = $riskTier,
                n.last_calculated = datetime()
        """, nodeLabel, idField);
        
        try (Session session = driver.session()) {
            session.run(query, Map.of(
                "nodeId", nodeId,
                "riskScore", riskScore,
                "riskTier", getRiskTier(riskScore)
            ));
        }
    }
    
    private String buildDependentNodesQuery(String nodeType) {
        switch (nodeType.toLowerCase()) {
            case "domain":
                return """
                    MATCH (n:Domain {fqdn: $nodeId})<-[:DEPENDS_ON]-(dependent)
                    RETURN 
                        CASE 
                            WHEN dependent:Domain THEN dependent.fqdn
                            ELSE dependent.id
                        END as dependentId,
                        labels(dependent)[0] as dependentType
                """;
            case "provider":
                return """
                    MATCH (n:Provider {id: $nodeId})<-[:DEPENDS_ON]-(dependent)
                    RETURN 
                        CASE 
                            WHEN dependent:Domain THEN dependent.fqdn
                            ELSE dependent.id
                        END as dependentId,
                        labels(dependent)[0] as dependentType
                """;
            case "service":
                return """
                    MATCH (n:Service {id: $nodeId})<-[:DEPENDS_ON]-(dependent)
                    RETURN 
                        CASE 
                            WHEN dependent:Domain THEN dependent.fqdn
                            ELSE dependent.id
                        END as dependentId,
                        labels(dependent)[0] as dependentType
                """;
            default:
                return """
                    MATCH (n {id: $nodeId})<-[:DEPENDS_ON]-(dependent)
                    RETURN 
                        CASE 
                            WHEN dependent:Domain THEN dependent.fqdn
                            ELSE dependent.id
                        END as dependentId,
                        labels(dependent)[0] as dependentType
                """;
        }
    }
    
    public Map<String, Object> getRiskPropagationMetrics() {
        String query = """
            MATCH (n)
            WHERE n:Domain OR n:Provider OR n:Service OR n:Organization
            WITH labels(n)[0] as nodeType, 
                 count(n) as totalNodes,
                 count(CASE WHEN n.last_calculated IS NOT NULL THEN 1 END) as calculatedNodes,
                 avg(n.risk_score) as avgRiskScore
            RETURN nodeType, totalNodes, calculatedNodes, avgRiskScore
        """;
        
        try (Session session = driver.session()) {
            Result result = session.run(query);
            Map<String, Object> metrics = new HashMap<>();
            
            while (result.hasNext()) {
                Record record = result.next();
                String nodeType = record.get("nodeType").asString();
                
                Map<String, Object> typeMetrics = new HashMap<>();
                typeMetrics.put("totalNodes", record.get("totalNodes").asInt());
                typeMetrics.put("calculatedNodes", record.get("calculatedNodes").asInt());
                typeMetrics.put("avgRiskScore", record.get("avgRiskScore").asDouble(0.0));
                
                metrics.put(nodeType, typeMetrics);
            }
            
            return metrics;
        }
    }
    
    public List<Map<String, Object>> getHighRiskNodes(double threshold) {
        String query = """
            MATCH (n)
            WHERE (n:Domain OR n:Provider OR n:Service OR n:Organization)
              AND n.risk_score >= $threshold
            RETURN 
                labels(n)[0] as nodeType,
                CASE 
                    WHEN n:Domain THEN n.fqdn
                    ELSE n.id
                END as nodeId,
                n.risk_score as riskScore,
                n.risk_tier as riskTier,
                n.last_calculated as lastCalculated
            ORDER BY n.risk_score DESC
            LIMIT 100
        """;
        
        try (Session session = driver.session()) {
            Result result = session.run(query, Map.of("threshold", threshold));
            List<Map<String, Object>> highRiskNodes = new ArrayList<>();
            
            while (result.hasNext()) {
                Record record = result.next();
                Map<String, Object> node = new HashMap<>();
                node.put("nodeType", record.get("nodeType").asString());
                node.put("nodeId", record.get("nodeId").asString());
                node.put("riskScore", record.get("riskScore").asDouble());
                node.put("riskTier", record.get("riskTier").asString());
                node.put("lastCalculated", record.get("lastCalculated").isNull() ? null : record.get("lastCalculated").asLocalDateTime());
                
                highRiskNodes.add(node);
            }
            
            return highRiskNodes;
        }
    }
    
    private String getRiskTier(double riskScore) {
        if (riskScore >= 80) return "Critical";
        if (riskScore >= 60) return "High";
        if (riskScore >= 40) return "Medium";
        if (riskScore >= 20) return "Low";
        return "Minimal";
    }
}