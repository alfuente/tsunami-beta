package com.example.risk.service;

import org.neo4j.driver.Session;
import org.neo4j.driver.Result;
import org.neo4j.driver.Record;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.util.*;

@Service
public class ThirdPartyScoreCalculator {
    
    @Autowired
    private Session neo4jSession;
    
    private static final int MAX_DEPTH = 2;
    private static final double DEPTH_ATTENUATION = 0.8;
    
    private static final Map<String, Double> EXPOSURE_WEIGHTS = Map.of(
        "Critical", 1.0,
        "Important", 0.6,
        "Nice-to-have", 0.3
    );
    
    public double calculateThirdPartyScore(String nodeId, String nodeType) {
        Set<String> visited = new HashSet<>();
        return calculateThirdPartyScoreRecursive(nodeId, nodeType, 0, visited);
    }
    
    private double calculateThirdPartyScoreRecursive(String nodeId, String nodeType, int depth, Set<String> visited) {
        if (depth >= MAX_DEPTH || visited.contains(nodeId)) {
            return 0.0;
        }
        
        visited.add(nodeId);
        
        String query = buildDependencyQuery(nodeType);
        Result result = neo4jSession.run(query, Map.of("nodeId", nodeId));
        
        double totalWeightedScore = 0.0;
        double totalWeight = 0.0;
        
        while (result.hasNext()) {
            Record record = result.next();
            String depId = record.get("depId").asString();
            String depType = record.get("depType").asString();
            String dependencyType = record.get("dependencyType").asString("");
            Double depRiskScore = record.get("depRiskScore").asDouble(0.0);
            
            double exposureWeight = EXPOSURE_WEIGHTS.getOrDefault(dependencyType, 0.3);
            double attenuationFactor = Math.pow(DEPTH_ATTENUATION, depth);
            double effectiveWeight = exposureWeight * attenuationFactor;
            
            double recursiveScore = calculateThirdPartyScoreRecursive(depId, depType, depth + 1, new HashSet<>(visited));
            double combinedScore = Math.max(depRiskScore, recursiveScore);
            
            totalWeightedScore += combinedScore * effectiveWeight;
            totalWeight += effectiveWeight;
        }
        
        visited.remove(nodeId);
        
        return totalWeight > 0 ? totalWeightedScore / totalWeight : 0.0;
    }
    
    private String buildDependencyQuery(String nodeType) {
        switch (nodeType.toLowerCase()) {
            case "domain":
                return """
                    MATCH (n:Domain {fqdn: $nodeId})-[r:DEPENDS_ON]->(dep)
                    WHERE dep:Service OR dep:Provider
                    RETURN 
                        CASE 
                            WHEN dep:Service THEN dep.id
                            WHEN dep:Provider THEN dep.id
                            ELSE dep.name
                        END as depId,
                        labels(dep)[0] as depType,
                        coalesce(r.dependency_type, 'Nice-to-have') as dependencyType,
                        coalesce(dep.risk_score, 0.0) as depRiskScore
                """;
            case "provider":
                return """
                    MATCH (n:Provider {id: $nodeId})-[r:DEPENDS_ON]->(dep)
                    WHERE dep:Service OR dep:Provider
                    RETURN 
                        CASE 
                            WHEN dep:Service THEN dep.id
                            WHEN dep:Provider THEN dep.id
                            ELSE dep.name
                        END as depId,
                        labels(dep)[0] as depType,
                        coalesce(r.dependency_type, 'Nice-to-have') as dependencyType,
                        coalesce(dep.risk_score, 0.0) as depRiskScore
                """;
            case "service":
                return """
                    MATCH (n:Service {id: $nodeId})-[r:DEPENDS_ON]->(dep)
                    WHERE dep:Service OR dep:Provider
                    RETURN 
                        CASE 
                            WHEN dep:Service THEN dep.id
                            WHEN dep:Provider THEN dep.id
                            ELSE dep.name
                        END as depId,
                        labels(dep)[0] as depType,
                        coalesce(r.dependency_type, 'Nice-to-have') as dependencyType,
                        coalesce(dep.risk_score, 0.0) as depRiskScore
                """;
            default:
                return """
                    MATCH (n {id: $nodeId})-[r:DEPENDS_ON]->(dep)
                    WHERE dep:Service OR dep:Provider
                    RETURN 
                        CASE 
                            WHEN dep:Service THEN dep.id
                            WHEN dep:Provider THEN dep.id
                            ELSE dep.name
                        END as depId,
                        labels(dep)[0] as depType,
                        coalesce(r.dependency_type, 'Nice-to-have') as dependencyType,
                        coalesce(dep.risk_score, 0.0) as depRiskScore
                """;
        }
    }
    
    public double calculateProviderConcentrationRisk(String nodeId, String nodeType) {
        String query = """
            MATCH (n:%s {%s: $nodeId})-[:DEPENDS_ON]->(p:Provider)
            WITH n, collect(p) as providers
            WITH n, providers, size(providers) as providerCount
            UNWIND providers as provider
            WITH n, provider, providerCount, 
                 coalesce(provider.market_share, 0.0) as marketShare
            WITH n, providerCount, 
                 sum(marketShare) as totalMarketShare,
                 max(marketShare) as maxMarketShare
            RETURN 
                CASE 
                    WHEN providerCount = 1 THEN 30.0
                    WHEN maxMarketShare > 0.5 THEN 20.0
                    WHEN totalMarketShare > 0.7 THEN 15.0
                    ELSE 0.0
                END as concentrationRisk
        """.formatted(nodeType, getIdField(nodeType));
        
        Result result = neo4jSession.run(query, Map.of("nodeId", nodeId));
        return result.hasNext() ? result.next().get("concentrationRisk").asDouble(0.0) : 0.0;
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