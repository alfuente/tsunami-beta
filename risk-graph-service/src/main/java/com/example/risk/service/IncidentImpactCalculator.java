package com.example.risk.service;

import org.neo4j.driver.Session;
import org.neo4j.driver.Result;
import org.neo4j.driver.Record;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.*;

@Service
public class IncidentImpactCalculator {
    
    @Autowired
    private Session neo4jSession;
    
    private static final double LAMBDA = 0.015;
    private static final double HALF_LIFE_DAYS = 46.0;
    
    private static final Map<String, Double> SEVERITY_SCORES = Map.of(
        "Critical", 100.0,
        "High", 70.0,
        "Medium", 40.0,
        "Low", 10.0
    );
    
    private static final Map<String, Double> PROPAGATION_FACTORS = Map.of(
        "Provider", 0.5,
        "Service", 0.4,
        "Domain", 0.3
    );
    
    public double calculateIncidentImpact(String nodeId, String nodeType) {
        double directImpact = calculateDirectIncidentImpact(nodeId, nodeType);
        double indirectImpact = calculateIndirectIncidentImpact(nodeId, nodeType);
        
        double totalImpact = directImpact + indirectImpact;
        return Math.min(100.0, totalImpact);
    }
    
    private double calculateDirectIncidentImpact(String nodeId, String nodeType) {
        String query = buildDirectIncidentQuery(nodeType);
        Result result = neo4jSession.run(query, Map.of("nodeId", nodeId));
        
        double totalImpact = 0.0;
        
        while (result.hasNext()) {
            Record record = result.next();
            String severity = record.get("severity").asString();
            LocalDateTime detected = record.get("detected").asLocalDateTime();
            LocalDateTime resolved = record.get("resolved").asLocalDateTime(null);
            Boolean failoverExists = record.get("failoverExists").asBoolean(false);
            
            double incidentScore = calculateIncidentScore(severity, detected, resolved);
            
            if (failoverExists) {
                incidentScore *= 0.6;
            }
            
            totalImpact += incidentScore;
        }
        
        return totalImpact;
    }
    
    private double calculateIndirectIncidentImpact(String nodeId, String nodeType) {
        String query = buildIndirectIncidentQuery(nodeType);
        Result result = neo4jSession.run(query, Map.of("nodeId", nodeId));
        
        double totalImpact = 0.0;
        
        while (result.hasNext()) {
            Record record = result.next();
            String severity = record.get("severity").asString();
            LocalDateTime detected = record.get("detected").asLocalDateTime();
            LocalDateTime resolved = record.get("resolved").asLocalDateTime(null);
            String affectedType = record.get("affectedType").asString();
            String dependencyType = record.get("dependencyType").asString("");
            Double exposureWeight = getExposureWeight(dependencyType);
            Boolean failoverExists = record.get("failoverExists").asBoolean(false);
            
            double incidentScore = calculateIncidentScore(severity, detected, resolved);
            
            double propagationFactor = PROPAGATION_FACTORS.getOrDefault(affectedType, 0.3);
            incidentScore *= propagationFactor * exposureWeight;
            
            if (failoverExists) {
                incidentScore *= 0.6;
            }
            
            totalImpact += incidentScore;
        }
        
        return totalImpact;
    }
    
    private double calculateIncidentScore(String severity, LocalDateTime detected, LocalDateTime resolved) {
        double baseScore = SEVERITY_SCORES.getOrDefault(severity, 10.0);
        
        LocalDateTime endTime = resolved != null ? resolved : LocalDateTime.now();
        long daysSinceDetection = ChronoUnit.DAYS.between(detected, endTime);
        
        double timeDecay = Math.exp(-LAMBDA * daysSinceDetection);
        return baseScore * timeDecay;
    }
    
    private String buildDirectIncidentQuery(String nodeType) {
        String nodeLabel = nodeType.substring(0, 1).toUpperCase() + nodeType.substring(1).toLowerCase();
        String idField = getIdField(nodeType);
        
        return """
            MATCH (n:%s {%s: $nodeId})<-[:AFFECTS]-(i:Incident)
            OPTIONAL MATCH (n)-[r:DEPENDS_ON]-()
            RETURN 
                i.severity as severity,
                i.detected as detected,
                i.resolved as resolved,
                coalesce(r.failover_exists, false) as failoverExists
        """.formatted(nodeLabel, idField);
    }
    
    private String buildIndirectIncidentQuery(String nodeType) {
        String nodeLabel = nodeType.substring(0, 1).toUpperCase() + nodeType.substring(1).toLowerCase();
        String idField = getIdField(nodeType);
        
        return """
            MATCH (n:%s {%s: $nodeId})-[r:DEPENDS_ON]->(dep)
            MATCH (dep)<-[:AFFECTS]-(i:Incident)
            RETURN 
                i.severity as severity,
                i.detected as detected,
                i.resolved as resolved,
                labels(dep)[0] as affectedType,
                coalesce(r.dependency_type, 'Nice-to-have') as dependencyType,
                coalesce(r.failover_exists, false) as failoverExists
        """.formatted(nodeLabel, idField);
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
    
    private double getExposureWeight(String dependencyType) {
        switch (dependencyType) {
            case "Critical":
                return 1.0;
            case "Important":
                return 0.6;
            case "Nice-to-have":
                return 0.3;
            default:
                return 0.3;
        }
    }
    
    public double calculateActiveIncidentPenalty(String nodeId, String nodeType) {
        String query = buildActiveIncidentQuery(nodeType);
        Result result = neo4jSession.run(query, Map.of("nodeId", nodeId));
        
        double penalty = 0.0;
        
        while (result.hasNext()) {
            Record record = result.next();
            String severity = record.get("severity").asString();
            LocalDateTime detected = record.get("detected").asLocalDateTime();
            
            long daysSinceDetection = ChronoUnit.DAYS.between(detected, LocalDateTime.now());
            
            if (daysSinceDetection <= 7) {
                penalty += SEVERITY_SCORES.getOrDefault(severity, 10.0) * 0.5;
            } else if (daysSinceDetection <= 30) {
                penalty += SEVERITY_SCORES.getOrDefault(severity, 10.0) * 0.3;
            }
        }
        
        return Math.min(50.0, penalty);
    }
    
    private String buildActiveIncidentQuery(String nodeType) {
        String nodeLabel = nodeType.substring(0, 1).toUpperCase() + nodeType.substring(1).toLowerCase();
        String idField = getIdField(nodeType);
        
        return """
            MATCH (n:%s {%s: $nodeId})<-[:AFFECTS]-(i:Incident)
            WHERE i.resolved IS NULL
            RETURN 
                i.severity as severity,
                i.detected as detected
        """.formatted(nodeLabel, idField);
    }
}