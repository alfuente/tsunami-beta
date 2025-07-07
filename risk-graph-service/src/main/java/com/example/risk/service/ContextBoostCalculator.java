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
public class ContextBoostCalculator {
    
    @Autowired
    private Session neo4jSession;
    
    private static final Map<String, Double> CERTIFICATION_BOOSTS = Map.of(
        "ISO_27001", 3.0,
        "SOC2_TYPE_II", 3.0,
        "PCI_DSS", 2.0,
        "HIPAA", 2.0,
        "GDPR_COMPLIANT", 1.5
    );
    
    private static final double CONTINUITY_PLAN_BOOST = 2.0;
    private static final double BUG_BOUNTY_BOOST = 1.0;
    private static final double SECURITY_TRAINING_BOOST = 1.0;
    private static final double INCIDENT_RESPONSE_BOOST = 1.5;
    
    public double calculateContextBoost(String nodeId, String nodeType) {
        double totalBoost = 0.0;
        
        totalBoost += calculateCertificationBoost(nodeId, nodeType);
        totalBoost += calculateContinuityPlanBoost(nodeId, nodeType);
        totalBoost += calculateBugBountyBoost(nodeId, nodeType);
        totalBoost += calculateSecurityTrainingBoost(nodeId, nodeType);
        totalBoost += calculateIncidentResponseBoost(nodeId, nodeType);
        
        return Math.min(5.0, totalBoost);
    }
    
    private double calculateCertificationBoost(String nodeId, String nodeType) {
        String query = buildCertificationQuery(nodeType);
        Result result = neo4jSession.run(query, Map.of("nodeId", nodeId));
        
        double boost = 0.0;
        Set<String> certifications = new HashSet<>();
        
        while (result.hasNext()) {
            Record record = result.next();
            String certification = record.get("certification").asString();
            LocalDateTime validUntil = record.get("valid_until").asLocalDateTime(null);
            
            if (validUntil == null || validUntil.isAfter(LocalDateTime.now())) {
                certifications.add(certification);
            }
        }
        
        for (String cert : certifications) {
            boost += CERTIFICATION_BOOSTS.getOrDefault(cert, 0.0);
        }
        
        return boost;
    }
    
    private double calculateContinuityPlanBoost(String nodeId, String nodeType) {
        String query = buildContinuityPlanQuery(nodeType);
        Result result = neo4jSession.run(query, Map.of("nodeId", nodeId));
        
        if (result.hasNext()) {
            Record record = result.next();
            LocalDateTime lastTested = record.get("last_tested").asLocalDateTime(null);
            
            if (lastTested != null) {
                long monthsSinceTest = ChronoUnit.MONTHS.between(lastTested, LocalDateTime.now());
                
                if (monthsSinceTest <= 12) {
                    return CONTINUITY_PLAN_BOOST;
                } else if (monthsSinceTest <= 24) {
                    return CONTINUITY_PLAN_BOOST * 0.5;
                }
            }
        }
        
        return 0.0;
    }
    
    private double calculateBugBountyBoost(String nodeId, String nodeType) {
        String query = buildBugBountyQuery(nodeType);
        Result result = neo4jSession.run(query, Map.of("nodeId", nodeId));
        
        if (result.hasNext()) {
            Record record = result.next();
            Boolean bugBountyActive = record.get("bug_bounty_active").asBoolean(false);
            LocalDateTime lastUpdate = record.get("last_update").asLocalDateTime(null);
            
            if (bugBountyActive && lastUpdate != null) {
                long monthsSinceUpdate = ChronoUnit.MONTHS.between(lastUpdate, LocalDateTime.now());
                
                if (monthsSinceUpdate <= 6) {
                    return BUG_BOUNTY_BOOST;
                }
            }
        }
        
        return 0.0;
    }
    
    private double calculateSecurityTrainingBoost(String nodeId, String nodeType) {
        String query = buildSecurityTrainingQuery(nodeType);
        Result result = neo4jSession.run(query, Map.of("nodeId", nodeId));
        
        if (result.hasNext()) {
            Record record = result.next();
            LocalDateTime lastTraining = record.get("last_security_training").asLocalDateTime(null);
            Double completionRate = record.get("training_completion_rate").asDouble(0.0);
            
            if (lastTraining != null && completionRate >= 0.8) {
                long monthsSinceTraining = ChronoUnit.MONTHS.between(lastTraining, LocalDateTime.now());
                
                if (monthsSinceTraining <= 12) {
                    return SECURITY_TRAINING_BOOST;
                }
            }
        }
        
        return 0.0;
    }
    
    private double calculateIncidentResponseBoost(String nodeId, String nodeType) {
        String query = buildIncidentResponseQuery(nodeType);
        Result result = neo4jSession.run(query, Map.of("nodeId", nodeId));
        
        if (result.hasNext()) {
            Record record = result.next();
            Boolean hasIncidentResponse = record.get("has_incident_response_plan").asBoolean(false);
            LocalDateTime lastDrill = record.get("last_incident_drill").asLocalDateTime(null);
            
            if (hasIncidentResponse && lastDrill != null) {
                long monthsSinceDrill = ChronoUnit.MONTHS.between(lastDrill, LocalDateTime.now());
                
                if (monthsSinceDrill <= 12) {
                    return INCIDENT_RESPONSE_BOOST;
                }
            }
        }
        
        return 0.0;
    }
    
    private String buildCertificationQuery(String nodeType) {
        String nodeLabel = nodeType.substring(0, 1).toUpperCase() + nodeType.substring(1).toLowerCase();
        String idField = getIdField(nodeType);
        
        return """
            MATCH (n:%s {%s: $nodeId})-[:HAS_CERTIFICATION]->(c:Certification)
            RETURN 
                c.type as certification,
                c.valid_until as valid_until
        """.formatted(nodeLabel, idField);
    }
    
    private String buildContinuityPlanQuery(String nodeType) {
        String nodeLabel = nodeType.substring(0, 1).toUpperCase() + nodeType.substring(1).toLowerCase();
        String idField = getIdField(nodeType);
        
        return """
            MATCH (n:%s {%s: $nodeId})
            RETURN 
                n.continuity_plan_last_tested as last_tested
        """.formatted(nodeLabel, idField);
    }
    
    private String buildBugBountyQuery(String nodeType) {
        String nodeLabel = nodeType.substring(0, 1).toUpperCase() + nodeType.substring(1).toLowerCase();
        String idField = getIdField(nodeType);
        
        return """
            MATCH (n:%s {%s: $nodeId})
            RETURN 
                n.bug_bounty_active as bug_bounty_active,
                n.bug_bounty_last_update as last_update
        """.formatted(nodeLabel, idField);
    }
    
    private String buildSecurityTrainingQuery(String nodeType) {
        String nodeLabel = nodeType.substring(0, 1).toUpperCase() + nodeType.substring(1).toLowerCase();
        String idField = getIdField(nodeType);
        
        return """
            MATCH (n:%s {%s: $nodeId})
            RETURN 
                n.last_security_training as last_security_training,
                n.training_completion_rate as training_completion_rate
        """.formatted(nodeLabel, idField);
    }
    
    private String buildIncidentResponseQuery(String nodeType) {
        String nodeLabel = nodeType.substring(0, 1).toUpperCase() + nodeType.substring(1).toLowerCase();
        String idField = getIdField(nodeType);
        
        return """
            MATCH (n:%s {%s: $nodeId})
            RETURN 
                n.has_incident_response_plan as has_incident_response_plan,
                n.last_incident_drill as last_incident_drill
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
    
    public double calculateRedundancyBoost(String nodeId, String nodeType) {
        String query = buildRedundancyQuery(nodeType);
        Result result = neo4jSession.run(query, Map.of("nodeId", nodeId));
        
        double boost = 0.0;
        
        if (result.hasNext()) {
            Record record = result.next();
            Boolean multiAz = record.get("multi_az").asBoolean(false);
            Boolean multiRegion = record.get("multi_region").asBoolean(false);
            Boolean hasFailover = record.get("has_failover").asBoolean(false);
            
            if (multiRegion) {
                boost += 2.0;
            } else if (multiAz) {
                boost += 1.5;
            }
            
            if (hasFailover) {
                boost += 1.0;
            }
        }
        
        return boost;
    }
    
    private String buildRedundancyQuery(String nodeType) {
        String nodeLabel = nodeType.substring(0, 1).toUpperCase() + nodeType.substring(1).toLowerCase();
        String idField = getIdField(nodeType);
        
        return """
            MATCH (n:%s {%s: $nodeId})
            RETURN 
                n.multi_az as multi_az,
                n.multi_region as multi_region,
                n.has_failover as has_failover
        """.formatted(nodeLabel, idField);
    }
}