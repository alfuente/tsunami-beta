package com.example.risk.validation;

import org.neo4j.driver.Session;
import org.neo4j.driver.Result;
import org.neo4j.driver.Record;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.*;

@Service
public class RiskValidationService {
    
    @Autowired
    private Session neo4jSession;
    
    public List<ValidationResult> validateRiskCalculations() {
        List<ValidationResult> results = new ArrayList<>();
        
        results.addAll(validateRiskScoreRanges());
        results.addAll(validateRiskTierConsistency());
        results.addAll(validateDependencyChains());
        results.addAll(validateIncidentImpacts());
        results.addAll(validateTemporalDecay());
        results.addAll(validateOrphanedNodes());
        results.addAll(validateBusinessRules());
        
        return results;
    }
    
    private List<ValidationResult> validateRiskScoreRanges() {
        List<ValidationResult> results = new ArrayList<>();
        
        String query = """
            MATCH (n)
            WHERE (n:Domain OR n:Provider OR n:Service OR n:Organization)
              AND (n.risk_score < 0 OR n.risk_score > 100)
            RETURN 
                labels(n)[0] as nodeType,
                CASE 
                    WHEN n:Domain THEN n.fqdn
                    ELSE n.id
                END as nodeId,
                n.risk_score as riskScore
        """;
        
        Result result = neo4jSession.run(query);
        while (result.hasNext()) {
            Record record = result.next();
            results.add(new ValidationResult(
                ValidationResult.Severity.ERROR,
                "INVALID_RISK_SCORE_RANGE",
                String.format("Node %s:%s has invalid risk score: %.2f (must be 0-100)",
                    record.get("nodeType").asString(),
                    record.get("nodeId").asString(),
                    record.get("riskScore").asDouble()),
                record.get("nodeId").asString()
            ));
        }
        
        return results;
    }
    
    private List<ValidationResult> validateRiskTierConsistency() {
        List<ValidationResult> results = new ArrayList<>();
        
        String query = """
            MATCH (n)
            WHERE (n:Domain OR n:Provider OR n:Service OR n:Organization)
              AND n.risk_score IS NOT NULL AND n.risk_tier IS NOT NULL
              AND (
                (n.risk_score >= 80 AND n.risk_tier <> 'Critical') OR
                (n.risk_score >= 60 AND n.risk_score < 80 AND n.risk_tier <> 'High') OR
                (n.risk_score >= 40 AND n.risk_score < 60 AND n.risk_tier <> 'Medium') OR
                (n.risk_score >= 20 AND n.risk_score < 40 AND n.risk_tier <> 'Low') OR
                (n.risk_score < 20 AND n.risk_tier <> 'Minimal')
              )
            RETURN 
                labels(n)[0] as nodeType,
                CASE 
                    WHEN n:Domain THEN n.fqdn
                    ELSE n.id
                END as nodeId,
                n.risk_score as riskScore,
                n.risk_tier as riskTier
        """;
        
        Result result = neo4jSession.run(query);
        while (result.hasNext()) {
            Record record = result.next();
            results.add(new ValidationResult(
                ValidationResult.Severity.WARNING,
                "INCONSISTENT_RISK_TIER",
                String.format("Node %s:%s has inconsistent risk tier: score=%.2f, tier=%s",
                    record.get("nodeType").asString(),
                    record.get("nodeId").asString(),
                    record.get("riskScore").asDouble(),
                    record.get("riskTier").asString()),
                record.get("nodeId").asString()
            ));
        }
        
        return results;
    }
    
    private List<ValidationResult> validateDependencyChains() {
        List<ValidationResult> results = new ArrayList<>();
        
        // Check for circular dependencies
        String circularQuery = """
            MATCH path = (n)-[:DEPENDS_ON*2..]->(n)
            WHERE n:Domain OR n:Provider OR n:Service
            RETURN 
                labels(n)[0] as nodeType,
                CASE 
                    WHEN n:Domain THEN n.fqdn
                    ELSE n.id
                END as nodeId,
                length(path) as pathLength
        """;
        
        Result result = neo4jSession.run(circularQuery);
        while (result.hasNext()) {
            Record record = result.next();
            results.add(new ValidationResult(
                ValidationResult.Severity.ERROR,
                "CIRCULAR_DEPENDENCY",
                String.format("Circular dependency detected for %s:%s (path length: %d)",
                    record.get("nodeType").asString(),
                    record.get("nodeId").asString(),
                    record.get("pathLength").asInt()),
                record.get("nodeId").asString()
            ));
        }
        
        // Check for missing dependency types
        String missingTypeQuery = """
            MATCH (n)-[r:DEPENDS_ON]->(dep)
            WHERE r.dependency_type IS NULL OR r.dependency_type = ''
            RETURN 
                labels(n)[0] as nodeType,
                CASE 
                    WHEN n:Domain THEN n.fqdn
                    ELSE n.id
                END as nodeId,
                labels(dep)[0] as depType,
                CASE 
                    WHEN dep:Domain THEN dep.fqdn
                    ELSE dep.id
                END as depId
            LIMIT 100
        """;
        
        result = neo4jSession.run(missingTypeQuery);
        while (result.hasNext()) {
            Record record = result.next();
            results.add(new ValidationResult(
                ValidationResult.Severity.WARNING,
                "MISSING_DEPENDENCY_TYPE",
                String.format("Missing dependency type for %s:%s -> %s:%s",
                    record.get("nodeType").asString(),
                    record.get("nodeId").asString(),
                    record.get("depType").asString(),
                    record.get("depId").asString()),
                record.get("nodeId").asString()
            ));
        }
        
        return results;
    }
    
    private List<ValidationResult> validateIncidentImpacts() {
        List<ValidationResult> results = new ArrayList<>();
        
        // Check for incidents without AFFECTS relationships
        String orphanIncidentsQuery = """
            MATCH (i:Incident)
            WHERE NOT (i)-[:AFFECTS]->()
            RETURN i.id as incidentId, i.severity as severity
        """;
        
        Result result = neo4jSession.run(orphanIncidentsQuery);
        while (result.hasNext()) {
            Record record = result.next();
            results.add(new ValidationResult(
                ValidationResult.Severity.WARNING,
                "ORPHAN_INCIDENT",
                String.format("Incident %s does not affect any nodes",
                    record.get("incidentId").asString()),
                record.get("incidentId").asString()
            ));
        }
        
        // Check for resolved incidents still marked as affecting nodes
        String resolvedIncidentsQuery = """
            MATCH (i:Incident)-[:AFFECTS]->(n)
            WHERE i.resolved IS NOT NULL 
              AND i.resolved < datetime() - duration('P30D')
            RETURN 
                i.id as incidentId,
                labels(n)[0] as nodeType,
                CASE 
                    WHEN n:Domain THEN n.fqdn
                    ELSE n.id
                END as nodeId,
                i.resolved as resolved
            LIMIT 50
        """;
        
        result = neo4jSession.run(resolvedIncidentsQuery);
        while (result.hasNext()) {
            Record record = result.next();
            results.add(new ValidationResult(
                ValidationResult.Severity.INFO,
                "OLD_RESOLVED_INCIDENT",
                String.format("Old resolved incident %s still affects %s:%s (resolved: %s)",
                    record.get("incidentId").asString(),
                    record.get("nodeType").asString(),
                    record.get("nodeId").asString(),
                    record.get("resolved").asLocalDateTime()),
                record.get("incidentId").asString()
            ));
        }
        
        return results;
    }
    
    private List<ValidationResult> validateTemporalDecay() {
        List<ValidationResult> results = new ArrayList<>();
        
        String query = """
            MATCH (n)
            WHERE (n:Domain OR n:Provider OR n:Service OR n:Organization)
              AND n.last_calculated IS NOT NULL
              AND n.last_calculated < datetime() - duration('P7D')
            RETURN 
                labels(n)[0] as nodeType,
                CASE 
                    WHEN n:Domain THEN n.fqdn
                    ELSE n.id
                END as nodeId,
                n.last_calculated as lastCalculated,
                n.risk_score as riskScore
            ORDER BY n.last_calculated ASC
            LIMIT 100
        """;
        
        Result result = neo4jSession.run(query);
        while (result.hasNext()) {
            Record record = result.next();
            LocalDateTime lastCalc = record.get("lastCalculated").asLocalDateTime();
            long daysSince = ChronoUnit.DAYS.between(lastCalc, LocalDateTime.now());
            
            results.add(new ValidationResult(
                daysSince > 30 ? ValidationResult.Severity.WARNING : ValidationResult.Severity.INFO,
                "STALE_RISK_CALCULATION",
                String.format("Risk score for %s:%s is stale (last calculated %d days ago)",
                    record.get("nodeType").asString(),
                    record.get("nodeId").asString(),
                    daysSince),
                record.get("nodeId").asString()
            ));
        }
        
        return results;
    }
    
    private List<ValidationResult> validateOrphanedNodes() {
        List<ValidationResult> results = new ArrayList<>();
        
        // Check for domains without any relationships
        String orphanDomainsQuery = """
            MATCH (d:Domain)
            WHERE NOT (d)-[]->() AND NOT ()-[]->(d)
            RETURN d.fqdn as fqdn
            LIMIT 50
        """;
        
        Result result = neo4jSession.run(orphanDomainsQuery);
        while (result.hasNext()) {
            Record record = result.next();
            results.add(new ValidationResult(
                ValidationResult.Severity.INFO,
                "ORPHAN_DOMAIN",
                String.format("Domain %s has no relationships",
                    record.get("fqdn").asString()),
                record.get("fqdn").asString()
            ));
        }
        
        return results;
    }
    
    private List<ValidationResult> validateBusinessRules() {
        List<ValidationResult> results = new ArrayList<>();
        
        // Critical domains should have monitoring
        String criticalDomainsQuery = """
            MATCH (d:Domain)
            WHERE d.business_criticality = 'Critical'
              AND (d.monitoring_enabled IS NULL OR d.monitoring_enabled = false)
            RETURN d.fqdn as fqdn
        """;
        
        Result result = neo4jSession.run(criticalDomainsQuery);
        while (result.hasNext()) {
            Record record = result.next();
            results.add(new ValidationResult(
                ValidationResult.Severity.WARNING,
                "CRITICAL_DOMAIN_NO_MONITORING",
                String.format("Critical domain %s does not have monitoring enabled",
                    record.get("fqdn").asString()),
                record.get("fqdn").asString()
            ));
        }
        
        // High-risk nodes should have recent assessments
        String highRiskQuery = """
            MATCH (n)
            WHERE (n:Domain OR n:Provider OR n:Service)
              AND n.risk_score >= 70
              AND (n.last_assessment IS NULL OR n.last_assessment < datetime() - duration('P90D'))
            RETURN 
                labels(n)[0] as nodeType,
                CASE 
                    WHEN n:Domain THEN n.fqdn
                    ELSE n.id
                END as nodeId,
                n.risk_score as riskScore
        """;
        
        result = neo4jSession.run(highRiskQuery);
        while (result.hasNext()) {
            Record record = result.next();
            results.add(new ValidationResult(
                ValidationResult.Severity.WARNING,
                "HIGH_RISK_NO_RECENT_ASSESSMENT",
                String.format("High-risk %s %s (score: %.2f) lacks recent security assessment",
                    record.get("nodeType").asString(),
                    record.get("nodeId").asString(),
                    record.get("riskScore").asDouble()),
                record.get("nodeId").asString()
            ));
        }
        
        return results;
    }
    
    public static class ValidationResult {
        public enum Severity { ERROR, WARNING, INFO }
        
        private final Severity severity;
        private final String code;
        private final String message;
        private final String nodeId;
        private final LocalDateTime timestamp;
        
        public ValidationResult(Severity severity, String code, String message, String nodeId) {
            this.severity = severity;
            this.code = code;
            this.message = message;
            this.nodeId = nodeId;
            this.timestamp = LocalDateTime.now();
        }
        
        // Getters
        public Severity getSeverity() { return severity; }
        public String getCode() { return code; }
        public String getMessage() { return message; }
        public String getNodeId() { return nodeId; }
        public LocalDateTime getTimestamp() { return timestamp; }
        
        @Override
        public String toString() {
            return String.format("[%s] %s: %s (Node: %s, Time: %s)",
                severity, code, message, nodeId, timestamp);
        }
    }
    
    public Map<String, Integer> getValidationSummary(List<ValidationResult> results) {
        Map<String, Integer> summary = new HashMap<>();
        
        for (ValidationResult result : results) {
            String key = result.getSeverity().toString();
            summary.put(key, summary.getOrDefault(key, 0) + 1);
        }
        
        summary.put("TOTAL", results.size());
        return summary;
    }
    
    public List<ValidationResult> getValidationsByCode(List<ValidationResult> results, String code) {
        return results.stream()
            .filter(r -> r.getCode().equals(code))
            .toList();
    }
    
    public List<ValidationResult> getValidationsBySeverity(List<ValidationResult> results, 
                                                          ValidationResult.Severity severity) {
        return results.stream()
            .filter(r -> r.getSeverity() == severity)
            .toList();
    }
}