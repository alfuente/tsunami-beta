package com.example.risk.service;

import jakarta.enterprise.context.ApplicationScoped;
import org.neo4j.driver.*;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.Map;
import java.util.HashMap;

@ApplicationScoped
public class RiskCalculator {

    private final Driver driver;
    
    @Autowired
    private BaseScoreCalculator baseScoreCalculator;
    
    @Autowired
    private ThirdPartyScoreCalculator thirdPartyScoreCalculator;
    
    @Autowired
    private IncidentImpactCalculator incidentImpactCalculator;
    
    @Autowired
    private ContextBoostCalculator contextBoostCalculator;

    public RiskCalculator(Driver driver) {
        this.driver = driver;
    }

    public int recalcForDomainTree(String rootFqdn) {
        try (Session s = driver.session()) {
            return s.executeWrite(tx -> {
                Result result = tx.run("""
                    MATCH (root:Domain {fqdn:$fqdn})-[:HAS_SUBDOMAIN*0..]->(d:Domain)
                    RETURN d.fqdn as fqdn, d as domain
                """, Map.of("fqdn", rootFqdn));
                
                int count = 0;
                while (result.hasNext()) {
                    Record record = result.next();
                    String domainFqdn = record.get("fqdn").asString();
                    
                    double riskScore = calculateCompleteRiskScore(domainFqdn, "domain");
                    
                    tx.run("""
                        MATCH (d:Domain {fqdn: $fqdn})
                        SET d.risk_score = $riskScore,
                            d.risk_tier = $riskTier,
                            d.last_calculated = datetime()
                    """, Map.of(
                        "fqdn", domainFqdn,
                        "riskScore", riskScore,
                        "riskTier", getRiskTier(riskScore)
                    ));
                    
                    count++;
                }
                
                return count;
            });
        }
    }
    
    public double calculateCompleteRiskScore(String nodeId, String nodeType) {
        Map<String, Object> domainData = fetchDomainData(nodeId);
        
        double baseScore = baseScoreCalculator.calculateBaseScore(domainData);
        double thirdPartyScore = thirdPartyScoreCalculator.calculateThirdPartyScore(nodeId, nodeType);
        double incidentImpact = incidentImpactCalculator.calculateIncidentImpact(nodeId, nodeType);
        double contextBoost = contextBoostCalculator.calculateContextBoost(nodeId, nodeType);
        
        double finalScore = (baseScore * 0.40) + 
                           (thirdPartyScore * 0.25) + 
                           (incidentImpact * 0.30) - 
                           (contextBoost * 0.05);
        
        return Math.max(0, Math.min(100, finalScore));
    }
    
    public int recalcForProvider(String providerId) {
        try (Session s = driver.session()) {
            return s.executeWrite(tx -> {
                double riskScore = calculateCompleteRiskScore(providerId, "provider");
                
                tx.run("""
                    MATCH (p:Provider {id: $providerId})
                    SET p.risk_score = $riskScore,
                        p.risk_tier = $riskTier,
                        p.last_calculated = datetime()
                """, Map.of(
                    "providerId", providerId,
                    "riskScore", riskScore,
                    "riskTier", getRiskTier(riskScore)
                ));
                
                return 1;
            });
        }
    }
    
    public int recalcForService(String serviceId) {
        try (Session s = driver.session()) {
            return s.executeWrite(tx -> {
                double riskScore = calculateCompleteRiskScore(serviceId, "service");
                
                tx.run("""
                    MATCH (s:Service {id: $serviceId})
                    SET s.risk_score = $riskScore,
                        s.risk_tier = $riskTier,
                        s.last_calculated = datetime()
                """, Map.of(
                    "serviceId", serviceId,
                    "riskScore", riskScore,
                    "riskTier", getRiskTier(riskScore)
                ));
                
                return 1;
            });
        }
    }
    
    public int recalcForOrganization(String organizationId) {
        try (Session s = driver.session()) {
            return s.executeWrite(tx -> {
                Result result = tx.run("""
                    MATCH (o:Organization {id: $orgId})
                    OPTIONAL MATCH (o)-[:OWNS]->(d:Domain)
                    OPTIONAL MATCH (o)-[:OPERATES]->(p:Provider)
                    OPTIONAL MATCH (o)-[:USES]->(s:Service)
                    RETURN 
                        coalesce(avg(d.risk_score), 0) as avgDomainRisk,
                        coalesce(avg(p.risk_score), 0) as avgProviderRisk,
                        coalesce(avg(s.risk_score), 0) as avgServiceRisk,
                        count(d) as domainCount,
                        count(p) as providerCount,
                        count(s) as serviceCount
                """, Map.of("orgId", organizationId));
                
                if (result.hasNext()) {
                    Record record = result.next();
                    double avgDomainRisk = record.get("avgDomainRisk").asDouble();
                    double avgProviderRisk = record.get("avgProviderRisk").asDouble();
                    double avgServiceRisk = record.get("avgServiceRisk").asDouble();
                    
                    double weightedRisk = (avgDomainRisk * 0.5) + 
                                         (avgProviderRisk * 0.3) + 
                                         (avgServiceRisk * 0.2);
                    
                    tx.run("""
                        MATCH (o:Organization {id: $orgId})
                        SET o.risk_score = $riskScore,
                            o.risk_tier = $riskTier,
                            o.last_calculated = datetime()
                    """, Map.of(
                        "orgId", organizationId,
                        "riskScore", weightedRisk,
                        "riskTier", getRiskTier(weightedRisk)
                    ));
                    
                    return 1;
                }
                
                return 0;
            });
        }
    }
    
    private Map<String, Object> fetchDomainData(String fqdn) {
        try (Session s = driver.session()) {
            Result result = s.run("""
                MATCH (d:Domain {fqdn: $fqdn})
                OPTIONAL MATCH (d)-[:SECURED_BY]->(c:Certificate)
                OPTIONAL MATCH (d)-[:RESOLVES_TO]->(ip:IP)-[:BELONGS_TO]->(asn:ASN)
                RETURN 
                    d.dns_sec_enabled as dns_sec_enabled,
                    d.multi_az as multi_az,
                    d.multi_region as multi_region,
                    collect(DISTINCT {asn: asn.asn, country: asn.country}) as name_servers,
                    c.tls_grade as tls_grade,
                    d.critical_cves as critical_cves,
                    d.high_cves as high_cves
            """, Map.of("fqdn", fqdn));
            
            if (result.hasNext()) {
                Record record = result.next();
                Map<String, Object> data = new HashMap<>();
                data.put("dns_sec_enabled", record.get("dns_sec_enabled").asBoolean(false));
                data.put("multi_az", record.get("multi_az").asBoolean(false));
                data.put("multi_region", record.get("multi_region").asBoolean(false));
                data.put("name_servers", record.get("name_servers").asList());
                data.put("tls_grade", record.get("tls_grade").asString(""));
                data.put("critical_cves", record.get("critical_cves").asInt(0));
                data.put("high_cves", record.get("high_cves").asInt(0));
                return data;
            }
            
            return new HashMap<>();
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
