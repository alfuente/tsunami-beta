package com.example.risk.dao;

import jakarta.enterprise.context.ApplicationScoped;
import org.neo4j.driver.*;
import java.util.*;

@ApplicationScoped
public class GraphQueries {
    private final Driver driver;
    
    public GraphQueries(Driver d) {
        this.driver = d;
    }
    
    public boolean domainExists(String fqdn) {
        try (Session s = driver.session()) {
            return s.run("MATCH (n {fqdn:$f}) WHERE n:Domain OR n:Subdomain RETURN n", Map.of("f", fqdn)).hasNext();
        }
    }
    
    public boolean isDomainOrSubdomain(String fqdn) {
        try (Session s = driver.session()) {
            Result result = s.run("MATCH (n {fqdn:$f}) RETURN labels(n) as labels", Map.of("f", fqdn));
            if (result.hasNext()) {
                org.neo4j.driver.Record record = result.next();
                List<Object> labels = record.get("labels").asList();
                return labels.contains("Domain") || labels.contains("Subdomain");
            }
            return false;
        }
    }
    
    public String getNodeType(String fqdn) {
        try (Session s = driver.session()) {
            Result result = s.run("MATCH (n {fqdn:$f}) RETURN labels(n) as labels", Map.of("f", fqdn));
            if (result.hasNext()) {
                org.neo4j.driver.Record record = result.next();
                List<Object> labels = record.get("labels").asList();
                if (labels.contains("Domain")) return "Domain";
                if (labels.contains("Subdomain")) return "Subdomain";
            }
            return "Unknown";
        }
    }
    
    public List<String> getSubdomainsForDomain(String domainFqdn) {
        try (Session s = driver.session()) {
            Result result = s.run(
                "MATCH (d:Domain {fqdn:$domain})-[:HAS_SUBDOMAIN]->(s:Subdomain) RETURN s.fqdn as fqdn", 
                Map.of("domain", domainFqdn)
            );
            List<String> subdomains = new ArrayList<>();
            while (result.hasNext()) {
                subdomains.add(result.next().get("fqdn").asString());
            }
            return subdomains;
        }
    }
    
    public String getParentDomain(String subdomainFqdn) {
        try (Session s = driver.session()) {
            Result result = s.run(
                "MATCH (d:Domain)-[:HAS_SUBDOMAIN]->(s:Subdomain {fqdn:$subdomain}) RETURN d.fqdn as fqdn", 
                Map.of("subdomain", subdomainFqdn)
            );
            if (result.hasNext()) {
                return result.next().get("fqdn").asString();
            }
            return null;
        }
    }
    
    public List<String> getStaleAnalysisNodes(int daysOld) {
        try (Session s = driver.session()) {
            Result result = s.run(
                "MATCH (n) WHERE (n:Domain OR n:Subdomain) " +
                "AND (n.last_analyzed IS NULL OR n.last_analyzed < datetime() - duration({days: $days})) " +
                "RETURN n.fqdn as fqdn ORDER BY coalesce(n.last_analyzed, '1970-01-01') LIMIT 100", 
                Map.of("days", daysOld)
            );
            List<String> nodes = new ArrayList<>();
            while (result.hasNext()) {
                nodes.add(result.next().get("fqdn").asString());
            }
            return nodes;
        }
    }
    
    public List<String> getStaleRiskScoringNodes(int daysOld) {
        try (Session s = driver.session()) {
            Result result = s.run(
                "MATCH (n) WHERE (n:Domain OR n:Subdomain) " +
                "AND (n.last_risk_scoring IS NULL OR n.last_risk_scoring < datetime() - duration({days: $days})) " +
                "RETURN n.fqdn as fqdn ORDER BY coalesce(n.last_risk_scoring, '1970-01-01') LIMIT 100", 
                Map.of("days", daysOld)
            );
            List<String> nodes = new ArrayList<>();
            while (result.hasNext()) {
                nodes.add(result.next().get("fqdn").asString());
            }
            return nodes;
        }
    }
    
    public List<String> getDomainsWithoutProviders() {
        try (Session s = driver.session()) {
            Result result = s.run(
                "MATCH (n) WHERE (n:Domain OR n:Subdomain) " +
                "AND NOT EXISTS((n)-[:RESOLVES_TO]->(:IPAddress)-[:HOSTED_BY]->(:Service)) " +
                "RETURN n.fqdn as fqdn ORDER BY n.fqdn LIMIT 100"
            );
            List<String> nodes = new ArrayList<>();
            while (result.hasNext()) {
                nodes.add(result.next().get("fqdn").asString());
            }
            return nodes;
        }
    }
    
    public Map<String, Object> getGraphStatistics() {
        try (Session s = driver.session()) {
            Map<String, Object> stats = new HashMap<>();
            
            // Basic counts
            stats.put("tlds", s.run("MATCH (t:TLD) RETURN COUNT(t) as count").next().get("count").asInt());
            stats.put("domains", s.run("MATCH (d:Domain) RETURN COUNT(d) as count").next().get("count").asInt());
            stats.put("subdomains", s.run("MATCH (s:Subdomain) RETURN COUNT(s) as count").next().get("count").asInt());
            stats.put("ips", s.run("MATCH (ip:IPAddress) RETURN COUNT(ip) as count").next().get("count").asInt());
            stats.put("services", s.run("MATCH (svc:Service) RETURN COUNT(svc) as count").next().get("count").asInt());
            
            // Relationship counts
            stats.put("domainSubdomainRels", s.run("MATCH (d:Domain)-[:HAS_SUBDOMAIN]->(s:Subdomain) RETURN COUNT(*) as count").next().get("count").asInt());
            stats.put("resolutionRels", s.run("MATCH (n)-[:RESOLVES_TO]->(ip:IPAddress) RETURN COUNT(*) as count").next().get("count").asInt());
            stats.put("hostingRels", s.run("MATCH (ip:IPAddress)-[:HOSTED_BY]->(svc:Service) RETURN COUNT(*) as count").next().get("count").asInt());
            
            // Stale analysis counts (7 days)
            stats.put("staleAnalysis", s.run(
                "MATCH (n) WHERE (n:Domain OR n:Subdomain) " +
                "AND (n.last_analyzed IS NULL OR n.last_analyzed < datetime() - duration({days: 7})) " +
                "RETURN COUNT(n) as count"
            ).next().get("count").asInt());
            
            stats.put("staleRisk", s.run(
                "MATCH (n) WHERE (n:Domain OR n:Subdomain) " +
                "AND (n.last_risk_scoring IS NULL OR n.last_risk_scoring < datetime() - duration({days: 7})) " +
                "RETURN COUNT(n) as count"
            ).next().get("count").asInt());
            
            stats.put("noProviders", s.run(
                "MATCH (n) WHERE (n:Domain OR n:Subdomain) " +
                "AND NOT EXISTS((n)-[:RESOLVES_TO]->(:IPAddress)-[:HOSTED_BY]->(:Service)) " +
                "RETURN COUNT(n) as count"
            ).next().get("count").asInt());
            
            return stats;
        }
    }
}