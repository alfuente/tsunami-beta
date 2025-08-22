package com.example.report.service;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.neo4j.driver.Driver;
import org.neo4j.driver.Session;
import org.neo4j.driver.Result;
import java.util.*;
import java.util.logging.Logger;

@ApplicationScoped
public class DomainDataService {
    
    private static final Logger LOGGER = Logger.getLogger(DomainDataService.class.getName());
    
    @Inject
    Driver neo4jDriver;
    
    public DomainRiskData getDomainRiskData(String domain) {
        try (Session session = neo4jDriver.session()) {
            DomainRiskData data = new DomainRiskData();
            data.domain = domain;
            
            // Get basic domain info
            getBasicDomainInfo(session, domain, data);
            
            // Get subdomains
            getSubdomains(session, domain, data);
            
            // Get technologies
            getTechnologies(session, domain, data);
            
            // Get providers
            getProviders(session, domain, data);
            
            // Get services
            getServices(session, domain, data);
            
            // Calculate risk metrics
            calculateRiskMetrics(data);
            
            return data;
        }
    }
    
    private void getBasicDomainInfo(Session session, String domain, DomainRiskData data) {
        String query = """
            MATCH (d:Domain {fqdn: $domain})
            RETURN d.risk_score as riskScore, 
                   d.risk_tier as riskTier,
                   d.last_calculated as lastCalculated,
                   d.monitoring_enabled as monitoringEnabled,
                   d.business_criticality as businessCriticality
            """;
            
        Result result = session.run(query, Map.of("domain", domain));
        
        if (result.hasNext()) {
            var record = result.next();
            data.riskScore = record.get("riskScore").asDouble(0.0);
            data.riskTier = record.get("riskTier").asString("Unknown");
            data.lastCalculated = record.get("lastCalculated").asString(null);
            data.monitoringEnabled = record.get("monitoringEnabled").asBoolean(false);
            data.businessCriticality = record.get("businessCriticality").asString("Unknown");
        }
    }
    
    private void getSubdomains(Session session, String domain, DomainRiskData data) {
        String query = """
            MATCH (d:Domain {fqdn: $domain})-[:HAS_SUBDOMAIN]->(s:Domain)
            RETURN s.fqdn as fqdn, 
                   s.risk_score as riskScore,
                   s.last_calculated as lastCalculated
            ORDER BY s.risk_score DESC
            """;
            
        Result result = session.run(query, Map.of("domain", domain));
        data.subdomains = new ArrayList<>();
        
        while (result.hasNext()) {
            var record = result.next();
            SubdomainInfo subdomain = new SubdomainInfo();
            subdomain.fqdn = record.get("fqdn").asString();
            subdomain.riskScore = record.get("riskScore").asDouble(0.0);
            subdomain.lastCalculated = record.get("lastCalculated").asString(null);
            data.subdomains.add(subdomain);
        }
    }
    
    private void getTechnologies(Session session, String domain, DomainRiskData data) {
        // Get specific technology versions
        String versionQuery = """
            MATCH (d:Domain)-[:USES_TECHNOLOGY_VERSION]->(tv:TechnologyVersion)
            WHERE d.fqdn = $domain OR d.fqdn ENDS WITH '.' + $domain
            RETURN tv.name as name, 
                   tv.version as version,
                   tv.category as category,
                   tv.risk_level as riskLevel,
                   tv.vulnerability_notes as vulnerabilityNotes,
                   tv.detection_count as detectionCount
            """;
            
        Result result = session.run(versionQuery, Map.of("domain", domain));
        data.technologyVersions = new ArrayList<>();
        
        while (result.hasNext()) {
            var record = result.next();
            TechnologyInfo tech = new TechnologyInfo();
            tech.name = record.get("name").asString();
            tech.version = record.get("version").asString();
            tech.category = record.get("category").asString();
            tech.riskLevel = record.get("riskLevel").asString("unknown");
            tech.vulnerabilityNotes = record.get("vulnerabilityNotes").asString("");
            tech.detectionCount = record.get("detectionCount").asInt(1);
            data.technologyVersions.add(tech);
        }
        
        // Get generic technologies
        String genericQuery = """
            MATCH (d:Domain)-[:USES_TECHNOLOGY]->(t:Technology)
            WHERE d.fqdn = $domain OR d.fqdn ENDS WITH '.' + $domain
            RETURN t.name as name, 
                   t.category as category,
                   t.detection_count as detectionCount
            """;
            
        result = session.run(genericQuery, Map.of("domain", domain));
        data.technologies = new ArrayList<>();
        
        while (result.hasNext()) {
            var record = result.next();
            TechnologyInfo tech = new TechnologyInfo();
            tech.name = record.get("name").asString();
            tech.category = record.get("category").asString();
            tech.detectionCount = record.get("detectionCount").asInt(1);
            data.technologies.add(tech);
        }
    }
    
    private void getProviders(Session session, String domain, DomainRiskData data) {
        String query = """
            MATCH (d:Domain)-[:USES_PROVIDER]->(p:Provider)
            WHERE d.fqdn = $domain OR d.fqdn ENDS WITH '.' + $domain
            RETURN p.name as name, 
                   p.type as type,
                   p.confidence as confidence
            """;
            
        Result result = session.run(query, Map.of("domain", domain));
        data.providers = new ArrayList<>();
        
        while (result.hasNext()) {
            var record = result.next();
            ProviderInfo provider = new ProviderInfo();
            provider.name = record.get("name").asString();
            provider.type = record.get("type").asString();
            provider.confidence = record.get("confidence").asDouble(0.0);
            data.providers.add(provider);
        }
    }
    
    private void getServices(Session session, String domain, DomainRiskData data) {
        String query = """
            MATCH (d:Domain)-[:RUNS_SERVICE]->(s:Service)
            WHERE d.fqdn = $domain OR d.fqdn ENDS WITH '.' + $domain
            RETURN s.service_name as serviceName, 
                   s.port as port,
                   s.protocol as protocol,
                   s.state as state,
                   s.product as product,
                   s.version as version
            """;
            
        Result result = session.run(query, Map.of("domain", domain));
        data.services = new ArrayList<>();
        
        while (result.hasNext()) {
            var record = result.next();
            ServiceInfo service = new ServiceInfo();
            service.serviceName = record.get("serviceName").asString();
            service.port = record.get("port").asInt(0);
            service.protocol = record.get("protocol").asString("");
            service.state = record.get("state").asString("");
            service.product = record.get("product").asString("");
            service.version = record.get("version").asString("");
            data.services.add(service);
        }
    }
    
    private void calculateRiskMetrics(DomainRiskData data) {
        // Calculate risk grade based on score
        if (data.riskScore >= 80) {
            data.riskGrade = "E";
            data.riskLevel = "Critical";
        } else if (data.riskScore >= 60) {
            data.riskGrade = "D";
            data.riskLevel = "High";
        } else if (data.riskScore >= 40) {
            data.riskGrade = "C";
            data.riskLevel = "Medium-High";
        } else if (data.riskScore >= 20) {
            data.riskGrade = "B";
            data.riskLevel = "Medium";
        } else if (data.riskScore >= 10) {
            data.riskGrade = "B-";
            data.riskLevel = "Low-Medium";
        } else {
            data.riskGrade = "A";
            data.riskLevel = "Low";
        }
        
        // Generate risk summary
        StringBuilder summary = new StringBuilder();
        summary.append(String.format("Domain %s has a risk score of %.1f (%s).", 
                      data.domain, data.riskScore, data.riskLevel));
        
        if (!data.subdomains.isEmpty()) {
            summary.append(String.format(" Analysis includes %d subdomains.", data.subdomains.size()));
        }
        
        long vulnerableTechs = data.technologyVersions.stream()
                .filter(t -> !"unknown".equals(t.riskLevel) && !"low".equals(t.riskLevel))
                .count();
                
        if (vulnerableTechs > 0) {
            summary.append(String.format(" %d potentially vulnerable technologies detected.", vulnerableTechs));
        }
        
        data.riskSummary = summary.toString();
    }
    
    // Data classes
    public static class DomainRiskData {
        public String domain;
        public Double riskScore = 0.0;
        public String riskGrade = "A";
        public String riskLevel = "Low";
        public String riskTier = "Unknown";
        public String riskSummary = "";
        public String lastCalculated;
        public Boolean monitoringEnabled = false;
        public String businessCriticality = "Unknown";
        public List<SubdomainInfo> subdomains = new ArrayList<>();
        public List<TechnologyInfo> technologies = new ArrayList<>();
        public List<TechnologyInfo> technologyVersions = new ArrayList<>();
        public List<ProviderInfo> providers = new ArrayList<>();
        public List<ServiceInfo> services = new ArrayList<>();
    }
    
    public static class SubdomainInfo {
        public String fqdn;
        public Double riskScore = 0.0;
        public String lastCalculated;
    }
    
    public static class TechnologyInfo {
        public String name;
        public String version;
        public String category;
        public String riskLevel = "unknown";
        public String vulnerabilityNotes = "";
        public Integer detectionCount = 1;
    }
    
    public static class ProviderInfo {
        public String name;
        public String type;
        public Double confidence = 0.0;
    }
    
    public static class ServiceInfo {
        public String serviceName;
        public Integer port;
        public String protocol;
        public String state;
        public String product;
        public String version;
    }
}