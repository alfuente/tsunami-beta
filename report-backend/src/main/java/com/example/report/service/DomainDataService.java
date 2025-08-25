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
    
    public GraphAnalysisData getGraphAnalysisData() {
        try (Session session = neo4jDriver.session()) {
            GraphAnalysisData data = new GraphAnalysisData();
            
            // Get basic node counts
            getNodeStatistics(session, data);
            
            // Get relationship statistics
            getRelationshipStatistics(session, data);
            
            // Get domain distribution
            getDomainDistribution(session, data);
            
            // Get technology analysis
            getTechnologyAnalysis(session, data);
            
            // Get risk distribution
            getRiskDistribution(session, data);
            
            // Get provider analysis
            getProviderAnalysis(session, data);
            
            // Get connectivity metrics
            getConnectivityMetrics(session, data);
            
            return data;
        }
    }
    
    private void getNodeStatistics(Session session, GraphAnalysisData data) {
        String query = """
            CALL apoc.meta.stats() YIELD labels
            RETURN labels
            """;
        
        Result result = session.run(query);
        data.nodeStatistics = new HashMap<>();
        
        if (result.hasNext()) {
            var record = result.next();
            var labels = record.get("labels").asMap();
            labels.forEach((key, value) -> {
                data.nodeStatistics.put(key.toString(), ((Number) value).longValue());
            });
        }
        
        // Get total nodes
        String totalQuery = "MATCH (n) RETURN count(n) as total";
        result = session.run(totalQuery);
        if (result.hasNext()) {
            data.totalNodes = result.next().get("total").asLong();
        }
    }
    
    private void getRelationshipStatistics(Session session, GraphAnalysisData data) {
        String query = """
            CALL apoc.meta.stats() YIELD relTypes
            RETURN relTypes
            """;
        
        Result result = session.run(query);
        data.relationshipStatistics = new HashMap<>();
        
        if (result.hasNext()) {
            var record = result.next();
            var relTypes = record.get("relTypes").asMap();
            relTypes.forEach((key, value) -> {
                data.relationshipStatistics.put(key.toString(), ((Number) value).longValue());
            });
        }
        
        // Get total relationships
        String totalQuery = "MATCH ()-[r]->() RETURN count(r) as total";
        result = session.run(totalQuery);
        if (result.hasNext()) {
            data.totalRelationships = result.next().get("total").asLong();
        }
    }
    
    private void getDomainDistribution(Session session, GraphAnalysisData data) {
        // Base domains vs subdomains
        String baseQuery = """
            MATCH (d:Domain)
            WHERE NOT (d)<-[:HAS_SUBDOMAIN]-()
            RETURN count(d) as baseDomains
            """;
        
        Result result = session.run(baseQuery);
        if (result.hasNext()) {
            data.baseDomainsCount = result.next().get("baseDomains").asLong();
        }
        
        String subQuery = """
            MATCH (d:Domain)<-[:HAS_SUBDOMAIN]-()
            RETURN count(d) as subdomains
            """;
        
        result = session.run(subQuery);
        if (result.hasNext()) {
            data.subdomainsCount = result.next().get("subdomains").asLong();
        }
        
        // Top level domains
        String tldQuery = """
            MATCH (d:Domain)
            WHERE NOT (d)<-[:HAS_SUBDOMAIN]-()
            WITH split(d.fqdn, '.') as parts
            WITH parts[size(parts)-1] as tld
            RETURN tld, count(*) as count
            ORDER BY count DESC
            LIMIT 10
            """;
        
        result = session.run(tldQuery);
        data.topLevelDomains = new ArrayList<>();
        
        while (result.hasNext()) {
            var record = result.next();
            CategoryCount cc = new CategoryCount();
            cc.category = record.get("tld").asString();
            cc.count = record.get("count").asLong();
            data.topLevelDomains.add(cc);
        }
    }
    
    private void getTechnologyAnalysis(Session session, GraphAnalysisData data) {
        // Technology categories
        String categoryQuery = """
            MATCH (t:Technology)
            RETURN t.category as category, count(*) as count
            ORDER BY count DESC
            """;
        
        Result result = session.run(categoryQuery);
        data.technologyCategories = new ArrayList<>();
        
        while (result.hasNext()) {
            var record = result.next();
            CategoryCount cc = new CategoryCount();
            cc.category = record.get("category").asString("");
            cc.count = record.get("count").asLong();
            data.technologyCategories.add(cc);
        }
        
        // Technology versions with risk
        String riskQuery = """
            MATCH (tv:TechnologyVersion)
            WHERE tv.risk_level IS NOT NULL
            RETURN tv.risk_level as riskLevel, count(*) as count
            ORDER BY count DESC
            """;
        
        result = session.run(riskQuery);
        data.technologyRiskLevels = new ArrayList<>();
        
        while (result.hasNext()) {
            var record = result.next();
            CategoryCount cc = new CategoryCount();
            cc.category = record.get("riskLevel").asString("");
            cc.count = record.get("count").asLong();
            data.technologyRiskLevels.add(cc);
        }
        
        // Most detected technologies
        String mostDetectedQuery = """
            MATCH (d:Domain)-[:USES_TECHNOLOGY]->(t:Technology)
            RETURN t.name as technology, count(d) as domains
            ORDER BY domains DESC
            LIMIT 15
            """;
        
        result = session.run(mostDetectedQuery);
        data.mostDetectedTechnologies = new ArrayList<>();
        
        while (result.hasNext()) {
            var record = result.next();
            CategoryCount cc = new CategoryCount();
            cc.category = record.get("technology").asString();
            cc.count = record.get("domains").asLong();
            data.mostDetectedTechnologies.add(cc);
        }
    }
    
    private void getRiskDistribution(Session session, GraphAnalysisData data) {
        String query = """
            MATCH (d:Domain)
            WHERE d.risk_score IS NOT NULL
            WITH 
                CASE 
                    WHEN d.risk_score >= 80 THEN 'Critical (80-100)'
                    WHEN d.risk_score >= 60 THEN 'High (60-80)'
                    WHEN d.risk_score >= 40 THEN 'Medium-High (40-60)'
                    WHEN d.risk_score >= 20 THEN 'Medium (20-40)'
                    WHEN d.risk_score >= 10 THEN 'Low-Medium (10-20)'
                    ELSE 'Low (0-10)'
                END as riskBucket
            RETURN riskBucket, count(*) as count
            ORDER BY 
                CASE riskBucket
                    WHEN 'Critical (80-100)' THEN 1
                    WHEN 'High (60-80)' THEN 2
                    WHEN 'Medium-High (40-60)' THEN 3
                    WHEN 'Medium (20-40)' THEN 4
                    WHEN 'Low-Medium (10-20)' THEN 5
                    ELSE 6
                END
            """;
        
        Result result = session.run(query);
        data.riskDistribution = new ArrayList<>();
        
        while (result.hasNext()) {
            var record = result.next();
            CategoryCount cc = new CategoryCount();
            cc.category = record.get("riskBucket").asString();
            cc.count = record.get("count").asLong();
            data.riskDistribution.add(cc);
        }
        
        // Average risk score
        String avgQuery = "MATCH (d:Domain) WHERE d.risk_score IS NOT NULL RETURN avg(d.risk_score) as avgRisk";
        result = session.run(avgQuery);
        if (result.hasNext()) {
            data.averageRiskScore = result.next().get("avgRisk").asDouble(0.0);
        }
    }
    
    private void getProviderAnalysis(Session session, GraphAnalysisData data) {
        // Provider types
        String typeQuery = """
            MATCH (p:Provider)
            RETURN p.type as providerType, count(*) as count
            ORDER BY count DESC
            """;
        
        Result result = session.run(typeQuery);
        data.providerTypes = new ArrayList<>();
        
        while (result.hasNext()) {
            var record = result.next();
            CategoryCount cc = new CategoryCount();
            cc.category = record.get("providerType").asString("");
            cc.count = record.get("count").asLong();
            data.providerTypes.add(cc);
        }
        
        // Most used providers
        String mostUsedQuery = """
            MATCH (d:Domain)-[:USES_PROVIDER]->(p:Provider)
            RETURN p.name as provider, count(d) as domains
            ORDER BY domains DESC
            LIMIT 15
            """;
        
        result = session.run(mostUsedQuery);
        data.mostUsedProviders = new ArrayList<>();
        
        while (result.hasNext()) {
            var record = result.next();
            CategoryCount cc = new CategoryCount();
            cc.category = record.get("provider").asString();
            cc.count = record.get("domains").asLong();
            data.mostUsedProviders.add(cc);
        }
    }
    
    private void getConnectivityMetrics(Session session, GraphAnalysisData data) {
        // Domains with most subdomains
        String subdomainQuery = """
            MATCH (base:Domain)-[:HAS_SUBDOMAIN]->(sub:Domain)
            RETURN base.fqdn as domain, count(sub) as subdomainCount
            ORDER BY subdomainCount DESC
            LIMIT 10
            """;
        
        Result result = session.run(subdomainQuery);
        data.domainsWithMostSubdomains = new ArrayList<>();
        
        while (result.hasNext()) {
            var record = result.next();
            CategoryCount cc = new CategoryCount();
            cc.category = record.get("domain").asString();
            cc.count = record.get("subdomainCount").asLong();
            data.domainsWithMostSubdomains.add(cc);
        }
        
        // Domains with most technologies
        String techQuery = """
            MATCH (d:Domain)-[:USES_TECHNOLOGY|USES_TECHNOLOGY_VERSION]->(t)
            RETURN d.fqdn as domain, count(t) as techCount
            ORDER BY techCount DESC
            LIMIT 10
            """;
        
        result = session.run(techQuery);
        data.domainsWithMostTechnologies = new ArrayList<>();
        
        while (result.hasNext()) {
            var record = result.next();
            CategoryCount cc = new CategoryCount();
            cc.category = record.get("domain").asString();
            cc.count = record.get("techCount").asLong();
            data.domainsWithMostTechnologies.add(cc);
        }
        
        // Service port distribution
        String portQuery = """
            MATCH (s:Service)
            WHERE s.port IS NOT NULL
            RETURN s.port as port, count(*) as count
            ORDER BY count DESC
            LIMIT 15
            """;
        
        result = session.run(portQuery);
        data.servicePortDistribution = new ArrayList<>();
        
        while (result.hasNext()) {
            var record = result.next();
            CategoryCount cc = new CategoryCount();
            cc.category = record.get("port").toString();
            cc.count = record.get("count").asLong();
            data.servicePortDistribution.add(cc);
        }
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
    
    public static class GraphAnalysisData {
        public Long totalNodes = 0L;
        public Long totalRelationships = 0L;
        public Map<String, Long> nodeStatistics = new HashMap<>();
        public Map<String, Long> relationshipStatistics = new HashMap<>();
        
        // Domain statistics
        public Long baseDomainsCount = 0L;
        public Long subdomainsCount = 0L;
        public List<CategoryCount> topLevelDomains = new ArrayList<>();
        
        // Technology analysis
        public List<CategoryCount> technologyCategories = new ArrayList<>();
        public List<CategoryCount> technologyRiskLevels = new ArrayList<>();
        public List<CategoryCount> mostDetectedTechnologies = new ArrayList<>();
        
        // Risk analysis
        public List<CategoryCount> riskDistribution = new ArrayList<>();
        public Double averageRiskScore = 0.0;
        
        // Provider analysis
        public List<CategoryCount> providerTypes = new ArrayList<>();
        public List<CategoryCount> mostUsedProviders = new ArrayList<>();
        
        // Connectivity metrics
        public List<CategoryCount> domainsWithMostSubdomains = new ArrayList<>();
        public List<CategoryCount> domainsWithMostTechnologies = new ArrayList<>();
        public List<CategoryCount> servicePortDistribution = new ArrayList<>();
        
        // Summary metrics
        public String analysisTimestamp = java.time.Instant.now().toString();
        public String databaseHealth = "Unknown";
    }
    
    public static class CategoryCount {
        public String category;
        public Long count;
        public Double percentage;
    }
}