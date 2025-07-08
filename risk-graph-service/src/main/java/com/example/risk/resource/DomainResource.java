package com.example.risk.resource;

import com.example.risk.dto.DomainResponse;
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

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.util.ArrayList;
import java.util.stream.Collectors;

@Path("/api/v1/domains")
@Tag(name = "Domains", description = "APIs for domain information and management")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class DomainResource {

    @Inject
    Driver driver;

    @GET
    @Path("/{fqdn}")
    @Operation(summary = "Get domain information", 
               description = "Retrieves comprehensive information about a specific domain")
    public Response getDomain(
            @Parameter(description = "Fully qualified domain name")
            @PathParam("fqdn") String fqdn,
            @Parameter(description = "Include incidents in response")
            @QueryParam("includeIncidents") @DefaultValue("true") boolean includeIncidents) {
        
        try {
            DomainResponse response = getDomainInfo(fqdn, includeIncidents);
            
            if (response == null) {
                return Response.status(Response.Status.NOT_FOUND)
                        .entity(Map.of("error", "Domain not found", "fqdn", fqdn))
                        .build();
            }
            
            return Response.ok(response).build();
            
        } catch (Exception e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(Map.of("error", "Failed to retrieve domain information", "message", e.getMessage()))
                    .build();
        }
    }

    @GET
    @Operation(summary = "List domains", 
               description = "Retrieves a list of domains with optional filtering")
    public Response listDomains(
            @Parameter(description = "Filter by risk tier")
            @QueryParam("riskTier") String riskTier,
            @Parameter(description = "Filter by business criticality")
            @QueryParam("businessCriticality") String businessCriticality,
            @Parameter(description = "Filter by monitoring status")
            @QueryParam("monitoringEnabled") Boolean monitoringEnabled,
            @Parameter(description = "Search by domain name pattern")
            @QueryParam("search") String search,
            @Parameter(description = "Maximum number of results")
            @QueryParam("limit") @DefaultValue("50") int limit,
            @Parameter(description = "Offset for pagination")
            @QueryParam("offset") @DefaultValue("0") int offset) {
        
        try {
            String query = buildDomainListQuery(riskTier, businessCriticality, monitoringEnabled, search, limit, offset);
            
            try (Session session = driver.session()) {
                Result result = session.run(query);
                List<DomainResponse> domains = new ArrayList<>();
                
                while (result.hasNext()) {
                    Record record = result.next();
                    DomainResponse domain = mapRecordToDomainResponse(record, false);
                    domains.add(domain);
                }
                
                return Response.ok(Map.of(
                    "domains", domains,
                    "total_count", domains.size(),
                    "filters", Map.of(
                        "risk_tier", riskTier != null ? riskTier : "all",
                        "business_criticality", businessCriticality != null ? businessCriticality : "all",
                        "monitoring_enabled", monitoringEnabled != null ? monitoringEnabled : "all",
                        "search", search != null ? search : ""
                    ),
                    "pagination", Map.of(
                        "limit", limit,
                        "offset", offset
                    )
                )).build();
            }
        } catch (Exception e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(Map.of("error", "Failed to list domains", "message", e.getMessage()))
                    .build();
        }
    }

    @GET
    @Path("/tree/{rootFqdn}")
    @Operation(summary = "Get domain tree", 
               description = "Retrieves a domain and all its subdomains")
    public Response getDomainTree(
            @Parameter(description = "Root domain FQDN")
            @PathParam("rootFqdn") String rootFqdn,
            @Parameter(description = "Include risk scores")
            @QueryParam("includeRisk") @DefaultValue("true") boolean includeRisk) {
        
        try {
            String query = """
                MATCH (root:Domain {fqdn: $rootFqdn})-[:HAS_SUBDOMAIN*0..]->(d:Domain)
                RETURN 
                    d.fqdn as fqdn,
                    d.risk_score as risk_score,
                    d.risk_tier as risk_tier,
                    d.last_calculated as last_calculated,
                    d.business_criticality as business_criticality,
                    d.monitoring_enabled as monitoring_enabled
                ORDER BY d.fqdn
                """;
            
            try (Session session = driver.session()) {
                Result result = session.run(query, Map.of("rootFqdn", rootFqdn));
                List<Map<String, Object>> domainTree = new ArrayList<>();
                
                while (result.hasNext()) {
                    Record record = result.next();
                    Map<String, Object> domainInfo = new HashMap<>();
                    domainInfo.put("fqdn", record.get("fqdn").asString());
                    domainInfo.put("risk_score", record.get("risk_score").asDouble(0.0));
                    domainInfo.put("risk_tier", record.get("risk_tier").asString("Unknown"));
                    domainInfo.put("last_calculated", record.get("last_calculated").asLocalDateTime(null));
                    domainInfo.put("business_criticality", record.get("business_criticality").asString("Unknown"));
                    domainInfo.put("monitoring_enabled", record.get("monitoring_enabled").asBoolean(false));
                    domainTree.add(domainInfo);
                }
                
                return Response.ok(Map.of(
                    "root_domain", rootFqdn,
                    "domain_tree", domainTree,
                    "total_count", domainTree.size(),
                    "include_risk", includeRisk
                )).build();
            }
        } catch (Exception e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(Map.of("error", "Failed to retrieve domain tree", "message", e.getMessage()))
                    .build();
        }
    }

    @GET
    @Path("/critical")
    @Operation(summary = "Get critical domains", 
               description = "Retrieves domains marked as business critical")
    public Response getCriticalDomains(
            @Parameter(description = "Include only domains without monitoring")
            @QueryParam("missingMonitoring") @DefaultValue("false") boolean missingMonitoring) {
        
        try {
            StringBuilder queryBuilder = new StringBuilder("""
                MATCH (d:Domain)
                WHERE d.business_criticality = 'Critical'
                """);
            
            if (missingMonitoring) {
                queryBuilder.append(" AND (d.monitoring_enabled IS NULL OR d.monitoring_enabled = false)");
            }
            
            queryBuilder.append("""
                RETURN 
                    d.fqdn as fqdn,
                    d.risk_score as risk_score,
                    d.risk_tier as risk_tier,
                    d.last_calculated as last_calculated,
                    d.monitoring_enabled as monitoring_enabled,
                    d.last_assessment as last_assessment
                ORDER BY d.risk_score DESC
                """);
            
            try (Session session = driver.session()) {
                Result result = session.run(queryBuilder.toString());
                List<Map<String, Object>> criticalDomains = new ArrayList<>();
                
                while (result.hasNext()) {
                    Record record = result.next();
                    criticalDomains.add(Map.of(
                        "fqdn", record.get("fqdn").asString(),
                        "risk_score", record.get("risk_score").asDouble(0.0),
                        "risk_tier", record.get("risk_tier").asString("Unknown"),
                        "last_calculated", record.get("last_calculated").asLocalDateTime(null),
                        "monitoring_enabled", record.get("monitoring_enabled").asBoolean(false),
                        "last_assessment", record.get("last_assessment").asLocalDateTime(null)
                    ));
                }
                
                return Response.ok(Map.of(
                    "critical_domains", criticalDomains,
                    "total_count", criticalDomains.size(),
                    "missing_monitoring_filter", missingMonitoring
                )).build();
            }
        } catch (Exception e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(Map.of("error", "Failed to retrieve critical domains", "message", e.getMessage()))
                    .build();
        }
    }

    @GET
    @Path("/security-summary")
    @Operation(summary = "Get domains security summary", 
               description = "Retrieves security overview for all domains")
    public Response getSecuritySummary() {
        try {
            String query = """
                MATCH (d:Domain)
                OPTIONAL MATCH (d)<-[:AFFECTS]-(i:Incident)
                WHERE i.resolved IS NULL
                RETURN 
                    count(d) as total_domains,
                    avg(d.risk_score) as avg_risk_score,
                    count(CASE WHEN d.risk_tier = 'Critical' THEN 1 END) as critical_domains,
                    count(CASE WHEN d.risk_tier = 'High' THEN 1 END) as high_risk_domains,
                    count(CASE WHEN d.monitoring_enabled = true THEN 1 END) as monitored_domains,
                    count(CASE WHEN d.dns_sec_enabled = true THEN 1 END) as dnssec_enabled_domains,
                    count(CASE WHEN d.tls_grade IN ['A+', 'A'] THEN 1 END) as good_tls_domains,
                    count(DISTINCT i) as active_incidents
                """;
            
            try (Session session = driver.session()) {
                Result result = session.run(query);
                
                if (result.hasNext()) {
                    Record record = result.next();
                    Map<String, Object> summary = Map.of(
                        "total_domains", record.get("total_domains").asInt(),
                        "average_risk_score", record.get("avg_risk_score").asDouble(0.0),
                        "risk_distribution", Map.of(
                            "critical", record.get("critical_domains").asInt(),
                            "high", record.get("high_risk_domains").asInt()
                        ),
                        "monitoring", Map.of(
                            "monitored_domains", record.get("monitored_domains").asInt(),
                            "monitoring_coverage", calculatePercentage(
                                record.get("monitored_domains").asInt(),
                                record.get("total_domains").asInt()
                            )
                        ),
                        "security", Map.of(
                            "dnssec_enabled", record.get("dnssec_enabled_domains").asInt(),
                            "good_tls_grade", record.get("good_tls_domains").asInt(),
                            "active_incidents", record.get("active_incidents").asInt()
                        )
                    );
                    
                    return Response.ok(summary).build();
                }
                
                return Response.ok(Map.of("error", "No domain data found")).build();
            }
        } catch (Exception e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(Map.of("error", "Failed to retrieve security summary", "message", e.getMessage()))
                    .build();
        }
    }

    private DomainResponse getDomainInfo(String fqdn, boolean includeIncidents) {
        String query = """
            MATCH (d:Domain {fqdn: $fqdn})
            OPTIONAL MATCH (d)-[:SECURED_BY]->(c:Certificate)
            OPTIONAL MATCH (d)-[:RESOLVES_TO]->(ip:IP)-[:BELONGS_TO]->(asn:ASN)
            RETURN 
                d.fqdn as fqdn,
                d.risk_score as risk_score,
                d.risk_tier as risk_tier,
                d.last_calculated as last_calculated,
                d.business_criticality as business_criticality,
                d.monitoring_enabled as monitoring_enabled,
                d.dns_sec_enabled as dns_sec_enabled,
                d.multi_az as multi_az,
                d.multi_region as multi_region,
                d.has_failover as has_failover,
                d.critical_cves as critical_cves,
                d.high_cves as high_cves,
                d.last_assessment as last_assessment,
                c.tls_grade as tls_grade,
                collect(DISTINCT {asn: asn.asn, country: asn.country}) as name_servers
            """;
        
        try (Session session = driver.session()) {
            Result result = session.run(query, Map.of("fqdn", fqdn));
            
            if (!result.hasNext()) {
                return null;
            }
            
            Record record = result.next();
            DomainResponse response = mapRecordToDomainResponse(record, includeIncidents);
            
            if (includeIncidents) {
                List<DomainResponse.IncidentInfo> incidents = getIncidentsForDomain(fqdn);
                response.setIncidents(incidents);
            }
            
            return response;
        }
    }

    private DomainResponse mapRecordToDomainResponse(Record record, boolean includeIncidents) {
        DomainResponse response = new DomainResponse(record.get("fqdn").asString());
        response.setRiskScore(record.get("risk_score").asDouble(0.0));
        response.setRiskTier(record.get("risk_tier").asString("Unknown"));
        response.setLastCalculated(record.get("last_calculated").asLocalDateTime(null));
        response.setBusinessCriticality(record.get("business_criticality").asString("Unknown"));
        response.setMonitoringEnabled(record.get("monitoring_enabled").asBoolean(false));
        
        // DNS Info
        DomainResponse.DnsInfo dnsInfo = new DomainResponse.DnsInfo();
        dnsInfo.setDnsSecEnabled(record.get("dns_sec_enabled").asBoolean(false));
        dnsInfo.setNameServers(record.get("name_servers").asList().stream()
            .map(obj -> (Map<String, Object>) obj)
            .collect(Collectors.toList()));
        response.setDnsInfo(dnsInfo);
        
        // Security Info
        DomainResponse.SecurityInfo securityInfo = new DomainResponse.SecurityInfo();
        securityInfo.setTlsGrade(record.get("tls_grade").asString("Unknown"));
        securityInfo.setCriticalCves(record.get("critical_cves").asInt(0));
        securityInfo.setHighCves(record.get("high_cves").asInt(0));
        securityInfo.setLastAssessment(record.get("last_assessment").asLocalDateTime(null));
        response.setSecurityInfo(securityInfo);
        
        // Infrastructure Info
        DomainResponse.InfrastructureInfo infrastructureInfo = new DomainResponse.InfrastructureInfo();
        infrastructureInfo.setMultiAz(record.get("multi_az").asBoolean(false));
        infrastructureInfo.setMultiRegion(record.get("multi_region").asBoolean(false));
        infrastructureInfo.setHasFailover(record.get("has_failover").asBoolean(false));
        response.setInfrastructureInfo(infrastructureInfo);
        
        return response;
    }

    private List<DomainResponse.IncidentInfo> getIncidentsForDomain(String fqdn) {
        String query = """
            MATCH (d:Domain {fqdn: $fqdn})<-[:AFFECTS]-(i:Incident)
            RETURN 
                i.id as incident_id,
                i.severity as severity,
                i.detected as detected,
                i.resolved as resolved
            ORDER BY i.detected DESC
            LIMIT 10
            """;
        
        try (Session session = driver.session()) {
            Result result = session.run(query, Map.of("fqdn", fqdn));
            List<DomainResponse.IncidentInfo> incidents = new ArrayList<>();
            
            while (result.hasNext()) {
                Record record = result.next();
                incidents.add(new DomainResponse.IncidentInfo(
                    record.get("incident_id").asString(),
                    record.get("severity").asString(),
                    record.get("detected").asLocalDateTime(),
                    record.get("resolved").asLocalDateTime(null)
                ));
            }
            
            return incidents;
        }
    }

    private String buildDomainListQuery(String riskTier, String businessCriticality, 
                                      Boolean monitoringEnabled, String search, int limit, int offset) {
        StringBuilder query = new StringBuilder("MATCH (d:Domain) WHERE 1=1");
        
        if (riskTier != null && !riskTier.isEmpty()) {
            query.append(" AND d.risk_tier = '").append(riskTier).append("'");
        }
        
        if (businessCriticality != null && !businessCriticality.isEmpty()) {
            query.append(" AND d.business_criticality = '").append(businessCriticality).append("'");
        }
        
        if (monitoringEnabled != null) {
            query.append(" AND d.monitoring_enabled = ").append(monitoringEnabled);
        }
        
        if (search != null && !search.isEmpty()) {
            query.append(" AND d.fqdn CONTAINS '").append(search).append("'");
        }
        
        query.append("""
             RETURN 
                d.fqdn as fqdn,
                d.risk_score as risk_score,
                d.risk_tier as risk_tier,
                d.last_calculated as last_calculated,
                d.business_criticality as business_criticality,
                d.monitoring_enabled as monitoring_enabled,
                d.dns_sec_enabled as dns_sec_enabled,
                d.multi_az as multi_az,
                d.multi_region as multi_region,
                d.has_failover as has_failover,
                d.critical_cves as critical_cves,
                d.high_cves as high_cves,
                d.last_assessment as last_assessment,
                '' as tls_grade,
                [] as name_servers
            ORDER BY d.risk_score DESC
            """).append("SKIP ").append(offset).append(" LIMIT ").append(limit);
        
        return query.toString();
    }

    private double calculatePercentage(int part, int total) {
        return total > 0 ? (double) part / total * 100.0 : 0.0;
    }
}