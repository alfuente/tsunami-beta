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
import java.time.ZonedDateTime;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;
import org.neo4j.driver.Value;

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
    @Path("/base-domains")
    @Operation(summary = "List base domains", 
               description = "Retrieves a list of base domains grouped by root domain")
    public Response listBaseDomains(
            @Parameter(description = "Filter by risk tier")
            @QueryParam("riskTier") String riskTier,
            @Parameter(description = "Filter by business criticality")
            @QueryParam("businessCriticality") String businessCriticality,
            @Parameter(description = "Filter by monitoring status")
            @QueryParam("monitoringEnabled") Boolean monitoringEnabled,
            @Parameter(description = "Search by domain name pattern")
            @QueryParam("search") String search,
            @Parameter(description = "Filter by TLD (Top Level Domain)")
            @QueryParam("tld") String tld,
            @Parameter(description = "Maximum number of results")
            @QueryParam("limit") @DefaultValue("50") int limit,
            @Parameter(description = "Offset for pagination")
            @QueryParam("offset") @DefaultValue("0") int offset) {
        
        try {
            String query = buildBaseDomainQuery(riskTier, businessCriticality, monitoringEnabled, search, tld, limit, offset);
            
            try (Session session = driver.session()) {
                Result result = session.run(query);
                List<Map<String, Object>> baseDomains = new ArrayList<>();
                
                while (result.hasNext()) {
                    Record record = result.next();
                    Map<String, Object> baseDomain = new HashMap<>();
                    baseDomain.put("base_domain", record.get("base_domain").asString());
                    baseDomain.put("subdomain_count", record.get("subdomain_count").asInt());
                    baseDomain.put("service_count", record.get("service_count").asInt());
                    baseDomain.put("provider_count", record.get("provider_count").asInt());
                    baseDomain.put("avg_risk_score", record.get("avg_risk_score").asDouble(0.0));
                    baseDomain.put("max_risk_score", record.get("max_risk_score").asDouble(0.0));
                    baseDomain.put("risk_tier", record.get("risk_tier").asString("Unknown"));
                    baseDomain.put("critical_subdomains", record.get("critical_subdomains").asInt());
                    baseDomain.put("high_risk_subdomains", record.get("high_risk_subdomains").asInt());
                    baseDomain.put("business_criticality", record.get("business_criticality").asString("Unknown"));
                    baseDomain.put("monitoring_enabled", record.get("monitoring_enabled").asBoolean(false));
                    baseDomains.add(baseDomain);
                }
                
                return Response.ok(Map.of(
                    "base_domains", baseDomains,
                    "total_count", baseDomains.size(),
                    "filters", Map.of(
                        "risk_tier", riskTier != null ? riskTier : "all",
                        "business_criticality", businessCriticality != null ? businessCriticality : "all",
                        "monitoring_enabled", monitoringEnabled != null ? monitoringEnabled : "all",
                        "search", search != null ? search : "",
                        "tld", tld != null ? tld : "all"
                    ),
                    "pagination", Map.of(
                        "limit", limit,
                        "offset", offset
                    )
                )).build();
            }
        } catch (Exception e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(Map.of("error", "Failed to list base domains", "message", e.getMessage()))
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
                    domainInfo.put("last_calculated", safeAsLocalDateTime(record.get("last_calculated")));
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
                        "last_calculated", safeAsLocalDateTime(record.get("last_calculated")),
                        "monitoring_enabled", record.get("monitoring_enabled").asBoolean(false),
                        "last_assessment", safeAsLocalDateTime(record.get("last_assessment"))
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
        // First try to find as Domain
        String domainQuery = """
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
            Result result = session.run(domainQuery, Map.of("fqdn", fqdn));
            
            if (result.hasNext()) {
                Record record = result.next();
                DomainResponse response = mapRecordToDomainResponse(record, includeIncidents);
                
                if (includeIncidents) {
                    List<DomainResponse.IncidentInfo> incidents = getIncidentsForDomain(fqdn);
                    response.setIncidents(incidents);
                }
                
                return response;
            }
            
            // If not found as Domain, try as Subdomain
            String subdomainQuery = """
                MATCH (s:Subdomain {fqdn: $fqdn})
                OPTIONAL MATCH (s)-[:SECURED_BY]->(c:Certificate)
                OPTIONAL MATCH (s)-[:RESOLVES_TO]->(ip:IP)-[:BELONGS_TO]->(asn:ASN)
                RETURN 
                    s.fqdn as fqdn,
                    s.risk_score as risk_score,
                    s.risk_tier as risk_tier,
                    s.last_calculated as last_calculated,
                    s.business_criticality as business_criticality,
                    s.monitoring_enabled as monitoring_enabled,
                    coalesce(s.dns_sec_enabled, false) as dns_sec_enabled,
                    coalesce(s.multi_az, false) as multi_az,
                    coalesce(s.multi_region, false) as multi_region,
                    coalesce(s.has_failover, false) as has_failover,
                    coalesce(s.critical_cves, 0) as critical_cves,
                    coalesce(s.high_cves, 0) as high_cves,
                    s.last_assessment as last_assessment,
                    c.tls_grade as tls_grade,
                    collect(DISTINCT {asn: asn.asn, country: asn.country}) as name_servers
                """;
            
            Result subdomainResult = session.run(subdomainQuery, Map.of("fqdn", fqdn));
            
            if (subdomainResult.hasNext()) {
                Record record = subdomainResult.next();
                DomainResponse response = mapRecordToDomainResponse(record, includeIncidents);
                
                if (includeIncidents) {
                    List<DomainResponse.IncidentInfo> incidents = getIncidentsForDomain(fqdn);
                    response.setIncidents(incidents);
                }
                
                return response;
            }
            
            return null;
        }
    }

    private DomainResponse mapRecordToDomainResponse(Record record, boolean includeIncidents) {
        DomainResponse response = new DomainResponse(record.get("fqdn").asString());
        response.setRiskScore(record.get("risk_score").asDouble(0.0));
        response.setRiskTier(record.get("risk_tier").asString("Unknown"));
        response.setLastCalculated(safeAsLocalDateTime(record.get("last_calculated")));
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
        securityInfo.setLastAssessment(safeAsLocalDateTime(record.get("last_assessment")));
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
                    safeAsLocalDateTime(record.get("detected")),
                    safeAsLocalDateTime(record.get("resolved"))
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
    
    /**
     * Helper method to safely convert Neo4j datetime values to LocalDateTime
     */
    private LocalDateTime safeAsLocalDateTime(Value value) {
        if (value == null || value.isNull()) {
            return null;
        }
        
        try {
            Object obj = value.asObject();
            if (obj instanceof ZonedDateTime) {
                return ((ZonedDateTime) obj).toLocalDateTime();
            } else if (obj instanceof LocalDateTime) {
                return (LocalDateTime) obj;
            } else {
                return null;
            }
        } catch (Exception e) {
            return null;
        }
    }

    private String buildBaseDomainQuery(String riskTier, String businessCriticality, 
                                       Boolean monitoringEnabled, String search, String tld, int limit, int offset) {
        StringBuilder query = new StringBuilder("""
            MATCH (d:Domain)
            WITH d, 
                 CASE 
                     WHEN d.fqdn CONTAINS '.' THEN 
                         CASE 
                             WHEN size(split(d.fqdn, '.')) >= 2 THEN 
                                 split(d.fqdn, '.')[-2] + '.' + split(d.fqdn, '.')[-1]
                             ELSE d.fqdn
                         END
                     ELSE d.fqdn
                 END as base_domain
            WHERE 1=1
            """);
        
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
            query.append(" AND base_domain CONTAINS '").append(search).append("'");
        }
        
        if (tld != null && !tld.isEmpty()) {
            query.append(" AND base_domain ENDS WITH '").append(tld).append("'");
        }
        
        query.append("""
            // Get all subdomains for this base domain
            OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(sub:Subdomain)
            
            // Get all services and providers from both domains and subdomains
            OPTIONAL MATCH (d)-[:RUNS]->(ds:Service)
            OPTIONAL MATCH (sub)-[:RUNS]->(ss:Service)
            OPTIONAL MATCH (d)-[:RESOLVES_TO]->(dip:IPAddress)-[:HOSTED_BY]->(dp:Provider)  
            OPTIONAL MATCH (sub)-[:RESOLVES_TO]->(sip:IPAddress)-[:HOSTED_BY]->(sp:Provider)
            
            WITH base_domain, d, 
                 collect(DISTINCT sub) as subdomains,
                 collect(DISTINCT ds.name) + collect(DISTINCT ss.name) as all_service_names,
                 collect(DISTINCT dp.name) + collect(DISTINCT sp.name) as all_provider_names,
                 coalesce(d.risk_score, 0) as domain_risk_score,
                 coalesce(d.business_criticality, 'Unknown') as business_criticality,
                 coalesce(d.monitoring_enabled, false) as monitoring_enabled
            
            WITH base_domain,
                 1 + size(subdomains) as subdomain_count,
                 size([name in all_service_names WHERE name IS NOT NULL AND name <> '']) as service_count,
                 size([name in all_provider_names WHERE name IS NOT NULL AND name <> '']) as provider_count,
                 domain_risk_score,
                 [sub in subdomains WHERE sub.risk_score IS NOT NULL | sub.risk_score] as subdomain_risks,
                 size([sub in subdomains WHERE sub.risk_tier = 'Critical']) as critical_subdomains,
                 size([sub in subdomains WHERE sub.risk_tier = 'High']) as high_risk_subdomains,
                 business_criticality, monitoring_enabled
            
            WITH base_domain, subdomain_count, service_count, provider_count,
                 domain_risk_score,
                 CASE WHEN size(subdomain_risks) > 0 
                      THEN reduce(sum = 0.0, score IN subdomain_risks | sum + score) / size(subdomain_risks)
                      ELSE 0.0 END as avg_subdomain_risk,
                 CASE WHEN size(subdomain_risks) > 0
                      THEN reduce(max = 0.0, score IN subdomain_risks | CASE WHEN score > max THEN score ELSE max END)
                      ELSE 0.0 END as max_subdomain_risk,
                 critical_subdomains, high_risk_subdomains, business_criticality, monitoring_enabled
            
            WITH base_domain, subdomain_count, service_count, provider_count,
                 CASE WHEN avg_subdomain_risk > 0 THEN (domain_risk_score + avg_subdomain_risk) / 2 ELSE domain_risk_score END as avg_risk_score,
                 CASE WHEN domain_risk_score > max_subdomain_risk THEN domain_risk_score ELSE max_subdomain_risk END as max_risk_score,
                 critical_subdomains, high_risk_subdomains, business_criticality, monitoring_enabled
            
            RETURN base_domain, subdomain_count, service_count, provider_count, 
                   avg_risk_score, max_risk_score,
                   CASE 
                       WHEN max_risk_score >= 80 THEN 'Critical'
                       WHEN max_risk_score >= 60 THEN 'High'
                       WHEN max_risk_score >= 40 THEN 'Medium'
                       ELSE 'Low'
                   END as risk_tier,
                   critical_subdomains, high_risk_subdomains, business_criticality, monitoring_enabled
            ORDER BY max_risk_score DESC
            """).append("SKIP ").append(offset).append(" LIMIT ").append(limit);
        
        return query.toString();
    }

    @GET
    @Path("/base-domains/{baseDomain}/details")
    @Operation(summary = "Get base domain details", 
               description = "Retrieves detailed information for a base domain including subdomains, services, and providers")
    public Response getBaseDomainDetails(
            @Parameter(description = "Base domain name (e.g., bice.cl)")
            @PathParam("baseDomain") String baseDomain,
            @Parameter(description = "Include risk breakdown")
            @QueryParam("includeRiskBreakdown") @DefaultValue("true") boolean includeRiskBreakdown) {
        
        try {
            String query = """
                MATCH (d:Domain)
                WITH d, 
                     CASE 
                         WHEN d.fqdn CONTAINS '.' THEN 
                             CASE 
                                 WHEN size(split(d.fqdn, '.')) >= 2 THEN 
                                     split(d.fqdn, '.')[-2] + '.' + split(d.fqdn, '.')[-1]
                                 ELSE d.fqdn
                             END
                         ELSE d.fqdn
                     END as base_domain
                WHERE base_domain = $baseDomain
                
                // Get both the domain and its subdomains
                OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(sub:Subdomain)
                
                // Combine domain and subdomains into a single collection
                WITH d, collect({node: d, type: 'Domain'}) + collect({node: sub, type: 'Subdomain'}) as all_nodes
                
                // Unwind to process each node individually
                UNWIND all_nodes as node_info
                WITH node_info.node as n, node_info.type as node_type
                WHERE n IS NOT NULL
                
                // Get services, providers, incidents, and risk breakdown for each node
                OPTIONAL MATCH (n)-[:RUNS]->(s:Service)
                OPTIONAL MATCH (n)-[:RESOLVES_TO]->(ip:IPAddress)-[:HOSTED_BY]->(p:Provider)
                OPTIONAL MATCH (n)<-[:AFFECTS]-(i:Incident)
                WHERE i.resolved IS NULL
                
                // Get risk calculation details if includeRiskBreakdown is true
                OPTIONAL MATCH (n)<-[:AFFECTS]-(r:Risk)
                WHERE $includeRiskBreakdown = true
                
                RETURN n.fqdn as subdomain,
                       coalesce(n.risk_score, 0.0) as risk_score,
                       coalesce(n.risk_tier, 'Unknown') as risk_tier,
                       coalesce(n.business_criticality, 'Unknown') as business_criticality,
                       coalesce(n.monitoring_enabled, false) as monitoring_enabled,
                       n.last_calculated as last_calculated,
                       collect(DISTINCT s.name) as services,
                       collect(DISTINCT p.name) as providers,
                       count(DISTINCT i) as active_incidents,
                       // Risk breakdown information
                       coalesce(n.base_score, 0.0) as base_score,
                       coalesce(n.third_party_score, 0.0) as third_party_score,
                       coalesce(n.incident_impact, 0.0) as incident_impact,
                       coalesce(n.context_boost, 0.0) as context_boost,
                       collect(DISTINCT {
                           risk_type: r.risk_type,
                           severity: r.severity,
                           score: r.score,
                           description: r.description,
                           remediation: r.remediation,
                           discovered_at: r.discovered_at
                       }) as risk_details
                ORDER BY risk_score DESC
                """;
            
            try (Session session = driver.session()) {
                Result result = session.run(query, Map.of("baseDomain", baseDomain, "includeRiskBreakdown", includeRiskBreakdown));
                List<Map<String, Object>> subdomains = new ArrayList<>();
                Map<String, Object> riskSummary = new HashMap<>();
                Map<String, Object> serviceSummary = new HashMap<>();
                Map<String, Object> providerSummary = new HashMap<>();
                
                List<Double> riskScores = new ArrayList<>();
                Set<String> allServices = new HashSet<>();
                Set<String> allProviders = new HashSet<>();
                int totalIncidents = 0;
                
                while (result.hasNext()) {
                    Record record = result.next();
                    Map<String, Object> subdomain = new HashMap<>();
                    subdomain.put("fqdn", record.get("subdomain").asString());
                    subdomain.put("risk_score", record.get("risk_score").asDouble(0.0));
                    subdomain.put("risk_tier", record.get("risk_tier").asString("Unknown"));
                    subdomain.put("business_criticality", record.get("business_criticality").asString("Unknown"));
                    subdomain.put("monitoring_enabled", record.get("monitoring_enabled").asBoolean(false));
                    subdomain.put("last_calculated", safeAsLocalDateTime(record.get("last_calculated")));
                    subdomain.put("services", record.get("services").asList());
                    subdomain.put("providers", record.get("providers").asList());
                    subdomain.put("active_incidents", record.get("active_incidents").asInt());
                    
                    // Add risk breakdown if requested
                    if (includeRiskBreakdown) {
                        Map<String, Object> riskBreakdown = new HashMap<>();
                        riskBreakdown.put("base_score", record.get("base_score").asDouble(0.0));
                        riskBreakdown.put("third_party_score", record.get("third_party_score").asDouble(0.0));
                        riskBreakdown.put("incident_impact", record.get("incident_impact").asDouble(0.0));
                        riskBreakdown.put("context_boost", record.get("context_boost").asDouble(0.0));
                        riskBreakdown.put("weights", Map.of(
                            "base_score", 0.40,
                            "third_party_score", 0.25,
                            "incident_impact", 0.30,
                            "context_boost", 0.05
                        ));
                        
                        List<Object> riskDetailsList = record.get("risk_details").asList();
                        List<Map<String, Object>> processedRiskDetails = new ArrayList<>();
                        for (Object riskDetailObj : riskDetailsList) {
                            if (riskDetailObj instanceof Map) {
                                @SuppressWarnings("unchecked")
                                Map<String, Object> riskDetail = (Map<String, Object>) riskDetailObj;
                                // Only include non-null risk details
                                if (riskDetail.get("risk_type") != null) {
                                    processedRiskDetails.add(riskDetail);
                                }
                            }
                        }
                        
                        riskBreakdown.put("risk_details", processedRiskDetails);
                        subdomain.put("risk_breakdown", riskBreakdown);
                    }
                    
                    subdomains.add(subdomain);
                    
                    riskScores.add(record.get("risk_score").asDouble(0.0));
                    List<Object> services = record.get("services").asList();
                    List<Object> providers = record.get("providers").asList();
                    services.forEach(service -> allServices.add(service.toString()));
                    providers.forEach(provider -> allProviders.add(provider.toString()));
                    totalIncidents += record.get("active_incidents").asInt();
                }
                
                if (!subdomains.isEmpty()) {
                    double avgRisk = riskScores.stream().mapToDouble(Double::doubleValue).average().orElse(0.0);
                    double maxRisk = riskScores.stream().mapToDouble(Double::doubleValue).max().orElse(0.0);
                    long criticalCount = riskScores.stream().filter(score -> score >= 80).count();
                    long highCount = riskScores.stream().filter(score -> score >= 60 && score < 80).count();
                    
                    riskSummary.put("average_risk_score", avgRisk);
                    riskSummary.put("max_risk_score", maxRisk);
                    riskSummary.put("critical_subdomains", criticalCount);
                    riskSummary.put("high_risk_subdomains", highCount);
                    riskSummary.put("total_incidents", totalIncidents);
                    
                    serviceSummary.put("total_services", allServices.size());
                    serviceSummary.put("services", new ArrayList<>(allServices));
                    
                    providerSummary.put("total_providers", allProviders.size());
                    providerSummary.put("providers", new ArrayList<>(allProviders));
                }
                
                return Response.ok(Map.of(
                    "base_domain", baseDomain,
                    "subdomains", subdomains,
                    "risk_summary", riskSummary,
                    "service_summary", serviceSummary,
                    "provider_summary", providerSummary,
                    "total_count", subdomains.size(),
                    "include_risk_breakdown", includeRiskBreakdown
                )).build();
            }
        } catch (Exception e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(Map.of("error", "Failed to retrieve base domain details", "message", e.getMessage()))
                    .build();
        }
    }
}