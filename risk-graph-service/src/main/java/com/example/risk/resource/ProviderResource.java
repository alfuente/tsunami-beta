package com.example.risk.resource;

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

import java.util.List;
import java.util.Map;
import java.util.ArrayList;

@Path("/api/v1/providers")
@Tag(name = "Providers", description = "APIs for querying provider information")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class ProviderResource {

    @Inject
    Driver driver;

    @GET
    @Operation(summary = "Get all providers", 
               description = "Retrieves all providers in the system with their statistics")
    public Response getAllProviders(
            @Parameter(description = "Include usage statistics for each provider")
            @QueryParam("includeStats") @DefaultValue("true") boolean includeStats,
            @Parameter(description = "Include risk analysis for each provider")
            @QueryParam("includeRisk") @DefaultValue("true") boolean includeRisk,
            @Parameter(description = "Filter by provider type")
            @QueryParam("type") String type,
            @Parameter(description = "Filter by country")
            @QueryParam("country") String country) {
        
        try {
            StringBuilder queryBuilder = new StringBuilder();
            queryBuilder.append("""
                MATCH (p:Provider)
                """);
            
            // Add filters
            List<String> whereConditions = new ArrayList<>();
            if (type != null && !type.isEmpty()) {
                whereConditions.add("p.type = $type");
            }
            if (country != null && !country.isEmpty()) {
                whereConditions.add("p.country = $country");
            }
            
            if (!whereConditions.isEmpty()) {
                queryBuilder.append("WHERE ").append(String.join(" AND ", whereConditions));
            }
            
            if (includeStats) {
                queryBuilder.append("""
                    OPTIONAL MATCH (d:Domain)-[:USES_PROVIDER]->(p)
                    OPTIONAL MATCH (s:Subdomain)-[:USES_PROVIDER]->(p)
                    WITH p, count(DISTINCT d) as domain_count, count(DISTINCT s) as subdomain_count
                    """);
            }
            
            queryBuilder.append("""
                RETURN 
                    p.id as id,
                    p.name as name,
                    p.type as type,
                    coalesce(p.country, 'Global') as country,
                    coalesce(p.evidence, 'Official provider') as evidence,
                    p.created_at as created_at,
                    p.source as source,
                    coalesce(p.aliases, []) as aliases,
                    coalesce(p.domains, []) as domains
                """);
            
            if (includeStats) {
                queryBuilder.append(", domain_count, subdomain_count");
            }
            
            if (includeRisk) {
                queryBuilder.append("""
                    , coalesce(p.risk_score, 0.0) as risk_score,
                    coalesce(p.risk_tier, 'Unknown') as risk_tier,
                    coalesce(p.confidence, 0.8) as confidence
                    """);
            }
            
            queryBuilder.append(" ORDER BY p.type, p.name");
            
            try (Session session = driver.session()) {
                Map<String, Object> parameters = new java.util.HashMap<>();
                if (type != null) parameters.put("type", type);
                if (country != null) parameters.put("country", country);
                
                Result result = session.run(queryBuilder.toString(), parameters);
                List<Map<String, Object>> providers = new ArrayList<>();
                
                while (result.hasNext()) {
                    Record record = result.next();
                    Map<String, Object> provider = new java.util.HashMap<>();
                    
                    provider.put("id", record.get("id").asString());
                    provider.put("name", record.get("name").asString());
                    provider.put("type", record.get("type").asString());
                    provider.put("country", record.get("country").asString());
                    provider.put("evidence", record.get("evidence").asString());
                    
                    if (!record.get("created_at").isNull()) {
                        provider.put("created_at", record.get("created_at").asObject().toString());
                    }
                    if (!record.get("source").isNull()) {
                        provider.put("source", record.get("source").asString());
                    }
                    
                    provider.put("aliases", record.get("aliases").asList());
                    provider.put("domains", record.get("domains").asList());
                    
                    if (includeStats) {
                        provider.put("domain_count", record.get("domain_count").asInt());
                        provider.put("subdomain_count", record.get("subdomain_count").asInt());
                        provider.put("total_usage", record.get("domain_count").asInt() + record.get("subdomain_count").asInt());
                    }
                    
                    if (includeRisk) {
                        provider.put("risk_score", record.get("risk_score").asDouble());
                        provider.put("risk_tier", record.get("risk_tier").asString());
                        provider.put("confidence", record.get("confidence").asDouble());
                    }
                    
                    providers.add(provider);
                }
                
                // Calculate summary statistics
                Map<String, Object> summary = calculateProviderSummary(providers);
                
                return Response.ok(Map.of(
                    "providers", providers,
                    "total_count", providers.size(),
                    "summary", summary,
                    "filters", Map.of(
                        "type", type != null ? type : "all",
                        "country", country != null ? country : "all",
                        "include_stats", includeStats,
                        "include_risk", includeRisk
                    )
                )).build();
            }
        } catch (Exception e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(Map.of("error", "Failed to retrieve providers", "message", e.getMessage()))
                    .build();
        }
    }

    @GET
    @Path("/{providerId}")
    @Operation(summary = "Get provider details", 
               description = "Retrieves detailed information about a specific provider")
    public Response getProvider(
            @Parameter(description = "Provider ID")
            @PathParam("providerId") String providerId,
            @Parameter(description = "Include domains and subdomains using this provider")
            @QueryParam("includeUsage") @DefaultValue("true") boolean includeUsage) {
        
        try {
            String query = """
                MATCH (p:Provider {id: $providerId})
                """ + (includeUsage ? """
                OPTIONAL MATCH (d:Domain)-[:USES_PROVIDER]->(p)
                OPTIONAL MATCH (s:Subdomain)-[:USES_PROVIDER]->(p)
                """ : "") + """
                RETURN 
                    p.id as id,
                    p.name as name,
                    p.type as type,
                    coalesce(p.country, 'Global') as country,
                    coalesce(p.evidence, 'Official provider') as evidence,
                    p.created_at as created_at,
                    p.updated_at as updated_at,
                    p.source as source,
                    coalesce(p.aliases, []) as aliases,
                    coalesce(p.domains, []) as domains,
                    coalesce(p.ip_ranges, []) as ip_ranges,
                    coalesce(p.risk_score, 0.0) as risk_score,
                    coalesce(p.risk_tier, 'Unknown') as risk_tier,
                    coalesce(p.confidence, 0.8) as confidence
                """ + (includeUsage ? """
                    , collect(DISTINCT d.fqdn) as domains_using,
                    collect(DISTINCT s.fqdn) as subdomains_using
                """ : "");
            
            try (Session session = driver.session()) {
                Result result = session.run(query, Map.of("providerId", providerId));
                
                if (!result.hasNext()) {
                    return Response.status(Response.Status.NOT_FOUND)
                            .entity(Map.of("error", "Provider not found", "provider_id", providerId))
                            .build();
                }
                
                Record record = result.next();
                Map<String, Object> provider = new java.util.HashMap<>();
                
                provider.put("id", record.get("id").asString());
                provider.put("name", record.get("name").asString());
                provider.put("type", record.get("type").asString());
                provider.put("country", record.get("country").asString());
                provider.put("evidence", record.get("evidence").asString());
                
                if (!record.get("created_at").isNull()) {
                    provider.put("created_at", record.get("created_at").asObject().toString());
                }
                if (!record.get("updated_at").isNull()) {
                    provider.put("updated_at", record.get("updated_at").asObject().toString());
                }
                if (!record.get("source").isNull()) {
                    provider.put("source", record.get("source").asString());
                }
                
                provider.put("aliases", record.get("aliases").asList());
                provider.put("domains", record.get("domains").asList());
                provider.put("ip_ranges", record.get("ip_ranges").asList());
                provider.put("risk_score", record.get("risk_score").asDouble());
                provider.put("risk_tier", record.get("risk_tier").asString());
                provider.put("confidence", record.get("confidence").asDouble());
                
                if (includeUsage) {
                    List<Object> domainsUsingObj = record.get("domains_using").asList();
                    List<Object> subdomainsUsingObj = record.get("subdomains_using").asList();
                    
                    // Convert to String lists and filter out null/empty values
                    List<String> domainsUsing = domainsUsingObj.stream()
                        .filter(d -> d != null)
                        .map(Object::toString)
                        .filter(s -> !s.isEmpty())
                        .toList();
                    List<String> subdomainsUsing = subdomainsUsingObj.stream()
                        .filter(s -> s != null)
                        .map(Object::toString)
                        .filter(s -> !s.isEmpty())
                        .toList();
                    
                    provider.put("usage", Map.of(
                        "domains", domainsUsing,
                        "subdomains", subdomainsUsing,
                        "total_domains", domainsUsing.size(),
                        "total_subdomains", subdomainsUsing.size()
                    ));
                }
                
                return Response.ok(provider).build();
            }
        } catch (Exception e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(Map.of("error", "Failed to retrieve provider", "message", e.getMessage()))
                    .build();
        }
    }

    @GET
    @Path("/types")
    @Operation(summary = "Get provider types", 
               description = "Retrieves all available provider types with counts")
    public Response getProviderTypes() {
        try {
            String query = """
                MATCH (p:Provider)
                RETURN p.type as type, count(*) as count
                ORDER BY count DESC, type
                """;
            
            try (Session session = driver.session()) {
                Result result = session.run(query);
                List<Map<String, Object>> types = new ArrayList<>();
                
                while (result.hasNext()) {
                    Record record = result.next();
                    types.add(Map.of(
                        "type", record.get("type").asString(),
                        "count", record.get("count").asInt()
                    ));
                }
                
                return Response.ok(Map.of(
                    "types", types,
                    "total_types", types.size()
                )).build();
            }
        } catch (Exception e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(Map.of("error", "Failed to retrieve provider types", "message", e.getMessage()))
                    .build();
        }
    }

    @GET
    @Path("/countries")
    @Operation(summary = "Get provider countries", 
               description = "Retrieves all countries with provider counts")
    public Response getProviderCountries() {
        try {
            String query = """
                MATCH (p:Provider)
                RETURN coalesce(p.country, 'Global') as country, count(*) as count
                ORDER BY count DESC, country
                """;
            
            try (Session session = driver.session()) {
                Result result = session.run(query);
                List<Map<String, Object>> countries = new ArrayList<>();
                
                while (result.hasNext()) {
                    Record record = result.next();
                    countries.add(Map.of(
                        "country", record.get("country").asString(),
                        "count", record.get("count").asInt()
                    ));
                }
                
                return Response.ok(Map.of(
                    "countries", countries,
                    "total_countries", countries.size()
                )).build();
            }
        } catch (Exception e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(Map.of("error", "Failed to retrieve provider countries", "message", e.getMessage()))
                    .build();
        }
    }

    private Map<String, Object> calculateProviderSummary(List<Map<String, Object>> providers) {
        // Group by type
        Map<String, Long> byType = providers.stream()
            .collect(java.util.stream.Collectors.groupingBy(
                p -> (String) p.get("type"),
                java.util.stream.Collectors.counting()
            ));
        
        // Group by country
        Map<String, Long> byCountry = providers.stream()
            .collect(java.util.stream.Collectors.groupingBy(
                p -> (String) p.get("country"),
                java.util.stream.Collectors.counting()
            ));
        
        return Map.of(
            "total_providers", providers.size(),
            "by_type", byType,
            "by_country", byCountry
        );
    }
}