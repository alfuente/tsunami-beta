// PATCH: Fix base domain query to use correct relationships and grouping
// File: risk-graph-service/src/main/java/com/example/risk/resource/DomainResource.java
// Function: buildBaseDomainQuery

private String buildBaseDomainQuery(String riskTier, String businessCriticality, 
                                   Boolean monitoringEnabled, String search, String tld, int limit, int offset) {
    StringBuilder query = new StringBuilder("""
        // Step 1: Find actual base domains (domains without SUBDOMAIN_OF relationship)
        MATCH (base:Domain)
        WHERE NOT (base)-[:SUBDOMAIN_OF]->()
        
        // Step 2: Get base domain identifier correctly
        WITH base,
             CASE 
                 WHEN base.fqdn CONTAINS '.' THEN 
                     CASE 
                         WHEN size(split(base.fqdn, '.')) >= 2 THEN 
                             split(base.fqdn, '.')[-2] + '.' + split(base.fqdn, '.')[-1]
                         ELSE base.fqdn
                     END
                 ELSE base.fqdn
             END as base_domain_name
        WHERE 1=1
        """);
    
    if (riskTier != null && !riskTier.isEmpty()) {
        query.append(" AND base.risk_tier = '").append(riskTier).append("'");
    }
    
    if (businessCriticality != null && !businessCriticality.isEmpty()) {
        query.append(" AND base.business_criticality = '").append(businessCriticality).append("'");
    }
    
    if (monitoringEnabled != null) {
        query.append(" AND base.monitoring_enabled = ").append(monitoringEnabled);
    }
    
    if (search != null && !search.isEmpty()) {
        query.append(" AND base_domain_name CONTAINS '").append(search).append("'");
    }
    
    if (tld != null && !tld.isEmpty()) {
        query.append(" AND base_domain_name ENDS WITH '").append(tld).append("'");
    }
    
    query.append("""
        // Step 3: Get all subdomains for this base domain (using correct relationship)
        OPTIONAL MATCH (subdomain:Domain)-[:SUBDOMAIN_OF]->(base)
        
        // Step 4: Get services and providers
        OPTIONAL MATCH (base)-[:HAS_SERVICE]->(bs:Service)
        OPTIONAL MATCH (subdomain)-[:HAS_SERVICE]->(ss:Service) 
        OPTIONAL MATCH (base)-[:USES_PROVIDER]->(bp:Provider)
        OPTIONAL MATCH (subdomain)-[:USES_PROVIDER]->(sp:Provider)
        
        // Step 5: Group by base domain
        WITH base_domain_name, base,
             collect(DISTINCT subdomain) as subdomains,
             collect(DISTINCT bs.service) + collect(DISTINCT ss.service) as all_services,
             collect(DISTINCT bp.name) + collect(DISTINCT sp.name) as all_providers,
             coalesce(base.risk_score, 0.0) as base_risk_score,
             coalesce(base.business_criticality, 'Unknown') as business_criticality,
             coalesce(base.monitoring_enabled, false) as monitoring_enabled
        
        // Step 6: Calculate aggregated metrics
        WITH base_domain_name,
             size(subdomains) as subdomain_count,
             size([s in all_services WHERE s IS NOT NULL AND s <> '']) as service_count,
             size([p in all_providers WHERE p IS NOT NULL AND p <> '']) as provider_count,
             base_risk_score,
             [sub in subdomains WHERE sub.risk_score IS NOT NULL | sub.risk_score] as subdomain_risks,
             size([sub in subdomains WHERE sub.risk_tier = 'Critical']) as critical_subdomains,
             size([sub in subdomains WHERE sub.risk_tier = 'High']) as high_risk_subdomains,
             business_criticality, monitoring_enabled
        
        // Step 7: Calculate risk aggregations
        WITH base_domain_name, subdomain_count, service_count, provider_count,
             base_risk_score,
             CASE WHEN size(subdomain_risks) > 0 
                  THEN reduce(sum = 0.0, score IN subdomain_risks | sum + score) / size(subdomain_risks)
                  ELSE 0.0 END as avg_subdomain_risk,
             CASE WHEN size(subdomain_risks) > 0
                  THEN reduce(max = 0.0, score IN subdomain_risks | CASE WHEN score > max THEN score ELSE max END)
                  ELSE 0.0 END as max_subdomain_risk,
             critical_subdomains, high_risk_subdomains, business_criticality, monitoring_enabled
        
        // Step 8: Final aggregation  
        WITH base_domain_name, subdomain_count, service_count, provider_count,
             CASE WHEN avg_subdomain_risk > 0 AND base_risk_score > 0 
                  THEN (base_risk_score + avg_subdomain_risk) / 2 
                  WHEN avg_subdomain_risk > 0 THEN avg_subdomain_risk
                  ELSE base_risk_score END as avg_risk_score,
             CASE WHEN base_risk_score > max_subdomain_risk THEN base_risk_score ELSE max_subdomain_risk END as max_risk_score,
             critical_subdomains, high_risk_subdomains, business_criticality, monitoring_enabled
        
        RETURN base_domain_name as base_domain, 
               subdomain_count, service_count, provider_count, 
               avg_risk_score, max_risk_score,
               CASE 
                   WHEN max_risk_score >= 80 THEN 'Critical'
                   WHEN max_risk_score >= 60 THEN 'High'  
                   WHEN max_risk_score >= 40 THEN 'Medium'
                   ELSE 'Low'
               END as risk_tier,
               critical_subdomains, high_risk_subdomains, business_criticality, monitoring_enabled
        ORDER BY max_risk_score DESC
        """).append(" SKIP ").append(offset).append(" LIMIT ").append(limit);
    
    return query.toString();
}
