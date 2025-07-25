# Backend Risk Graph Service - Fixes Needed

## Critical Query Fixes Required

### 1. GraphQueries.java - Line 109
**Current (BROKEN):**
```java
"AND NOT EXISTS((n)-[:RESOLVES_TO]->(:IPAddress)-[:HOSTED_BY]->(:Service)) "
```

**Fixed:**
```java
"AND NOT EXISTS((n)-[:RESOLVES_TO]->(:IPAddress)-[:HOSTED_BY]->(:Provider)) "
```

### 2. DomainResource.java - Line 359
**Current (BROKEN):**
```java
OPTIONAL MATCH (d)-[:RESOLVES_TO]->(ip:IP)-[:BELONGS_TO]->(asn:ASN)
```

**Fixed:**
```java
OPTIONAL MATCH (d)-[:RESOLVES_TO]->(ip:IPAddress)
OPTIONAL MATCH (ip)-[:HOSTED_BY]->(p:Provider)
```

### 3. DomainResource.java - Line 609
**Current (BROKEN):**
```java
OPTIONAL MATCH (d)-[:RUNS]->(ds:Service)
OPTIONAL MATCH (sub)-[:RUNS]->(ss:Service)
```

**Fixed:**
```java
OPTIONAL MATCH (d)-[:USES_SERVICE]->(dp:Provider)
OPTIONAL MATCH (sub)-[:USES_SERVICE]->(sp:Provider)
```

### 4. Provider Integration Query (NEW)
**Add to DomainResource.java:**
```java
// Get providers for domain/subdomain
OPTIONAL MATCH (d)-[:USES_SERVICE]->(p:Provider)
OPTIONAL MATCH (d)-[:RESOLVES_TO]->(ip:IPAddress)-[:HOSTED_BY]->(infra:Provider)
WITH d, collect(DISTINCT p) + collect(DISTINCT infra) as all_providers
```

## Risk Score Integration Fixes

### 1. RiskCalculator.java - Line 174
**Current (INCOMPLETE):**
```java
MATCH (d:Domain {fqdn: $fqdn})
OPTIONAL MATCH (d)-[:SECURED_BY]->(c:Certificate)
```

**Fixed to include Risk nodes:**
```java
MATCH (d:Domain {fqdn: $fqdn})
OPTIONAL MATCH (d)<-[:AFFECTS]-(r:Risk)
OPTIONAL MATCH (d)-[:SECURED_BY]->(c:Certificate)
WITH d, c, 
     CASE WHEN count(r) > 0 
          THEN reduce(sum = 0.0, risk IN collect(r) | sum + risk.score) / count(r)
          ELSE 0.0 END as calculated_risk_score,
     count(r) as risk_count
```

### 2. Add Risk Aggregation Method
**New method for RiskCalculator.java:**
```java
public double calculateRiskFromRiskNodes(String nodeId, String nodeType) {
    try (Session s = driver.session()) {
        Result result = s.run("""
            MATCH (n {fqdn: $nodeId})<-[:AFFECTS]-(r:Risk)
            WHERE (n:Domain OR n:Subdomain)
            RETURN 
                avg(r.score) as avg_score,
                max(r.score) as max_score,
                count(CASE WHEN r.severity = 'critical' THEN 1 END) as critical_count,
                count(CASE WHEN r.severity = 'high' THEN 1 END) as high_count,
                count(r) as total_risks
        """, Map.of("nodeId", nodeId));
        
        if (result.hasNext()) {
            Record record = result.next();
            double avgScore = record.get("avg_score").asDouble(0.0);
            double maxScore = record.get("max_score").asDouble(0.0);
            int criticalCount = record.get("critical_count").asInt(0);
            int highCount = record.get("high_count").asInt(0);
            
            // Weighted formula: 60% max + 40% average
            double baseScore = (maxScore * 0.6) + (avgScore * 0.4);
            
            // Apply multipliers for critical risks
            if (criticalCount > 0) {
                baseScore = Math.min(100.0, baseScore * (1 + criticalCount * 0.1));
            } else if (highCount > 2) {
                baseScore = Math.min(100.0, baseScore * 1.1);
            }
            
            return baseScore;
        }
        
        return 0.0;
    }
}
```

## Provider Risk Calculation

### Add Provider Risk Method to RiskCalculator.java:
```java
public double calculateProviderRisk(String providerId) {
    try (Session s = driver.session()) {
        Result result = s.run("""
            MATCH (p:Provider {name: $providerId})<-[:USES_SERVICE]-(n)
            WHERE (n:Domain OR n:Subdomain) AND n.risk_score IS NOT NULL
            RETURN 
                avg(n.risk_score) as avg_client_risk,
                max(n.risk_score) as max_client_risk,
                count(n) as client_count,
                p.type as provider_type
        """, Map.of("providerId", providerId));
        
        if (result.hasNext()) {
            Record record = result.next();
            double avgClientRisk = record.get("avg_client_risk").asDouble(0.0);
            double maxClientRisk = record.get("max_client_risk").asDouble(0.0);
            int clientCount = record.get("client_count").asInt(0);
            String providerType = record.get("provider_type").asString("");
            
            // Base risk from clients
            double baseRisk = (avgClientRisk * 0.4) + (maxClientRisk * 0.6);
            
            // Concentration risk
            double concentrationMultiplier = 1.0 + Math.log10(Math.max(1, clientCount)) * 0.1;
            
            // Provider type risk adjustment
            double typeMultiplier = switch (providerType) {
                case "Infrastructure" -> 1.2;  // Higher risk for infrastructure
                case "Service" -> 1.0;          // Normal risk for services
                default -> 1.1;                // Unknown providers slightly higher risk
            };
            
            return Math.min(100.0, baseRisk * concentrationMultiplier * typeMultiplier);
        }
        
        return 0.0;
    }
}
```

## UI Integration Points

### 1. API Response Enhancement
**Add to DomainResponse.java:**
```java
@JsonProperty("provider_summary")
private ProviderSummary providerSummary;

@JsonProperty("risk_breakdown")
private RiskBreakdown riskBreakdown;

public static class ProviderSummary {
    private List<String> infrastructureProviders;
    private List<String> serviceProviders;
    private double avgProviderRisk;
    private String highestRiskProvider;
    // getters/setters
}

public static class RiskBreakdown {
    private double calculatedFromRisks;
    private double baseInfrastructureScore;
    private double providerScore;
    private double combinedScore;
    private List<RiskDetail> individualRisks;
    // getters/setters
}
```

### 2. Dashboard Data Integration
**Update security-summary endpoint to include:**
```java
// Add provider risk distribution
OPTIONAL MATCH (p:Provider)
WHERE p.risk_score IS NOT NULL
RETURN 
    count(CASE WHEN p.risk_tier = 'Critical' THEN 1 END) as critical_providers,
    count(CASE WHEN p.risk_tier = 'High' THEN 1 END) as high_risk_providers,
    avg(p.risk_score) as avg_provider_risk
```

## Implementation Priority

1. **HIGH**: Fix basic query compatibility (IP vs IPAddress, Service vs Provider)
2. **HIGH**: Integrate Risk node calculations into domain/provider scores
3. **MEDIUM**: Add provider risk calculation methods
4. **MEDIUM**: Enhance API responses with risk breakdown
5. **LOW**: Update UI components to display provider risks

## Testing Commands

After implementing fixes:

```bash
# Test domain with risks
curl "http://localhost:8081/api/v1/domains/bice.cl"

# Test base domains with provider info
curl "http://localhost:8081/api/v1/domains/base-domains"

# Test base domain details with risk breakdown
curl "http://localhost:8081/api/v1/domains/base-domains/bice.cl/details?includeRiskBreakdown=true"
```