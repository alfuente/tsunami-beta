# Neo4j Graph Data Model Documentation

## Overview

This document describes the complete graph data model used by the Tsunami domain analysis system. The graph stores detailed information about domains, their subdomains, technologies, providers, services, certificates, and security relationships.

## Node Types

### Core Domain Nodes

#### Domain
Represents base domains in the system.

**Labels**: `Domain`

**Properties**:
```cypher
CREATE (d:Domain {
    fqdn: "example.com",              // Fully Qualified Domain Name (required, unique)
    base_domain: "example.com",       // Base domain reference
    tld: "com",                       // Top Level Domain
    risk_score: 25.0,                 // Calculated risk score (0-100)
    risk_level: "Medium",             // Risk categorization
    last_updated: datetime(),         // Last analysis timestamp
    has_spf: true,                    // SPF record present
    has_dmarc: true,                  // DMARC record present
    has_dkim: true,                   // DKIM record present
    spf_record: "v=spf1 ...",         // SPF record content
    dmarc_record: "v=DMARC1 ...",     // DMARC record content
    dns_records: "{...}",             // JSON string of DNS records
    mx_records: "[...]"               // JSON array of MX records
})
```

**Indexes and Constraints**:
```cypher
CREATE CONSTRAINT domain_fqdn_unique IF NOT EXISTS FOR (d:Domain) REQUIRE d.fqdn IS UNIQUE;
CREATE INDEX domain_base_domain IF NOT EXISTS FOR (d:Domain) ON (d.base_domain);
CREATE INDEX domain_risk_score IF NOT EXISTS FOR (d:Domain) ON (d.risk_score);
CREATE INDEX domain_tld IF NOT EXISTS FOR (d:Domain) ON (d.tld);
```

#### Subdomain
Represents subdomains discovered for each base domain.

**Labels**: `Subdomain`

**Properties**:
```cypher
CREATE (s:Subdomain {
    fqdn: "api.example.com",          // Full subdomain name (required, unique)
    base_domain: "example.com",       // Parent domain reference
    subdomain_part: "api",            // Subdomain component only
    risk_score: 15.0,                 // Calculated risk score
    risk_level: "Low",                // Risk categorization
    last_updated: datetime(),         // Last analysis timestamp
    is_active: true,                  // Whether subdomain is currently active
    response_time: 150,               // Response time in milliseconds
    http_status: 200,                 // HTTP response status
    https_enabled: true,              // HTTPS availability
    dns_records: "{...}",             // DNS resolution data
    discovery_method: "amass"         // How subdomain was discovered
})
```

### Infrastructure Nodes

#### Provider
Represents service providers, CDNs, hosting companies, etc.

**Labels**: `Provider`

**Properties**:
```cypher
CREATE (p:Provider {
    name: "AWS CloudFront",           // Provider name (required, unique)
    type: "cdn",                      // Provider category
    country: "US",                    // Country of operation
    asn: 16509,                       // Autonomous System Number
    confidence: 0.95,                 // Detection confidence (0-1)
    metadata: "{...}",                // Additional provider metadata
    risk_factor: 0.1,                 // Risk multiplier for this provider
    last_updated: datetime()          // Last information update
})
```

**Provider Types**:
- `cdn` - Content Delivery Networks
- `hosting` - Hosting providers
- `dns` - DNS service providers
- `analytics` - Analytics platforms
- `social_media` - Social media platforms
- `infrastructure` - Cloud infrastructure
- `security` - Security services
- `other` - Other services

#### Service
Represents running services discovered on domains/subdomains.

**Labels**: `Service`

**Properties**:
```cypher
CREATE (s:Service {
    name: "HTTP",                     // Service name
    port: 80,                         // Service port
    protocol: "tcp",                  // Protocol used
    version: "Apache/2.4.41",        // Service version if detected
    banner: "Apache/2.4.41 ...",     // Service banner
    domain: "example.com",            // Associated domain
    status: "open",                   // Service status
    last_scan: datetime(),            // Last scan timestamp
    confidence: 0.9                   // Detection confidence
})
```

#### Technology
Represents web technologies detected on domains.

**Labels**: `Technology`

**Properties**:
```cypher
CREATE (t:Technology {
    name: "Apache HTTP Server",       // Technology name (required)
    category: "web-servers",          // Technology category
    website: "https://apache.org",    // Official website
    icon: "apache.png",               // Icon filename
    confidence: 90,                   // Detection confidence (0-100)
    risk_level: "Low",                // Associated risk level
    cpe: "cpe:2.3:a:apache:http_server:*" // CPE identifier if available
})
```

#### TechnologyVersion
Represents specific versions of technologies.

**Labels**: `TechnologyVersion`

**Properties**:
```cypher
CREATE (tv:TechnologyVersion {
    version: "2.4.41",                // Version string
    release_date: date("2019-08-14"), // Release date
    is_latest: false,                 // Is this the latest version
    is_supported: true,               // Is this version still supported
    vulnerability_count: 3,           // Known vulnerabilities
    risk_score: 15.0,                 // Version-specific risk score
    confidence: 95                    // Detection confidence
})
```

### Security Nodes

#### Certificate
Represents SSL/TLS certificates.

**Labels**: `Certificate`

**Properties**:
```cypher
CREATE (c:Certificate {
    serial_number: "03:d5:...",       // Certificate serial number
    subject: "CN=example.com",        // Certificate subject
    issuer: "Let's Encrypt",          // Certificate issuer
    valid_from: datetime("2024-01-01T00:00:00Z"), // Validity start
    valid_to: datetime("2024-04-01T00:00:00Z"),   // Validity end
    fingerprint_sha256: "abc123...",  // SHA256 fingerprint
    key_size: 2048,                   // Key size in bits
    signature_algorithm: "SHA256-RSA", // Signature algorithm
    is_expired: false,                // Expiration status
    is_self_signed: false,            // Self-signed flag
    alt_names: ["*.example.com"],     // Subject alternative names
    risk_score: 5.0                   // Certificate risk score
})
```

#### Vulnerability
Represents security vulnerabilities.

**Labels**: `Vulnerability`

**Properties**:
```cypher
CREATE (v:Vulnerability {
    cve_id: "CVE-2021-44228",         // CVE identifier
    title: "Log4j RCE",              // Vulnerability title
    description: "Remote code execution...", // Description
    severity: "Critical",             // CVSS severity
    cvss_score: 9.8,                  // CVSS base score
    cvss_vector: "CVSS:3.1/AV:N/...", // CVSS vector
    published_date: date("2021-12-10"), // Publication date
    modified_date: date("2021-12-15"),   // Last modification
    cwe_id: "CWE-502",                // CWE identifier
    references: ["https://..."]       // Reference URLs
})
```

### Supporting Nodes

#### Organization
Represents organizations associated with certificates.

**Labels**: `Organization`

**Properties**:
```cypher
CREATE (o:Organization {
    name: "Example Corp",             // Organization name
    country: "US",                    // Country
    locality: "San Francisco",       // City/locality
    state: "California",             // State/province
    unit: "IT Department"            // Organizational unit
})
```

#### DNSServer
Represents DNS servers used by domains.

**Labels**: `DNSServer`

**Properties**:
```cypher
CREATE (dns:DNSServer {
    server: "ns1.example.com",        // DNS server hostname
    ip: "1.2.3.4",                    // IP address
    type: "authoritative",            // DNS server type
    response_time: 45                 // Response time in ms
})
```

## Relationships

### Domain Relationships

#### HAS_SUBDOMAIN
Connects domains to their subdomains.

```cypher
CREATE (d:Domain)-[r:HAS_SUBDOMAIN {
    discovered_date: datetime(),      // When subdomain was found
    discovery_method: "amass",        // How it was discovered
    confidence: 0.9                   // Discovery confidence
}]->(s:Subdomain)
```

#### RESOLVES_TO
Connects domains to IP addresses.

```cypher
CREATE (d:Domain)-[r:RESOLVES_TO {
    record_type: "A",                 // DNS record type (A, AAAA, CNAME)
    ttl: 3600,                        // DNS TTL
    last_resolved: datetime()         // Last resolution time
}]->(ip:IPAddress)
```

### Service Relationships

#### RUNS_SERVICE
Connects domains to services running on them.

```cypher
CREATE (d:Domain)-[r:RUNS_SERVICE {
    scan_date: datetime(),            // When service was scanned
    scan_method: "nmap",              // Scanning method used
    confidence: 0.95                  // Detection confidence
}]->(s:Service)
```

#### USES_PROVIDER
Connects domains to service providers.

```cypher
CREATE (d:Domain)-[r:USES_PROVIDER {
    usage_type: "hosting",            // Type of service used
    detected_date: datetime(),        // When provider was detected
    confidence: 0.8,                  // Detection confidence
    method: "dns_analysis"            // Detection method
}]->(p:Provider)
```

### Technology Relationships

#### USES_TECHNOLOGY
Connects domains to technologies they use.

```cypher
CREATE (d:Domain)-[r:USES_TECHNOLOGY {
    detected_date: datetime(),        // Detection timestamp
    detection_method: "http_headers", // How technology was detected
    confidence: 85,                   // Detection confidence (0-100)
    category: "web-servers",          // Technology category
    version: "2.4.41"                 // Detected version
}]->(t:Technology)
```

#### USES_TECHNOLOGY_VERSION
Connects domains to specific technology versions.

```cypher
CREATE (d:Domain)-[r:USES_TECHNOLOGY_VERSION {
    detected_date: datetime(),        // Detection timestamp
    confidence: 90,                   // Detection confidence
    method: "banner_analysis"         // Detection method
}]->(tv:TechnologyVersion)
```

#### IS_VERSION_OF
Connects technology versions to their parent technologies.

```cypher
CREATE (tv:TechnologyVersion)-[r:IS_VERSION_OF]->(t:Technology)
```

### Security Relationships

#### SECURED_BY
Connects domains to their SSL certificates.

```cypher
CREATE (d:Domain)-[r:SECURED_BY {
    protocol: "TLS 1.3",             // TLS protocol version
    cipher_suite: "TLS_AES_256_...", // Cipher suite used
    scan_date: datetime(),            // When certificate was scanned
    is_valid: true,                   // Certificate validity
    trust_level: "trusted"            // Trust assessment
}]->(c:Certificate)
```

#### ISSUED_BY
Connects certificates to their issuing organizations.

```cypher
CREATE (c:Certificate)-[r:ISSUED_BY {
    issue_date: datetime(),           // Issuance date
    trust_level: "ca_trusted"        // CA trust level
}]->(o:Organization)
```

## Complex Queries Examples

### Risk Analysis Queries

```cypher
// Find high-risk domains with their technologies and vulnerabilities
MATCH (d:Domain)-[:USES_TECHNOLOGY]->(t:Technology)-[:HAS_VULNERABILITY]->(v:Vulnerability)
WHERE d.risk_score > 70 AND v.severity = "Critical"
RETURN d.fqdn, d.risk_score, t.name, v.cve_id, v.cvss_score
ORDER BY d.risk_score DESC
```

### Provider Analysis Queries

```cypher
// Analyze provider usage patterns
MATCH (d:Domain)-[r:USES_PROVIDER]->(p:Provider)
WITH p, COUNT(d) as domain_count, COLLECT(d.fqdn) as domains
RETURN p.name, p.type, p.country, domain_count, domains[0..5] as sample_domains
ORDER BY domain_count DESC
```

### Technology Stack Analysis

```cypher
// Find complete technology stacks for domains
MATCH (d:Domain)-[:USES_TECHNOLOGY]->(t:Technology)
WITH d, COLLECT(t.name) as tech_stack
WHERE SIZE(tech_stack) > 5
RETURN d.fqdn, d.risk_score, tech_stack
ORDER BY SIZE(tech_stack) DESC
```

### Certificate Security Analysis

```cypher
// Find domains with expiring or weak certificates
MATCH (d:Domain)-[:SECURED_BY]->(c:Certificate)
WHERE c.valid_to < datetime() + duration("P30D") 
   OR c.key_size < 2048
   OR c.is_self_signed = true
RETURN d.fqdn, c.valid_to, c.key_size, c.is_self_signed, c.issuer
ORDER BY c.valid_to ASC
```

### Subdomain Risk Propagation

```cypher
// Analyze risk propagation from base domains to subdomains
MATCH (d:Domain)-[:HAS_SUBDOMAIN]->(s:Subdomain)
WHERE d.risk_score > 50
RETURN d.fqdn as base_domain, 
       d.risk_score as base_risk,
       COUNT(s) as subdomain_count,
       AVG(s.risk_score) as avg_subdomain_risk,
       COLLECT(s.fqdn)[0..10] as sample_subdomains
ORDER BY base_risk DESC
```

## Data Flow and Updates

### Incremental Updates
The graph supports incremental updates where:
1. New domains are added without affecting existing data
2. Technology detection updates existing relationships
3. Certificate information is refreshed on schedule
4. Risk scores are recalculated based on graph changes

### Data Consistency
- All timestamps use UTC timezone
- Risk scores are normalized to 0-100 scale
- Confidence values use 0-1 scale for relationships, 0-100 for nodes
- All string comparisons are case-insensitive

## Performance Considerations

### Indexes for Query Performance
```cypher
// Essential indexes for fast queries
CREATE INDEX domain_fqdn_index IF NOT EXISTS FOR (d:Domain) ON (d.fqdn);
CREATE INDEX subdomain_fqdn_index IF NOT EXISTS FOR (s:Subdomain) ON (s.fqdn);
CREATE INDEX technology_name_index IF NOT EXISTS FOR (t:Technology) ON (t.name);
CREATE INDEX provider_name_index IF NOT EXISTS FOR (p:Provider) ON (p.name);
CREATE INDEX certificate_fingerprint_index IF NOT EXISTS FOR (c:Certificate) ON (c.fingerprint_sha256);
```

### Query Optimization
- Use `LIMIT` clauses for large result sets
- Leverage relationship direction for better performance
- Consider graph algorithms for complex analysis
- Use periodic commits for bulk operations

## Extension Points

The graph model is designed to be extensible:
- New node types can be added for additional data sources
- Relationship properties can be extended with metadata
- Custom risk calculation algorithms can use graph traversals
- Integration with external threat intelligence sources

This model provides comprehensive coverage of domain security analysis while maintaining flexibility for future enhancements.