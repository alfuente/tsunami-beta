#!/bin/bash
set -euo pipefail

echo "Validating normalized Service model..."

cypher-shell -u neo4j -p test <<'CQL'
// Validation 1: Check for legacy DNSServer nodes
MATCH (dns:DNSServer)
RETURN 'ERROR: Found legacy DNSServer nodes' AS issue, count(dns) AS count
UNION
// Validation 2: Check for USES_DNS relationships  
MATCH ()-[r:USES_DNS]->()
RETURN 'ERROR: Found legacy USES_DNS relationships' AS issue, count(r) AS count
UNION
// Validation 3: Check Service nodes without type
MATCH (s:Service)
WHERE s.type IS NULL
RETURN 'WARNING: Service nodes without type' AS issue, count(s) AS count
UNION
// Validation 4: Check Service nodes without category
MATCH (s:Service) 
WHERE s.category IS NULL
RETURN 'WARNING: Service nodes without category' AS issue, count(s) AS count
UNION
// Validation 5: Summary of Service types
MATCH (s:Service)
RETURN 'INFO: Service distribution by type - ' + s.type AS issue, count(s) AS count
ORDER BY s.type;

CQL

echo ""
echo "Normalized model statistics:"

cypher-shell -u neo4j -p test <<'CQL'
// Total Service nodes by type
MATCH (s:Service)
RETURN s.type AS service_type, s.category AS category, count(*) AS count
ORDER BY service_type, category;

// DNS-specific services (should use DEPENDS_ON)
MATCH (d:Domain)-[r:DEPENDS_ON]->(s:Service)
WHERE s.type = 'DNS'
RETURN 'DNS Services via DEPENDS_ON' AS relation_type, count(r) AS count
UNION
// Email-specific services  
MATCH (d:Domain)-[r:DEPENDS_ON]->(s:Service)
WHERE s.type = 'Email'
RETURN 'Email Services via DEPENDS_ON' AS relation_type, count(r) AS count;

CQL

echo "✅ Model validation completed"