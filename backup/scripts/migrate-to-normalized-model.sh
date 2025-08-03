#!/bin/bash
set -euo pipefail

echo "Migrating to normalized Service model..."

cypher-shell -u neo4j -p test <<'CQL'
// Step 1: Convert existing DNSServer nodes to Service nodes
MATCH (dns:DNSServer)
SET dns:Service
SET dns.type = 'DNS',
    dns.category = 'Infrastructure',
    dns.name = dns.hostname
REMOVE dns:DNSServer;

// Step 2: Convert USES_DNS relationships to DEPENDS_ON
MATCH (d:Domain)-[old:USES_DNS]->(svc:Service)
WHERE svc.type = 'DNS'
CREATE (d)-[:DEPENDS_ON {
  dependency_type: 'Critical',
  service_level: 'DNS', 
  record_type: 'NS',
  priority: 1
}]->(svc)
DELETE old;

// Step 3: Ensure all Service nodes have required properties
MATCH (s:Service)
WHERE s.provider_name IS NULL
SET s.provider_name = 'unknown';

MATCH (s:Service)
WHERE s.category IS NULL
SET s.category = CASE s.type
  WHEN 'DNS' THEN 'Infrastructure'
  WHEN 'Email' THEN 'Infrastructure'
  WHEN 'CDN' THEN 'Performance'
  WHEN 'Web' THEN 'Application'
  ELSE 'Infrastructure'
END;

// Step 4: Generate unique IDs for Service nodes that don't have them
MATCH (s:Service)
WHERE s.id IS NULL
SET s.id = toLower(s.type) + '_' + replace(s.name, '.', '_');

// Verification queries
MATCH (s:Service) RETURN s.type AS type, count(*) AS count ORDER BY type;
MATCH ()-[r:DEPENDS_ON]->(:Service) RETURN count(r) AS depends_on_relations;
MATCH ()-[r:USES_DNS]->() RETURN count(r) AS old_uses_dns_relations;

CQL

echo "✅ Migration to normalized Service model completed"
echo "   • All DNSServer nodes converted to Service with type='DNS'"
echo "   • All USES_DNS relationships converted to DEPENDS_ON"
echo "   • All Service nodes have required properties"