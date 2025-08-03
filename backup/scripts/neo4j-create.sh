#!/bin/bash
set -euo pipefail

# Crear constraints e índices para el modelo normalizado de riesgos
echo "Creating Neo4j schema constraints and indexes..."

# Constraints únicos
cypher-shell -u neo4j -p test.password <<'CQL'
// Domain constraints
CREATE CONSTRAINT domain_fqdn IF NOT EXISTS FOR (d:Domain) REQUIRE d.fqdn IS UNIQUE;

// Service constraints (modelo normalizado)
CREATE CONSTRAINT service_name_type IF NOT EXISTS FOR (s:Service) REQUIRE (s.name, s.type) IS UNIQUE;

// Organization constraints
CREATE CONSTRAINT org_id IF NOT EXISTS FOR (o:Organization) REQUIRE o.id IS UNIQUE;

// Provider constraints
CREATE CONSTRAINT provider_id IF NOT EXISTS FOR (p:Provider) REQUIRE p.id IS UNIQUE;

// Certificate constraints
CREATE CONSTRAINT cert_serial IF NOT EXISTS FOR (c:Certificate) REQUIRE c.serial_number IS UNIQUE;

// IP constraints
CREATE CONSTRAINT ip_address IF NOT EXISTS FOR (i:IP) REQUIRE i.ip IS UNIQUE;

// ASN constraints
CREATE CONSTRAINT asn_number IF NOT EXISTS FOR (a:ASN) REQUIRE a.asn IS UNIQUE;

// Netblock constraints
CREATE CONSTRAINT netblock_cidr IF NOT EXISTS FOR (n:Netblock) REQUIRE n.cidr IS UNIQUE;

// Incident constraints
CREATE CONSTRAINT incident_id IF NOT EXISTS FOR (inc:Incident) REQUIRE inc.id IS UNIQUE;

// Indexes para consultas de rendimiento
CREATE INDEX service_type IF NOT EXISTS FOR (s:Service) ON (s.type);
CREATE INDEX service_category IF NOT EXISTS FOR (s:Service) ON (s.category);
CREATE INDEX service_provider IF NOT EXISTS FOR (s:Service) ON (s.provider_name);
CREATE INDEX domain_risk_score IF NOT EXISTS FOR (d:Domain) ON (d.risk_score);
CREATE INDEX domain_tld IF NOT EXISTS FOR (d:Domain) ON (d.tld);
CREATE INDEX incident_severity IF NOT EXISTS FOR (inc:Incident) ON (inc.severity);
CREATE INDEX incident_detected IF NOT EXISTS FOR (inc:Incident) ON (inc.detected);

CQL

echo "✅ Neo4j schema created with normalized Service model"
