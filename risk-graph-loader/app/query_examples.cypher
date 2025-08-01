// =============================================================================
// CONSULTAS CYPHER PARA SUBDOMINIOS Y DOMINIOS RELACIONADOS
// =============================================================================

// -----------------------------------------------------------------------------
// 1. OBTENER SUBDOMINIOS REALES Y DOMINIOS RELACIONADOS PARA UN DOMINIO
// -----------------------------------------------------------------------------

// Consulta completa con conteos
MATCH (d:Domain {fqdn: "banco.itau.cl"})
OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(s:Subdomain)
OPTIONAL MATCH (d)-[:DISCOVERED_RELATED]->(rd:RelatedDomain)
RETURN 
  d.fqdn as domain,
  collect(DISTINCT s.fqdn) as real_subdomains,
  collect(DISTINCT rd.fqdn) as related_domains,
  size(collect(DISTINCT s.fqdn)) as subdomain_count,
  size(collect(DISTINCT rd.fqdn)) as related_count;

// -----------------------------------------------------------------------------
// 2. SOLO SUBDOMINIOS REALES (HAS_SUBDOMAIN)
// -----------------------------------------------------------------------------

MATCH (d:Domain {fqdn: "banco.itau.cl"})-[:HAS_SUBDOMAIN]->(s:Subdomain)
RETURN 
  s.fqdn as subdomain,
  s.subdomain_parts as parts,
  s.discovered_by as discovery_method,
  s.created_at as created,
  s.processing_phase as processed
ORDER BY s.fqdn;

// -----------------------------------------------------------------------------
// 3. SOLO DOMINIOS RELACIONADOS (DISCOVERED_RELATED)
// -----------------------------------------------------------------------------

MATCH (d:Domain {fqdn: "banco.itau.cl"})-[r:DISCOVERED_RELATED]->(rd:RelatedDomain)
RETURN 
  rd.fqdn as related_domain,
  rd.base_domain as actual_base_domain,
  rd.discovery_source as source,
  rd.discovery_method as method,
  rd.discovery_context as context,
  rd.discovered_during_scan_of as original_scan,
  r.source as relationship_source,
  r.method as relationship_method,
  r.timestamp as discovered_at
ORDER BY rd.fqdn;

// -----------------------------------------------------------------------------
// 4. ANÁLISIS DE TIPOS DE DOMINIOS RELACIONADOS
// -----------------------------------------------------------------------------

// Clasificar dominios relacionados por tipo
MATCH (d:Domain {fqdn: "banco.itau.cl"})-[:DISCOVERED_RELATED]->(rd:RelatedDomain)
WITH rd,
  CASE 
    WHEN rd.fqdn CONTAINS "dns" OR rd.fqdn CONTAINS "ns" THEN "DNS Server"
    WHEN rd.fqdn CONTAINS "cdn" OR rd.fqdn CONTAINS "cloudflare" THEN "CDN Service"
    WHEN rd.fqdn CONTAINS "imperva" OR rd.fqdn CONTAINS "security" THEN "Security Service"
    WHEN rd.fqdn CONTAINS "amazonaws.com" OR rd.fqdn CONTAINS "azurewebsites" THEN "Cloud Service"
    WHEN rd.fqdn CONTAINS "google" OR rd.fqdn CONTAINS "gcp" THEN "Google Service"
    ELSE "Other"
  END as service_type
RETURN 
  service_type,
  count(*) as count,
  collect(rd.fqdn)[0..5] as examples
ORDER BY count DESC;

// -----------------------------------------------------------------------------
// 5. ESTADÍSTICAS GENERALES
// -----------------------------------------------------------------------------

// Obtener estadísticas completas para todos los dominios
MATCH (d:Domain)
OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(s:Subdomain)
OPTIONAL MATCH (d)-[:DISCOVERED_RELATED]->(rd:RelatedDomain)
RETURN 
  d.fqdn as domain,
  count(DISTINCT s) as real_subdomains,
  count(DISTINCT rd) as related_domains,
  count(DISTINCT s) + count(DISTINCT rd) as total_discovered
ORDER BY real_subdomains DESC;

// -----------------------------------------------------------------------------
// 6. BUSCAR DOMINIOS CON MUCHOS RELACIONADOS (POSIBLES HUBS)
// -----------------------------------------------------------------------------

MATCH (d:Domain)-[:DISCOVERED_RELATED]->(rd:RelatedDomain)
WITH d, count(rd) as related_count
WHERE related_count > 10
RETURN 
  d.fqdn as domain,
  related_count
ORDER BY related_count DESC;

// -----------------------------------------------------------------------------
// 7. DOMINIOS RELACIONADOS COMPARTIDOS (INFRAESTRUCTURA COMÚN)
// -----------------------------------------------------------------------------

// Encontrar dominios relacionados que aparecen en múltiples scans
MATCH (rd:RelatedDomain)<-[:DISCOVERED_RELATED]-(d:Domain)
WITH rd, collect(d.fqdn) as domains, count(d) as domain_count
WHERE domain_count > 1
RETURN 
  rd.fqdn as shared_related_domain,
  rd.base_domain as actual_base,
  domain_count,
  domains[0..5] as example_domains
ORDER BY domain_count DESC;

// -----------------------------------------------------------------------------
// 8. TIMELINE DE DESCUBRIMIENTOS
// -----------------------------------------------------------------------------

// Ver cuando se descubrieron los dominios (requiere timestamps)
MATCH (d:Domain {fqdn: "banco.itau.cl"})-[r:DISCOVERED_RELATED]->(rd:RelatedDomain)
WHERE r.timestamp IS NOT NULL
RETURN 
  rd.fqdn as related_domain,
  r.timestamp as discovered_at,
  rd.discovery_context as context
ORDER BY r.timestamp DESC;

// -----------------------------------------------------------------------------
// 9. LIMPIAR DOMINIOS RELACIONADOS (Si no los quieres)
// -----------------------------------------------------------------------------

// ¡CUIDADO! Esta consulta elimina TODOS los dominios relacionados
// MATCH (rd:RelatedDomain)
// DETACH DELETE rd;

// Eliminar solo los de un dominio específico
// MATCH (d:Domain {fqdn: "banco.itau.cl"})-[:DISCOVERED_RELATED]->(rd:RelatedDomain)
// DETACH DELETE rd;

// -----------------------------------------------------------------------------
// 10. CONSULTA COMBINADA PARA REPORTE COMPLETO
// -----------------------------------------------------------------------------

MATCH (d:Domain {fqdn: "banco.itau.cl"})
CALL {
  WITH d
  OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(s:Subdomain)
  RETURN count(s) as subdomain_count, collect(s.fqdn)[0..10] as subdomain_examples
}
CALL {
  WITH d  
  OPTIONAL MATCH (d)-[:DISCOVERED_RELATED]->(rd:RelatedDomain)
  RETURN count(rd) as related_count, collect(rd.fqdn)[0..10] as related_examples
}
RETURN 
  d.fqdn as domain,
  subdomain_count,
  related_count,
  subdomain_examples,
  related_examples;