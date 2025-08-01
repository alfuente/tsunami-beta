// =============================================================================
// SCRIPT PARA CORREGIR DATOS DNS EXISTENTES
// =============================================================================

// Opción 1: Establecer campos DNS vacíos para nodos existentes (Recomendado)
// Esto evita el warning y permite que el discovery funcione
MATCH (n)
WHERE n:Domain OR n:Subdomain
SET n.dns_cname_records = COALESCE(n.dns_cname_records, []),
    n.dns_a_records = COALESCE(n.dns_a_records, []),
    n.dns_aaaa_records = COALESCE(n.dns_aaaa_records, []),
    n.dns_mx_records = COALESCE(n.dns_mx_records, []),
    n.dns_txt_records = COALESCE(n.dns_txt_records, []),
    n.dns_ns_records = COALESCE(n.dns_ns_records, []);

// Verificar que se aplicaron los cambios
MATCH (n)
WHERE n:Domain OR n:Subdomain
RETURN labels(n)[0] as node_type, 
       count(*) as count,
       count(n.dns_cname_records) as with_cname_field
ORDER BY node_type;

// Opción 2: Si quieres empezar de cero (¡CUIDADO! Elimina todos los datos)
// MATCH (n)
// WHERE n:Domain OR n:Subdomain OR n:RelatedDomain
// DETACH DELETE n;

// Opción 3: Solo eliminar nodos sin análisis DNS completo
// MATCH (s:Subdomain)
// WHERE s.dns_analyzed_at IS NULL
// DETACH DELETE s;

// =============================================================================
// CONSULTAS DE VERIFICACIÓN POST-FIX
// =============================================================================

// Ver cuántos nodos tienen campos DNS
MATCH (n)
WHERE n:Domain OR n:Subdomain
RETURN labels(n)[0] as type,
       count(*) as total,
       count(n.dns_cname_records) as with_cname,
       count(n.dns_a_records) as with_a_records
ORDER BY type;

// Ver ejemplos de registros CNAME
MATCH (n)
WHERE n:Domain OR n:Subdomain AND size(n.dns_cname_records) > 0
RETURN n.fqdn as domain, n.dns_cname_records as cnames
LIMIT 10;

// Probar la consulta que antes fallaba
MATCH (n) WHERE n:Domain OR n:Subdomain
RETURN n.fqdn as fqdn, 
       COALESCE(n.dns_cname_records, []) as cnames
LIMIT 5;