// Tsunami Beta - Domain Cleanup Script
// Generated on 2025-08-25T12:43:45.107948
// This script cleans up duplicate Domain nodes that should be Subdomains

// IMPORTANT: Review this script before execution!

// === MANUAL REVIEW REQUIRED ===
// These nodes have complex relationships and need manual review

// Manual review needed: api.bancochile.cl
// Manual review needed: extranet.bancochile.cl
// Manual review needed: login.bancochile.cl
// Manual review needed: mail.bancochile.cl
// Manual review needed: online.bancochile.cl
// Manual review needed: portal.bancochile.cl
// Manual review needed: portalempresas.bancochile.cl
// Manual review needed: portalpersonas.bancochile.cl
// Manual review needed: servicios.bancochile.cl
// Manual review needed: www.bancochile.cl

// === VERIFICATION QUERIES ===
// Run these after cleanup to verify results

// Check remaining duplicates
MATCH (d:Domain), (s:Subdomain) WHERE d.fqdn = s.fqdn RETURN count(*) as remaining_duplicates;

// Check orphaned relationships
MATCH (n) WHERE NOT EXISTS{(n)--(:Domain|:Subdomain)} AND NOT n:Domain AND NOT n:Subdomain RETURN labels(n), count(*);