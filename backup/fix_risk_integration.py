#!/usr/bin/env python3
"""
Fix Risk Integration - Conecta Python risk calculator con Java backend
"""

from neo4j import GraphDatabase
import json
from datetime import datetime

class RiskIntegrationFixer:
    def __init__(self, neo4j_uri: str, neo4j_user: str, neo4j_pass: str):
        self.drv = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_pass))
    
    def calculate_and_update_domain_risk_scores(self):
        """Calcula risk scores desde Risk nodes y actualiza Domain/Subdomain."""
        
        with self.drv.session() as s:
            # Obtener todos los dominios con sus risks
            result = s.run("""
                MATCH (n)-[:AFFECTS]-(r:Risk)
                WHERE n:Domain OR n:Subdomain
                WITH n, collect(r) as risks
                RETURN n.fqdn as fqdn, labels(n)[0] as node_type, risks
            """)
            
            updates = 0
            for record in result:
                fqdn = record["fqdn"]
                node_type = record["node_type"]
                risks = record["risks"]
                
                # Calcular risk score agregado
                total_score = 0.0
                max_score = 0.0
                critical_count = 0
                high_count = 0
                
                for risk in risks:
                    score = risk.get("score", 0.0)
                    severity = risk.get("severity", "").upper()
                    
                    total_score += score
                    max_score = max(max_score, score)
                    
                    if severity in ["CRITICAL"]:
                        critical_count += 1
                    elif severity == "HIGH":
                        high_count += 1
                
                # Fórmula de agregación
                avg_score = total_score / len(risks) if risks else 0.0
                
                # Score ponderado: 60% max + 40% promedio
                final_score = (max_score * 0.6) + (avg_score * 0.4)
                
                # Aplicar multiplicadores por cantidad crítica
                if critical_count > 0:
                    final_score = min(100.0, final_score * (1 + critical_count * 0.1))
                elif high_count > 2:
                    final_score = min(100.0, final_score * 1.1)
                
                # Determinar risk tier
                risk_tier = self._get_risk_tier(final_score)
                
                # Actualizar el nodo
                s.run(f"""
                    MATCH (n:{node_type} {{fqdn: $fqdn}})
                    SET n.risk_score = $risk_score,
                        n.risk_tier = $risk_tier,
                        n.risk_details = $risk_details,
                        n.last_calculated = datetime()
                """, 
                fqdn=fqdn, 
                risk_score=final_score,
                risk_tier=risk_tier,
                risk_details=json.dumps({
                    "total_risks": len(risks),
                    "critical_risks": critical_count,
                    "high_risks": high_count,
                    "max_score": max_score,
                    "avg_score": avg_score,
                    "final_score": final_score
                }))
                
                updates += 1
                print(f"✓ Updated {node_type} {fqdn}: score={final_score:.1f}, tier={risk_tier}")
            
            return updates
    
    def fix_backend_queries_compatibility(self):
        """Crea relaciones de compatibilidad para queries del backend Java."""
        
        with self.drv.session() as s:
            # 1. Crear relaciones RUNS desde USES_SERVICE para compatibilidad
            result1 = s.run("""
                MATCH (n)-[:USES_SERVICE]->(p:Provider)
                WHERE n:Domain OR n:Subdomain
                WITH n, p
                MERGE (n)-[:RUNS]->(p)
                RETURN count(*) as created
            """)
            runs_created = result1.single()["created"]
            
            # 2. Crear alias IP para IPAddress
            result2 = s.run("""
                MATCH (ip:IPAddress)
                SET ip:IP
                RETURN count(*) as updated
            """)
            ip_updated = result2.single()["updated"]
            
            # 3. Crear relaciones SECURED_BY para certificados (mock)
            result3 = s.run("""
                MATCH (n) WHERE n:Domain OR n:Subdomain
                MERGE (c:Certificate {domain: n.fqdn})
                SET c.tls_grade = coalesce(n.tls_grade, 'Unknown'),
                    c.created_at = datetime()
                MERGE (n)-[:SECURED_BY]->(c)
                RETURN count(c) as created
            """)
            certs_created = result3.single()["created"]
            
            print(f"Backend compatibility fixes:")
            print(f"  - RUNS relationships: {runs_created}")
            print(f"  - IP labels added: {ip_updated}")
            print(f"  - Certificate relationships: {certs_created}")
    
    def update_provider_risk_scores(self):
        """Actualiza risk scores de providers basado en dominios que usan."""
        
        with self.drv.session() as s:
            result = s.run("""
                MATCH (p:Provider)<-[:USES_SERVICE]-(n)
                WHERE n:Domain OR n:Subdomain AND n.risk_score IS NOT NULL
                WITH p, collect(n.risk_score) as domain_scores
                WHERE size(domain_scores) > 0
                WITH p, domain_scores,
                     reduce(sum = 0.0, score IN domain_scores | sum + score) / size(domain_scores) as avg_risk,
                     reduce(max = 0.0, score IN domain_scores | CASE WHEN score > max THEN score ELSE max END) as max_risk
                SET p.risk_score = (avg_risk * 0.4) + (max_risk * 0.6),
                    p.risk_tier = CASE 
                        WHEN (avg_risk * 0.4) + (max_risk * 0.6) >= 80 THEN 'Critical'
                        WHEN (avg_risk * 0.4) + (max_risk * 0.6) >= 60 THEN 'High'
                        WHEN (avg_risk * 0.4) + (max_risk * 0.6) >= 40 THEN 'Medium'
                        ELSE 'Low'
                    END,
                    p.last_calculated = datetime()
                RETURN count(p) as updated
            """)
            
            updated = result.single()["updated"]
            print(f"✓ Updated risk scores for {updated} providers")
            return updated
    
    def _get_risk_tier(self, score: float) -> str:
        """Convierte score a tier."""
        if score >= 80:
            return "Critical"
        elif score >= 60:
            return "High"
        elif score >= 40:
            return "Medium"
        elif score >= 20:
            return "Low"
        else:
            return "Minimal"
    
    def close(self):
        self.drv.close()

def main():
    print("🔧 Fixing Risk Integration...")
    
    fixer = RiskIntegrationFixer("bolt://localhost:7687", "neo4j", "test.password")
    
    try:
        # 1. Calcular y actualizar risk scores
        print("\n1. Calculating domain risk scores from Risk nodes...")
        domain_updates = fixer.calculate_and_update_domain_risk_scores()
        print(f"   ✓ Updated {domain_updates} domains/subdomains")
        
        # 2. Fix backend compatibility
        print("\n2. Fixing backend query compatibility...")
        fixer.fix_backend_queries_compatibility()
        
        # 3. Update provider scores
        print("\n3. Updating provider risk scores...")
        provider_updates = fixer.update_provider_risk_scores()
        
        print(f"\n🎉 Risk integration fixed successfully!")
        print(f"   - Domain/Subdomain updates: {domain_updates}")
        print(f"   - Provider updates: {provider_updates}")
        
    finally:
        fixer.close()

if __name__ == "__main__":
    main()