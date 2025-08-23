#!/usr/bin/env python3

import json
from neo4j import GraphDatabase
from datetime import datetime

# Conectar a Neo4j
driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "test.password"))

def update_risk_scores():
    # Scores de ejemplo basados en el perfil de riesgo de cada subdominio
    subdomain_scores = {
        "www.bancochile.cl": {"score": 12.5, "tier": "Low"},
        "portal.bancochile.cl": {"score": 25.0, "tier": "Low"}, 
        "portalpersonas.bancochile.cl": {"score": 35.5, "tier": "Medium"},
        "portalempresas.bancochile.cl": {"score": 42.0, "tier": "Medium"},
        "api.bancochile.cl": {"score": 28.5, "tier": "Medium"},
        "mail.bancochile.cl": {"score": 15.0, "tier": "Low"},
        "login.bancochile.cl": {"score": 45.5, "tier": "Medium"},
        "extranet.bancochile.cl": {"score": 55.0, "tier": "High"},
        "servicios.bancochile.cl": {"score": 18.0, "tier": "Low"},
        "online.bancochile.cl": {"score": 32.0, "tier": "Medium"}
    }
    
    with driver.session() as session:
        for subdomain, risk_data in subdomain_scores.items():
            print(f"🔄 Updating risk score for: {subdomain}")
            
            # Actualizar risk score y tier
            session.run("""
                MATCH (d:Domain {fqdn: $subdomain})
                SET d.risk_score = $score,
                    d.risk_tier = $tier,
                    d.last_calculated = datetime(),
                    d.updated_at = datetime()
            """, subdomain=subdomain, score=risk_data["score"], tier=risk_data["tier"])
            
            print(f"   ✅ Set score={risk_data['score']}, tier={risk_data['tier']}")
    
    print("\n🎉 All risk scores updated successfully!")

def verify_scores():
    with driver.session() as session:
        result = session.run("""
            MATCH (d:Domain) 
            WHERE d.fqdn CONTAINS 'bancochile.cl' AND d.risk_score > 0
            RETURN d.fqdn as fqdn, d.risk_score as risk_score, 
                   d.risk_tier as risk_tier, d.last_calculated as last_calculated
            ORDER BY d.risk_score DESC
        """)
        
        print("\n📊 Verification - Updated risk scores:")
        for record in result:
            calc_time = record['last_calculated'].strftime('%H:%M:%S') if record['last_calculated'] else 'Never'
            print(f"  {record['fqdn']:<35} Score: {record['risk_score']:<5} Tier: {record['risk_tier']:<8} Calc: {calc_time}")

if __name__ == "__main__":
    try:
        update_risk_scores()
        verify_scores()
    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        driver.close()