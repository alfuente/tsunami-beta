#!/usr/bin/env python3
"""
Script para crear el nodo de configuración de pesos de riesgo en Neo4j
"""

from neo4j import GraphDatabase
import json
from datetime import datetime

def create_risk_configuration_node():
    """Crear nodo RiskConfiguration con pesos configurables"""
    driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "test.password"))
    
    with driver.session() as session:
        # Eliminar configuración existente si existe
        session.run("MATCH (rc:RiskConfiguration) DELETE rc")
        
        # Crear nueva configuración con pesos por defecto (25% cada uno)
        result = session.run("""
            CREATE (rc:RiskConfiguration {
                id: 'default',
                name: 'Default Risk Weights Configuration',
                
                // Pesos de los componentes de riesgo (deben sumar 1.0)
                base_risk_weight: 0.25,        // Riesgos base (tecnologías, servicios, TLS)
                subdomain_risk_weight: 0.25,   // Agregación de riesgos de subdominios
                dns_mx_risk_weight: 0.25,      // Riesgos de DNS/MX (nameservers, SPF, DMARC)
                provider_risk_weight: 0.25,    // Riesgos de proveedores de servicios
                
                // Configuración adicional
                max_risk_score: 100.0,
                min_risk_score: 0.0,
                
                // Factores de escalamiento para cada componente
                subdomain_aggregation_method: 'weighted_average',
                subdomain_critical_threshold: 80.0,
                
                // Configuración DNS/MX
                dns_nameserver_min_count: 2,
                dns_nameserver_optimal_count: 4,
                dns_security_weights_json: $dns_weights,
                
                // Configuración de proveedores  
                provider_risk_factors_json: $provider_factors,
                
                created_at: $timestamp,
                updated_at: $timestamp,
                active: true
            })
            RETURN rc.id as config_id
        """, 
        timestamp=datetime.now().isoformat(),
        dns_weights=json.dumps({
            'dnssec_enabled': 0.3,
            'spf_configured': 0.25,
            'dmarc_configured': 0.25,
            'mx_redundancy': 0.2
        }),
        provider_factors=json.dumps({
            'cloud_major': 0.1,      # AWS, Azure, GCP (bajo riesgo)
            'cloud_minor': 0.3,      # Proveedores menores
            'hosting_shared': 0.5,   # Hosting compartido
            'unknown_provider': 0.8  # Proveedor desconocido
        }))
        
        config_record = result.single()
        print(f"Created RiskConfiguration node: {config_record['config_id']}")
        
        # Crear índice único para el ID de configuración
        session.run("CREATE CONSTRAINT risk_config_id_unique IF NOT EXISTS FOR (rc:RiskConfiguration) REQUIRE rc.id IS UNIQUE")
        
        # Mostrar la configuración creada
        result = session.run("""
            MATCH (rc:RiskConfiguration {id: 'default'})
            RETURN rc
        """)
        
        config = result.single()['rc']
        print("\n=== Risk Configuration Created ===")
        print(f"Base Risk Weight: {config['base_risk_weight']} (25%)")
        print(f"Subdomain Risk Weight: {config['subdomain_risk_weight']} (25%)")
        print(f"DNS/MX Risk Weight: {config['dns_mx_risk_weight']} (25%)")
        print(f"Provider Risk Weight: {config['provider_risk_weight']} (25%)")
        print(f"Total Weight: {config['base_risk_weight'] + config['subdomain_risk_weight'] + config['dns_mx_risk_weight'] + config['provider_risk_weight']}")
        
    driver.close()

if __name__ == "__main__":
    create_risk_configuration_node()