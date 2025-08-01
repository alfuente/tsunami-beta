#!/usr/bin/env python3
"""
Test simple para verificar que el análisis básico funciona
"""

import sys
import time
from subdomain_relationship_discovery_v4 import EnhancedSubdomainGraphIngester

def test_single_subdomain():
    """Test análisis de un solo subdominio"""
    
    # Configuración con TLS deshabilitado y timeouts cortos
    ingester = EnhancedSubdomainGraphIngester(
        neo4j_uri="bolt://localhost:7687",
        neo4j_user="neo4j", 
        neo4j_pass="test.password",
        ipinfo_token="0bf607ce2c13ac",
        enable_tls_analysis=False,  # TLS deshabilitado
        enable_service_detection=True,
        enable_provider_detection=True, 
        enable_industry_classification=True,
        tls_timeout=5,
        tls_retries=1
    )
    
    try:
        print("🔧 Inicializando constraints...")
        ingester.setup_constraints()
        
        print("📋 Analizando subdomain: www.bice.cl")
        
        with ingester.drv.session() as session:
            with session.begin_transaction() as tx:
                # Verificar que existe
                exists = tx.run("""
                    MATCH (s:Subdomain {fqdn: $fqdn})
                    RETURN s.fqdn as fqdn
                """, fqdn="www.bice.cl").single()
                
                if not exists:
                    print("❌ Subdomain www.bice.cl no existe en la base de datos")
                    return False
                
                print("✅ Subdomain encontrado, iniciando análisis...")
                
                # Ejecutar análisis
                start_time = time.time()
                results = ingester._perform_enhanced_subdomain_analysis("www.bice.cl", tx)
                duration = time.time() - start_time
                
                print(f"✅ Análisis completado en {duration:.2f}s")
                print(f"📊 Resultados: {results}")
                
                tx.commit()
                
        return True
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return False
    finally:
        ingester.close()

if __name__ == "__main__":
    print("=== TEST SIMPLE DE ANÁLISIS ===")
    success = test_single_subdomain()
    
    if success:
        print("\n✅ Test completado exitosamente!")
    else:
        print("\n❌ Test falló")
        sys.exit(1)