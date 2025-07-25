#!/usr/bin/env python3
"""
Script de prueba para verificar que Amass se prioriza correctamente
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from risk_loader_advanced3 import run_amass_with_fallback

def test_amass_priority():
    """Prueba la función modificada para verificar priorización de Amass"""
    
    # Dominio de prueba
    test_domain = "bancochile.cl"
    
    print(f"🔍 Testing Amass priority for domain: {test_domain}")
    print("="*60)
    
    # Ejecutar descubrimiento con configuración específica
    results = run_amass_with_fallback(
        domain=test_domain,
        sample_mode=True,  # Modo rápido para testing
        amass_timeout=30,  # 30 segundos timeout
        amass_passive=True  # Solo modo pasivo para ser gentil
    )
    
    print("\n" + "="*60)
    print(f"📊 Results for {test_domain}:")
    print(f"   Total subdomains found: {len(results)}")
    
    if results:
        print("   Discovered subdomains:")
        for i, result in enumerate(results[:10], 1):  # Solo mostrar primeros 10
            name = result.get('name', 'Unknown')
            source = result.get('source', 'Unknown')
            print(f"   {i:2d}. {name} (source: {source})")
        
        if len(results) > 10:
            print(f"   ... and {len(results) - 10} more")
    else:
        print("   No subdomains found")
    
    print("="*60)
    print("✅ Test completed - Check logs above to verify Amass was tried first")
    
    return results

if __name__ == "__main__":
    test_amass_priority()