#!/usr/bin/env python3
"""
Prueba simple de amass para verificar configuración
"""

from risk_loader_advanced3 import run_amass_local

def test_amass_configurations():
    """Prueba diferentes configuraciones de amass."""
    test_domain = "example.com"
    
    print("=== PRUEBA 1: Default (active, 120s) ===")
    results1 = run_amass_local(test_domain, sample_mode=False, amass_timeout=None, amass_passive=None)
    print(f"Resultados: {len(results1)}\n")
    
    print("=== PRUEBA 2: Passive mode, 30s ===")
    results2 = run_amass_local(test_domain, sample_mode=False, amass_timeout=30, amass_passive=True)
    print(f"Resultados: {len(results2)}\n")
    
    print("=== PRUEBA 3: Sample mode (passive, 15s) ===")
    results3 = run_amass_local(test_domain, sample_mode=True, amass_timeout=None, amass_passive=None)
    print(f"Resultados: {len(results3)}\n")
    
    print("=== PRUEBA 4: Custom timeout, force active ===")
    results4 = run_amass_local(test_domain, sample_mode=True, amass_timeout=60, amass_passive=False)
    print(f"Resultados: {len(results4)}\n")

if __name__ == "__main__":
    test_amass_configurations()