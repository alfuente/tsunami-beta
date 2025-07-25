#!/usr/bin/env python3
"""
Configuración de emergencia para usar fallbacks cuando amass falla
"""

# Agregar esto al final de risk_loader_advanced3.py para forzar el uso de fallbacks

def run_discovery_with_reliable_fallback(domain: str, sample_mode: bool = False, 
                                        amass_timeout: int = None, amass_passive: bool = None) -> List[dict]:
    """Función de descubrimiento que prioriza métodos confiables."""
    
    print(f"[DISCOVERY] Starting reliable discovery for {domain}")
    
    # Intento 1: DNS Bruteforce (rápido y confiable)
    results = run_dns_bruteforce_fallback(domain)
    
    if results:
        print(f"[DISCOVERY] DNS bruteforce found {len(results)} subdomains for {domain}")
        
        # Si encontramos resultados con DNS, intenta también amass brevemente
        try:
            print(f"[DISCOVERY] Trying amass as secondary source...")
            amass_results = run_amass_local(domain, sample_mode=True, amass_timeout=20, amass_passive=True)
            
            # Combinar resultados únicos
            combined_results = results.copy()
            existing_names = {r.get('name', '') for r in results}
            
            for amass_result in amass_results:
                name = amass_result.get('name', '')
                if name and name not in existing_names:
                    combined_results.append(amass_result)
                    existing_names.add(name)
            
            if len(combined_results) > len(results):
                print(f"[DISCOVERY] Amass added {len(combined_results) - len(results)} additional subdomains")
            
            return combined_results
            
        except Exception as e:
            print(f"[DISCOVERY] Amass secondary attempt failed: {e}")
            return results
    
    # Si DNS bruteforce falla, intenta subfinder
    print(f"[DISCOVERY] DNS bruteforce failed, trying subfinder...")
    results = run_subfinder_fallback(domain, timeout=30)
    
    if results:
        return results
    
    # Si todo falla, intenta amass como último recurso
    print(f"[DISCOVERY] All fallbacks failed, trying amass as last resort...")
    return run_amass_local(domain, sample_mode, amass_timeout, amass_passive)


# Para usar esta configuración, reemplaza la función run_amass_with_fallback
# con run_discovery_with_reliable_fallback en el archivo principal