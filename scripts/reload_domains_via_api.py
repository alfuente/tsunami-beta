#!/usr/bin/env python3

import requests
import time
import json

def reload_domains_via_api():
    print("🔄 Forcing domain data reload via API...")
    
    # Subdominios importantes que sabemos tienen risk scores en Neo4j
    important_subdomains = [
        "www.bancochile.cl",
        "api.bancochile.cl", 
        "portal.bancochile.cl",
        "portalpersonas.bancochile.cl",
        "portalempresas.bancochile.cl",
        "login.bancochile.cl",
        "extranet.bancochile.cl",
        "mail.bancochile.cl",
        "servicios.bancochile.cl",
        "online.bancochile.cl"
    ]
    
    # 1. Forzar recálculo para asegurar sincronización
    print("\n⚖️ Step 1: Force recalculating risk scores...")
    for subdomain in important_subdomains:
        try:
            print(f"   🔄 Recalculating: {subdomain}")
            response = requests.post(
                f"http://localhost:8081/api/v1/calculations/domain/{subdomain}?force_recalculation=true",
                timeout=15
            )
            response.raise_for_status()
            result = response.json()
            print(f"     ✅ Status: {result.get('status')}, Nodes: {result.get('nodes_processed')}")
            time.sleep(1)
        except Exception as e:
            print(f"     ❌ Error: {e}")
    
    # 2. Verificar que los scores se actualizaron correctamente
    print("\n📊 Step 2: Verifying updated scores...")
    updated_count = 0
    
    for subdomain in important_subdomains:
        try:
            response = requests.get(f"http://localhost:8081/api/v1/domains/{subdomain}", timeout=10)
            response.raise_for_status()
            result = response.json()
            
            risk_score = result.get('risk_score', 0.0)
            risk_tier = result.get('risk_tier', 'Unknown')
            last_calculated = result.get('last_calculated')
            
            if risk_score > 0:
                updated_count += 1
                print(f"   ✅ {subdomain:<35} Score: {risk_score:<6} Tier: {risk_tier} Calc: {last_calculated[:19] if last_calculated else 'Never'}")
            else:
                print(f"   ❌ {subdomain:<35} Score: {risk_score} (not updated)")
                
        except Exception as e:
            print(f"   ❌ {subdomain}: Error getting data - {e}")
    
    print(f"\n📈 Total updated: {updated_count}/{len(important_subdomains)} subdomains")
    
    # 3. Verificar el árbol de dominios
    print("\n🌳 Step 3: Checking domain tree...")
    try:
        response = requests.get("http://localhost:8081/api/v1/domains/tree/bancochile.cl", timeout=15)
        response.raise_for_status()
        tree_data = response.json()
        
        print(f"   Total domains in tree: {tree_data.get('total_count', 0)}")
        
        # Buscar nuestros subdominios en el árbol
        found_with_scores = []
        for domain in tree_data.get('domain_tree', []):
            if domain['fqdn'] in important_subdomains and domain['risk_score'] > 0:
                found_with_scores.append(domain)
        
        print(f"   Found {len(found_with_scores)} of our subdomains with scores in tree:")
        for domain in found_with_scores:
            print(f"     {domain['fqdn']:<35} Score: {domain['risk_score']}")
        
        if len(found_with_scores) == 0:
            print("   ⚠️ WARNING: No subdomains with scores found in tree - cache issue?")
            
    except Exception as e:
        print(f"   ❌ Error checking tree: {e}")
    
    print("\n🎉 Domain reload process completed!")

if __name__ == "__main__":
    reload_domains_via_api()