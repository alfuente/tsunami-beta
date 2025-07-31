#!/usr/bin/env python3
"""
Script para monitorear el progreso del procesamiento en background
"""

from neo4j import GraphDatabase
import os

def check_progress():
    print("📊 ESTADO DEL PROCESAMIENTO EN BACKGROUND")
    print("=" * 50)
    
    # Check if process is still running
    import subprocess
    try:
        result = subprocess.run(['pgrep', '-f', 'subdomain_relationship_discovery_v4.py'], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            pid = result.stdout.strip()
            print(f"✅ Proceso activo (PID: {pid})")
        else:
            print("❌ Proceso no está corriendo")
    except Exception as e:
        print(f"⚠️ Error verificando proceso: {e}")
    
    # Check database state
    try:
        with open('../../risk-graph-service/test.password', 'r') as f:
            password = f.read().strip()

        driver = GraphDatabase.driver('bolt://localhost:7687', auth=('neo4j', password))
        with driver.session() as session:
            # Node counts
            labels = ['Domain', 'Subdomain', 'Provider', 'Service', 'Certificate', 'Industry', 'RelatedDomain']
            print(f"\n📈 CONTEO DE NODOS:")
            for label in labels:
                result = session.run(f'MATCH (n:{label}) RETURN count(n) as count')
                count = result.single()['count']
                status = "🆕" if label in ['Provider', 'Service', 'Certificate', 'Industry'] and count > 0 else ""
                print(f"   {label}: {count} {status}")
            
            # Recent activity
            result = session.run('''
                MATCH (n)
                WHERE n.created_at > '2025-07-30T18:40:00'
                RETURN labels(n)[0] as type, count(n) as count
                ORDER BY count DESC
            ''')
            
            recent = list(result)
            if recent:
                print(f"\n🔄 ACTIVIDAD RECIENTE (después de 18:40):")
                for record in recent:
                    print(f"   {record['type']}: +{record['count']}")
            
        driver.close()
    except Exception as e:
        print(f"❌ Error consultando base de datos: {e}")
    
    # Check log file
    log_files = ['processing_small.log', 'processing.log']
    log_found = False
    
    for log_file in log_files:
        if os.path.exists(log_file):
            print(f"\n📝 ÚLTIMAS LÍNEAS DE {log_file}:")
            try:
                with open(log_file, 'r') as f:
                    lines = f.readlines()
                    for line in lines[-5:]:
                        print(f"   {line.strip()}")
                log_found = True
                break
            except Exception as e:
                print(f"   Error leyendo {log_file}: {e}")
    
    if not log_found:
        print(f"\n📝 No se encontraron archivos de log")

if __name__ == "__main__":
    check_progress()