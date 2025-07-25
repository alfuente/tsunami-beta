#!/usr/bin/env python3
"""
Diagnóstico de configuración de Amass para troubleshooting
"""

import subprocess
import tempfile
from pathlib import Path
import shutil

def check_amass_installation():
    """Verifica si amass está instalado y accesible."""
    print("=== DIAGNÓSTICO DE AMASS ===\n")
    
    # Check if amass is in PATH
    amass_path = shutil.which("amass")
    if amass_path:
        print(f"✅ Amass encontrado en: {amass_path}")
    else:
        print("❌ Amass NO encontrado en PATH")
        return False
    
    # Check amass version
    try:
        result = subprocess.run(["amass", "-version"], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            print(f"✅ Versión de Amass: {result.stdout.strip()}")
        else:
            print(f"⚠️  Error obteniendo versión: {result.stderr}")
    except Exception as e:
        print(f"❌ Error ejecutando amass -version: {e}")
        return False
    
    return True

def test_amass_basic():
    """Prueba básica de amass con un dominio conocido."""
    print("\n=== PRUEBA BÁSICA DE AMASS ===")
    
    test_domain = "example.com"
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "test_out.txt"
        
        # Comando básico de prueba
        cmd = [
            "amass", "enum", 
            "-d", test_domain, 
            "-o", str(out),
            "-timeout", "10",
            "-passive"
        ]
        
        print(f"Ejecutando: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(
                cmd, 
                capture_output=True,
                timeout=15,
                text=True
            )
            
            print(f"Return code: {result.returncode}")
            print(f"STDOUT: {result.stdout}")
            print(f"STDERR: {result.stderr}")
            
            if out.exists():
                content = out.read_text().strip()
                print(f"Archivo de salida existe, contenido ({len(content)} chars):")
                if content:
                    lines = content.split('\n')[:5]  # Primeras 5 líneas
                    for i, line in enumerate(lines, 1):
                        print(f"  {i}: {line}")
                    if len(content.split('\n')) > 5:
                        print(f"  ... (+{len(content.split('\n')) - 5} líneas más)")
                else:
                    print("  (archivo vacío)")
            else:
                print("❌ Archivo de salida no fue creado")
                
        except subprocess.TimeoutExpired:
            print("⏰ Timeout en ejecución de amass")
        except Exception as e:
            print(f"❌ Error ejecutando amass: {e}")

def test_amass_with_script_params():
    """Prueba con los parámetros que usa el script actual."""
    print("\n=== PRUEBA CON PARÁMETROS DEL SCRIPT ===")
    
    test_domain = "bice.cl"
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "script_test_out.txt"
        
        # Comando igual al del script
        cmd = [
            "amass", "enum", 
            "-d", test_domain, 
            "-o", str(out),
            "-max-dns-queries", "20",
            "-max-depth", "1",
            "-r", "8.8.8.8,1.1.1.1,9.9.9.9",
            "-timeout", "60",
            "-passive",
            "-exclude", "crtsh,dnsdumpster,hackertarget,threatcrowd,virustotal"
        ]
        
        print(f"Ejecutando: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(
                cmd, 
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                timeout=70,
                text=True
            )
            
            print(f"Return code: {result.returncode}")
            print(f"STDERR: {result.stderr}")
            
            if out.exists():
                content = out.read_text().strip()
                print(f"Archivo de salida existe, contenido ({len(content)} chars):")
                if content:
                    lines = content.split('\n')[:10]  # Primeras 10 líneas
                    for i, line in enumerate(lines, 1):
                        print(f"  {i}: {line}")
                    if len(content.split('\n')) > 10:
                        print(f"  ... (+{len(content.split('\n')) - 10} líneas más)")
                else:
                    print("  (archivo vacío)")
                    
                # Analizar por qué puede estar vacío
                print("\n=== ANÁLISIS DEL ARCHIVO VACÍO ===")
                print("Posibles causas:")
                print("1. El dominio no tiene subdominios públicos detectables")
                print("2. Las fuentes pasivas están bloqueadas/limitadas")
                print("3. El timeout es muy corto")
                print("4. Problemas de red/DNS")
                
            else:
                print("❌ Archivo de salida no fue creado")
                
        except subprocess.TimeoutExpired:
            print("⏰ Timeout en ejecución de amass")
            if out.exists():
                content = out.read_text().strip()
                print(f"Resultados parciales ({len(content)} chars): {content[:200]}...")
        except Exception as e:
            print(f"❌ Error ejecutando amass: {e}")

def test_active_mode():
    """Prueba en modo activo para comparar."""
    print("\n=== PRUEBA EN MODO ACTIVO ===")
    
    test_domain = "bice.cl"
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "active_test_out.txt"
        
        # Comando en modo activo (sin -passive)
        cmd = [
            "amass", "enum", 
            "-d", test_domain, 
            "-o", str(out),
            "-max-dns-queries", "20",
            "-max-depth", "1",
            "-r", "8.8.8.8,1.1.1.1,9.9.9.9",
            "-timeout", "30"
        ]
        
        print(f"Ejecutando: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(
                cmd, 
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                timeout=40,
                text=True
            )
            
            print(f"Return code: {result.returncode}")
            print(f"STDERR: {result.stderr}")
            
            if out.exists():
                content = out.read_text().strip()
                print(f"Archivo de salida existe, contenido ({len(content)} chars):")
                if content:
                    lines = content.split('\n')[:10]  # Primeras 10 líneas
                    for i, line in enumerate(lines, 1):
                        print(f"  {i}: {line}")
                    if len(content.split('\n')) > 10:
                        print(f"  ... (+{len(content.split('\n')) - 10} líneas más)")
                else:
                    print("  (archivo vacío)")
            else:
                print("❌ Archivo de salida no fue creado")
                
        except subprocess.TimeoutExpired:
            print("⏰ Timeout en ejecución de amass")
            if out.exists():
                content = out.read_text().strip()
                print(f"Resultados parciales ({len(content)} chars): {content[:200]}...")
        except Exception as e:
            print(f"❌ Error ejecutando amass: {e}")

def check_dns_resolution():
    """Verifica resolución DNS básica."""
    print("\n=== VERIFICACIÓN DNS ===")
    
    import socket
    test_domains = ["bice.cl", "bci.cl", "example.com"]
    
    for domain in test_domains:
        try:
            ip = socket.gethostbyname(domain)
            print(f"✅ {domain} -> {ip}")
        except Exception as e:
            print(f"❌ {domain} -> Error: {e}")

if __name__ == "__main__":
    try:
        if check_amass_installation():
            check_dns_resolution()
            test_amass_basic()
            test_amass_with_script_params()
            test_active_mode()
        
        print("\n=== RECOMENDACIONES ===")
        print("1. Si amass no está instalado: sudo apt install amass")
        print("2. Si está devolviendo archivos vacíos, intenta:")
        print("   - Usar modo activo (sin --amass-passive)")
        print("   - Aumentar el timeout (--amass-timeout 120)")
        print("   - Verificar conectividad a internet")
        print("3. Si persisten los errores, considera usar --mock-mode para testing")
        
    except KeyboardInterrupt:
        print("\n❌ Diagnóstico interrumpido por el usuario")
    except Exception as e:
        print(f"\n❌ Error en diagnóstico: {e}")