#!/usr/bin/env python3
"""
amass_cache.py - Sistema de caché inteligente para resultados de Amass

Características:
- Almacenamiento persistente en disco con compresión
- Separación por modo (activo/pasivo) y configuración
- Expiración paramétrica (default: 1 semana)
- Metadata de tracking (timestamp, configuración, estadísticas)
- Thread-safe para uso concurrente
- Compresión automática para ahorrar espacio
"""

import json
import hashlib
import gzip
import threading
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, asdict
import logging

@dataclass
class CacheMetadata:
    """Metadata para entradas de caché."""
    domain: str
    timestamp: str
    mode: str  # "passive", "active", "brute", etc.
    timeout: int
    amass_version: str
    config_hash: str  # Hash de la configuración de APIs usada
    subdomain_count: int
    cache_version: str = "1.0"
    
    def is_expired(self, cache_ttl_hours: int) -> bool:
        """Verifica si la entrada ha expirado."""
        try:
            cache_time = datetime.fromisoformat(self.timestamp)
            expiry_time = cache_time + timedelta(hours=cache_ttl_hours)
            return datetime.now() > expiry_time
        except:
            return True  # Si no podemos parsear, consideramos expirado

@dataclass
class CacheStats:
    """Estadísticas del caché."""
    hits: int = 0
    misses: int = 0
    evictions: int = 0
    total_domains_cached: int = 0
    
    @property
    def hit_ratio(self) -> float:
        total = self.hits + self.misses
        return self.hits / total if total > 0 else 0.0

class AmassCache:
    """Sistema de caché para resultados de Amass."""
    
    def __init__(self, cache_dir: str = "amass_cache", cache_ttl_hours: int = 168):  # 168h = 1 semana
        self.cache_dir = Path(cache_dir)
        self.cache_ttl_hours = cache_ttl_hours
        self.stats = CacheStats()
        self._lock = threading.Lock()
        
        # Crear directorio de caché
        self.cache_dir.mkdir(exist_ok=True)
        (self.cache_dir / "metadata").mkdir(exist_ok=True)
        (self.cache_dir / "data").mkdir(exist_ok=True)
        
        # Archivo de estadísticas
        self.stats_file = self.cache_dir / "cache_stats.json"
        self._load_stats()
        
        logging.info(f"[CACHE] Initialized: {self.cache_dir}, TTL: {cache_ttl_hours}h")
    
    def _generate_cache_key(self, domain: str, mode: str, timeout: int, config_hash: str) -> str:
        """Genera una clave única para el caché."""
        key_data = f"{domain}:{mode}:{timeout}:{config_hash}"
        return hashlib.sha256(key_data.encode()).hexdigest()[:16]
    
    def _get_config_hash(self) -> str:
        """Genera hash de la configuración actual de Amass."""
        try:
            import os
            config_path = Path.home() / ".config" / "amass" / "datasources.yaml"
            if config_path.exists():
                content = config_path.read_text()
                return hashlib.md5(content.encode()).hexdigest()[:8]
            else:
                return "no_config"
        except:
            return "unknown"
    
    def _get_cache_paths(self, cache_key: str) -> Tuple[Path, Path]:
        """Obtiene las rutas de metadata y datos para una clave."""
        metadata_path = self.cache_dir / "metadata" / f"{cache_key}.json"
        data_path = self.cache_dir / "data" / f"{cache_key}.json.gz"
        return metadata_path, data_path
    
    def _load_stats(self):
        """Carga estadísticas desde disco."""
        try:
            if self.stats_file.exists():
                with open(self.stats_file, 'r') as f:
                    stats_data = json.load(f)
                    self.stats = CacheStats(**stats_data)
        except Exception as e:
            logging.warning(f"[CACHE] Could not load stats: {e}")
            self.stats = CacheStats()
    
    def _save_stats(self):
        """Guarda estadísticas a disco."""
        try:
            with open(self.stats_file, 'w') as f:
                json.dump(asdict(self.stats), f, indent=2)
        except Exception as e:
            logging.warning(f"[CACHE] Could not save stats: {e}")
    
    def get(self, domain: str, mode: str = "passive", timeout: int = 300) -> Optional[List[Dict[str, Any]]]:
        """
        Obtiene resultados de Amass desde el caché.
        
        Args:
            domain: Dominio a buscar
            mode: Modo de Amass ("passive", "active", "brute", etc.)
            timeout: Timeout usado
            
        Returns:
            Lista de resultados de Amass o None si no existe/expiró
        """
        with self._lock:
            config_hash = self._get_config_hash()
            cache_key = self._generate_cache_key(domain, mode, timeout, config_hash)
            metadata_path, data_path = self._get_cache_paths(cache_key)
            
            try:
                # Verificar si existe metadata
                if not metadata_path.exists() or not data_path.exists():
                    self.stats.misses += 1
                    self._save_stats()
                    logging.debug(f"[CACHE] MISS: {domain} ({mode}) - no files")
                    return None
                
                # Cargar metadata
                with open(metadata_path, 'r') as f:
                    metadata_dict = json.load(f)
                    metadata = CacheMetadata(**metadata_dict)
                
                # Verificar expiración
                if metadata.is_expired(self.cache_ttl_hours):
                    self.stats.misses += 1
                    self.stats.evictions += 1
                    self._save_stats()
                    logging.info(f"[CACHE] EXPIRED: {domain} ({mode}) - age: {metadata.timestamp}")
                    
                    # Limpiar archivos expirados
                    try:
                        metadata_path.unlink()
                        data_path.unlink()
                    except:
                        pass
                    
                    return None
                
                # Verificar cambio de configuración
                if metadata.config_hash != config_hash:
                    self.stats.misses += 1
                    self.stats.evictions += 1
                    self._save_stats()
                    logging.info(f"[CACHE] CONFIG_CHANGE: {domain} ({mode}) - config hash changed")
                    return None
                
                # Cargar datos
                with gzip.open(data_path, 'rt', encoding='utf-8') as f:
                    results = json.load(f)
                
                self.stats.hits += 1
                self._save_stats()
                
                age_hours = (datetime.now() - datetime.fromisoformat(metadata.timestamp)).total_seconds() / 3600
                logging.info(f"[CACHE] HIT: {domain} ({mode}) - {metadata.subdomain_count} subdomains, age: {age_hours:.1f}h")
                
                return results
                
            except Exception as e:
                self.stats.misses += 1
                self._save_stats()
                logging.error(f"[CACHE] ERROR loading {domain} ({mode}): {e}")
                return None
    
    def put(self, domain: str, results: List[Dict[str, Any]], mode: str = "passive", timeout: int = 300):
        """
        Guarda resultados de Amass en el caché.
        
        Args:
            domain: Dominio
            results: Resultados de Amass
            mode: Modo usado
            timeout: Timeout usado
        """
        with self._lock:
            try:
                config_hash = self._get_config_hash()
                cache_key = self._generate_cache_key(domain, mode, timeout, config_hash)
                metadata_path, data_path = self._get_cache_paths(cache_key)
                
                # Crear metadata
                metadata = CacheMetadata(
                    domain=domain,
                    timestamp=datetime.now().isoformat(),
                    mode=mode,
                    timeout=timeout,
                    amass_version="4.2.0",  # TODO: detectar versión dinámicamente
                    config_hash=config_hash,
                    subdomain_count=len(results)
                )
                
                # Guardar metadata
                with open(metadata_path, 'w') as f:
                    json.dump(asdict(metadata), f, indent=2)
                
                # Guardar datos comprimidos
                with gzip.open(data_path, 'wt', encoding='utf-8') as f:
                    json.dump(results, f, indent=2)
                
                # Actualizar estadísticas
                self.stats.total_domains_cached += 1
                self._save_stats()
                
                size_mb = data_path.stat().st_size / (1024 * 1024)
                logging.info(f"[CACHE] STORED: {domain} ({mode}) - {len(results)} subdomains, {size_mb:.2f}MB")
                
            except Exception as e:
                logging.error(f"[CACHE] ERROR storing {domain} ({mode}): {e}")
    
    def clear_expired(self) -> int:
        """
        Limpia entradas expiradas del caché.
        
        Returns:
            Número de entradas eliminadas
        """
        with self._lock:
            cleared = 0
            
            try:
                # Revisar todos los archivos de metadata
                for metadata_file in (self.cache_dir / "metadata").glob("*.json"):
                    try:
                        with open(metadata_file, 'r') as f:
                            metadata_dict = json.load(f)
                            metadata = CacheMetadata(**metadata_dict)
                        
                        if metadata.is_expired(self.cache_ttl_hours):
                            # Eliminar archivos
                            cache_key = metadata_file.stem
                            _, data_path = self._get_cache_paths(cache_key)
                            
                            metadata_file.unlink()
                            if data_path.exists():
                                data_path.unlink()
                            
                            cleared += 1
                            
                    except Exception as e:
                        logging.warning(f"[CACHE] Error cleaning {metadata_file}: {e}")
                        # Eliminar archivo corrupto
                        try:
                            metadata_file.unlink()
                            cleared += 1
                        except:
                            pass
                
                self.stats.evictions += cleared
                self._save_stats()
                
                logging.info(f"[CACHE] Cleaned {cleared} expired entries")
                return cleared
                
            except Exception as e:
                logging.error(f"[CACHE] Error during cleanup: {e}")
                return 0
    
    def get_stats(self) -> Dict[str, Any]:
        """Obtiene estadísticas del caché."""
        with self._lock:
            # Contar archivos actuales
            current_files = len(list((self.cache_dir / "metadata").glob("*.json")))
            
            return {
                "hits": self.stats.hits,
                "misses": self.stats.misses,
                "hit_ratio": round(self.stats.hit_ratio * 100, 1),
                "evictions": self.stats.evictions,
                "total_cached": self.stats.total_domains_cached,
                "current_entries": current_files,
                "cache_dir": str(self.cache_dir),
                "ttl_hours": self.cache_ttl_hours
            }
    
    def list_cached_domains(self) -> List[Dict[str, Any]]:
        """Lista todos los dominios en caché con su metadata."""
        with self._lock:
            cached_domains = []
            
            try:
                for metadata_file in (self.cache_dir / "metadata").glob("*.json"):
                    try:
                        with open(metadata_file, 'r') as f:
                            metadata_dict = json.load(f)
                            metadata = CacheMetadata(**metadata_dict)
                        
                        age_hours = (datetime.now() - datetime.fromisoformat(metadata.timestamp)).total_seconds() / 3600
                        
                        cached_domains.append({
                            "domain": metadata.domain,
                            "mode": metadata.mode,
                            "timestamp": metadata.timestamp,
                            "age_hours": round(age_hours, 1),
                            "subdomain_count": metadata.subdomain_count,
                            "expired": metadata.is_expired(self.cache_ttl_hours)
                        })
                        
                    except Exception as e:
                        logging.warning(f"[CACHE] Error reading {metadata_file}: {e}")
                
                return sorted(cached_domains, key=lambda x: x["timestamp"], reverse=True)
                
            except Exception as e:
                logging.error(f"[CACHE] Error listing domains: {e}")
                return []


# Funciones de utilidad para integración fácil
_global_cache = None

def get_global_cache(cache_dir: str = "amass_cache", cache_ttl_hours: int = 168) -> AmassCache:
    """Obtiene instancia global de caché (singleton)."""
    global _global_cache
    if _global_cache is None:
        _global_cache = AmassCache(cache_dir, cache_ttl_hours)
    return _global_cache

def cached_amass_call(domain: str, mode: str, timeout: int, amass_function, 
                      cache_ttl_hours: int = 168) -> List[Dict[str, Any]]:
    """
    Wrapper para llamadas a Amass con caché automático.
    
    Args:
        domain: Dominio a analizar
        mode: Modo de Amass
        timeout: Timeout
        amass_function: Función que ejecuta Amass
        cache_ttl_hours: TTL del caché en horas
    
    Returns:
        Resultados de Amass (desde caché o nueva ejecución)
    """
    cache = get_global_cache(cache_ttl_hours=cache_ttl_hours)
    
    # Intentar obtener desde caché
    cached_results = cache.get(domain, mode, timeout)
    if cached_results is not None:
        return cached_results
    
    # Ejecutar Amass
    logging.info(f"[CACHE] Executing Amass for {domain} ({mode})")
    results = amass_function()
    
    # Guardar en caché
    cache.put(domain, results, mode, timeout)
    
    return results


if __name__ == "__main__":
    # Test básico
    cache = AmassCache("test_cache", cache_ttl_hours=1)
    
    # Simular datos
    test_results = [
        {"name": "www.example.com", "type": "A", "address": "1.2.3.4"},
        {"name": "api.example.com", "type": "A", "address": "1.2.3.5"}
    ]
    
    # Guardar
    cache.put("example.com", test_results, "passive", 300)
    
    # Recuperar
    retrieved = cache.get("example.com", "passive", 300)
    print(f"Retrieved: {len(retrieved) if retrieved else 0} results")
    
    # Estadísticas
    print(f"Stats: {cache.get_stats()}")